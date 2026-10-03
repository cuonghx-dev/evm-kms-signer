import { secp256k1 } from "@noble/curves/secp256k1";
import { expect } from "chai";
import { generateKeyPairSync } from "crypto";

import { createEvmKmsSigner, Kms, pemToDer, publicKeyFromSpki } from "../src";
import { localKms } from "../src/kms/local";

// Hardhat account #0
const PRIVATE_KEY = Buffer.from(
  "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "hex"
);
const ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const OTHER_PRIVATE_KEY = Buffer.from(
  "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "hex"
);
const DIGEST = Buffer.from(
  "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68",
  "hex"
);
const HALF_N = secp256k1.CURVE.n / BigInt(2);

context("createEvmKmsSigner", () => {
  it("derives the checksummed address from the KMS public key", async () => {
    const signer = createEvmKmsSigner({
      kms: localKms({ privateKey: PRIVATE_KEY }),
    });
    expect(await signer.getAddress()).to.equal(ADDRESS);
  });

  it("fetches the public key once", async () => {
    let calls = 0;
    const local = localKms({ privateKey: PRIVATE_KEY });
    const signer = createEvmKmsSigner({
      kms: {
        ...local,
        getPublicKey: () => {
          calls++;
          return local.getPublicKey();
        },
      },
    });
    await Promise.all([signer.getAddress(), signer.sign(DIGEST)]);
    await signer.getAddress();
    expect(calls).to.equal(1);
  });

  it("retries the public key after a failure", async () => {
    let calls = 0;
    const local = localKms({ privateKey: PRIVATE_KEY });
    const signer = createEvmKmsSigner({
      kms: {
        ...local,
        getPublicKey: () =>
          calls++ === 0
            ? Promise.reject(new Error("transient"))
            : local.getPublicKey(),
      },
    });
    await expectRejects(signer.getAddress(), "transient");
    expect(await signer.getAddress()).to.equal(ADDRESS);
  });

  it("accepts a custom KMS implementation", async () => {
    const local = localKms({ privateKey: PRIVATE_KEY });
    const custom: Kms<"custom"> = {
      type: "custom",
      getPublicKey: () => local.getPublicKey(),
      sign: (digest) => local.sign(digest),
    };
    const signer = createEvmKmsSigner({ kms: custom });
    expect(signer.kms.type).to.equal("custom");
    expect(await signer.getAddress()).to.equal(ADDRESS);
  });

  it("parses a PEM public key", () => {
    const kms = localKms({ privateKey: PRIVATE_KEY });
    expect(
      Buffer.from(publicKeyFromSpki(pemToDer(kms.publicKeyPem())))
    ).to.deep.equal(Buffer.from(secp256k1.getPublicKey(PRIVATE_KEY, false)));
  });

  it("rejects a public key on another curve", async () => {
    // P-256 keys have the same 65-byte uncompressed encoding as secp256k1
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const spki = new Uint8Array(
      publicKey.export({ type: "spki", format: "der" })
    );
    const signer = createEvmKmsSigner({
      kms: {
        ...localKms({ privateKey: PRIVATE_KEY }),
        getPublicKey: async () => spki,
      },
    });
    await expectRejects(signer.getAddress(), "not a secp256k1 key");
  });

  it("rejects a public key that is not on the curve", () => {
    const spki = pemToDer(localKms({ privateKey: PRIVATE_KEY }).publicKeyPem());
    spki[spki.length - 1] ^= 0x01;
    expect(() => publicKeyFromSpki(spki)).to.throw(
      "not a valid secp256k1 point"
    );
  });

  for (const forceHighS of [false, true]) {
    it(`returns a low-s recoverable signature (forceHighS=${forceHighS})`, async () => {
      const signer = createEvmKmsSigner({
        kms: localKms({ privateKey: PRIVATE_KEY, forceHighS }),
      });
      const { r, s, yParity } = await signer.sign(DIGEST);

      expect(s <= HALF_N).to.equal(true);
      const recovered = new secp256k1.Signature(r, s)
        .addRecoveryBit(yParity)
        .recoverPublicKey(DIGEST)
        .toRawBytes(false);
      expect(Buffer.from(recovered)).to.deep.equal(
        Buffer.from(await signer.getPublicKey())
      );
    });
  }

  it("rejects a signature from a different key", async () => {
    const kms = localKms({ privateKey: PRIVATE_KEY });
    const other = localKms({ privateKey: OTHER_PRIVATE_KEY });
    const signer = createEvmKmsSigner({ kms: { ...kms, sign: other.sign } });

    await expectRejects(signer.sign(DIGEST), "KMS signature does not match");
  });

  it("rejects a digest that is not 32 bytes", async () => {
    const signer = createEvmKmsSigner({
      kms: localKms({ privateKey: PRIVATE_KEY }),
    });
    await expectRejects(
      signer.sign(DIGEST.subarray(1)),
      "Invalid digest length"
    );
  });
});

async function expectRejects(promise: Promise<unknown>, message: string) {
  try {
    await promise;
  } catch (error) {
    expect((error as Error).message).to.include(message);
    return;
  }
  expect.fail("Expected promise to reject");
}
