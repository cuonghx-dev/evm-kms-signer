import { secp256k1 } from "@noble/curves/secp256k1";
import { expect } from "chai";

import {
  createLocalKmsBackend,
  KmsKey,
  pemToDer,
  publicKeyFromSpki,
} from "../src";

// Hardhat account #0
const PRIVATE_KEY = Buffer.from(
  "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "hex"
);
const ADDRESS = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const OTHER_PRIVATE_KEY = Buffer.from(
  "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "hex"
);
const DIGEST = Buffer.from(
  "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68",
  "hex"
);
const HALF_N = secp256k1.CURVE.n / BigInt(2);

context("KmsKey", () => {
  it("derives the address from the KMS public key", async () => {
    const key = new KmsKey(createLocalKmsBackend(PRIVATE_KEY));
    expect(await key.getAddress()).to.equal(ADDRESS);
  });

  it("parses a PEM public key", () => {
    const backend = createLocalKmsBackend(PRIVATE_KEY);
    expect(
      Buffer.from(publicKeyFromSpki(pemToDer(backend.publicKeyPem())))
    ).to.deep.equal(Buffer.from(secp256k1.getPublicKey(PRIVATE_KEY, false)));
  });

  for (const forceHighS of [false, true]) {
    it(`returns a low-s recoverable signature (forceHighS=${forceHighS})`, async () => {
      const key = new KmsKey(
        createLocalKmsBackend(PRIVATE_KEY, { forceHighS })
      );
      const { r, s, yParity } = await key.sign(DIGEST);

      expect(s <= HALF_N).to.equal(true);
      const recovered = new secp256k1.Signature(r, s)
        .addRecoveryBit(yParity)
        .recoverPublicKey(DIGEST)
        .toRawBytes(false);
      expect(Buffer.from(recovered)).to.deep.equal(
        Buffer.from(await key.getPublicKey())
      );
    });
  }

  it("rejects a signature from a different key", async () => {
    const backend = createLocalKmsBackend(PRIVATE_KEY);
    const other = createLocalKmsBackend(OTHER_PRIVATE_KEY);
    const key = new KmsKey({ ...backend, sign: other.sign });

    await expectRejects(key.sign(DIGEST), "KMS signature does not match");
  });

  it("rejects a digest that is not 32 bytes", async () => {
    const key = new KmsKey(createLocalKmsBackend(PRIVATE_KEY));
    await expectRejects(key.sign(DIGEST.subarray(1)), "Invalid digest length");
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
