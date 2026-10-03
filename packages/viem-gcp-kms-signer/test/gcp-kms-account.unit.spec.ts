import { createLocalKmsBackend } from "@cuonghx.gu-tech/kms-signer-core";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { expect } from "chai";
import { hexToBytes, parseEther, parseGwei } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { gcpKmsToAccount } from "../src";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const OTHER_PRIVATE_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const reference = privateKeyToAccount(PRIVATE_KEY);
const KEY_VERSION_NAME =
  "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

function mockClient(
  options: { forceHighS?: boolean; signingKey?: `0x${string}` } = {}
) {
  const backend = createLocalKmsBackend(hexToBytes(PRIVATE_KEY));
  const signer = createLocalKmsBackend(
    hexToBytes(options.signingKey ?? PRIVATE_KEY),
    options
  );
  return {
    async getPublicKey({ name }: { name: string }) {
      expect(name).to.equal(KEY_VERSION_NAME);
      return [{ pem: backend.publicKeyPem() }];
    },
    async asymmetricSign({
      name,
      digest,
    }: {
      name: string;
      digest: { sha256: Uint8Array };
    }) {
      expect(name).to.equal(KEY_VERSION_NAME);
      return [{ signature: await signer.sign(digest.sha256) }];
    },
  } as unknown as KeyManagementServiceClient;
}

const TYPED_DATA = {
  domain: {
    name: "Ether Mail",
    version: "1",
    chainId: 1,
    verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
  },
  types: {
    Person: [
      { name: "name", type: "string" },
      { name: "wallet", type: "address" },
    ],
  },
  primaryType: "Person",
  message: {
    name: "Bob",
    wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
  },
} as const;

const HASH =
  "0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68";

context("gcpKmsToAccount (mock KMS)", () => {
  for (const forceHighS of [false, true]) {
    describe(`forceHighS=${forceHighS}`, () => {
      const account = () =>
        gcpKmsToAccount({
          keyVersionName: KEY_VERSION_NAME,
          client: mockClient({ forceHighS }),
        });

      // RFC 6979 signatures are deterministic, so every result must match a
      // plain private key account byte for byte.
      it("exposes address, publicKey and source", async () => {
        const kms = await account();
        expect(kms.address).to.equal(reference.address);
        expect(kms.publicKey).to.equal(reference.publicKey);
        expect(kms.source).to.equal("gcpKms");
        expect(kms.type).to.equal("local");
      });

      it("signs a hash", async () => {
        expect(await (await account()).sign!({ hash: HASH })).to.equal(
          await reference.sign({ hash: HASH })
        );
      });

      it("signs a message", async () => {
        expect(
          await (await account()).signMessage({ message: "hello world" })
        ).to.equal(await reference.signMessage({ message: "hello world" }));
      });

      it("signs typed data", async () => {
        expect(await (await account()).signTypedData(TYPED_DATA)).to.equal(
          await reference.signTypedData(TYPED_DATA)
        );
      });

      it("signs an EIP-1559 transaction", async () => {
        const tx = {
          chainId: 1,
          maxFeePerGas: parseGwei("20"),
          gas: BigInt(21000),
          to: "0x0000000000000000000000000000000000007e57",
          value: parseEther("0.001"),
        } as const;
        expect(await (await account()).signTransaction(tx)).to.equal(
          await reference.signTransaction(tx)
        );
      });

      it("signs a legacy transaction", async () => {
        const tx = {
          chainId: 1,
          gasPrice: parseGwei("20"),
          gas: BigInt(21000),
          to: "0x0000000000000000000000000000000000007e57",
          value: parseEther("0.001"),
        } as const;
        expect(await (await account()).signTransaction(tx)).to.equal(
          await reference.signTransaction(tx)
        );
      });

      it("signs an EIP-7702 authorization", async () => {
        const authorization = {
          address: "0x0000000000000000000000000000000000007e57",
          chainId: 1,
          nonce: 0,
        } as const;
        expect(
          await (await account()).signAuthorization!(authorization)
        ).to.deep.equal(await reference.signAuthorization(authorization));
      });
    });
  }

  it("rejects a signature from a different key", async () => {
    const account = await gcpKmsToAccount({
      keyVersionName: KEY_VERSION_NAME,
      client: mockClient({ signingKey: OTHER_PRIVATE_KEY }),
    });
    try {
      await account.signMessage({ message: "hello world" });
    } catch (error) {
      expect((error as Error).message).to.include(
        "KMS signature does not match"
      );
      return;
    }
    expect.fail("Expected signMessage to reject");
  });
});
