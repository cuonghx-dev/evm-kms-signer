import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from "@aws-sdk/client-kms";
import { createLocalKmsBackend } from "@cuonghx/kms-signer-core";
import { expect } from "chai";
import { hexToBytes, parseEther, parseGwei } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { awsKmsToAccount } from "../src";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const OTHER_PRIVATE_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const reference = privateKeyToAccount(PRIVATE_KEY);
const KEY_ID = "alias/test-key";

function mockClient(
  options: { forceHighS?: boolean; signingKey?: `0x${string}` } = {}
) {
  const backend = createLocalKmsBackend(hexToBytes(PRIVATE_KEY));
  const signer = createLocalKmsBackend(
    hexToBytes(options.signingKey ?? PRIVATE_KEY),
    options
  );
  return {
    async send(command: GetPublicKeyCommand | SignCommand) {
      expect(command.input.KeyId).to.equal(KEY_ID);
      if (command instanceof GetPublicKeyCommand) {
        return { PublicKey: await backend.getPublicKey() };
      }
      expect(command.input).to.include({
        MessageType: "DIGEST",
        SigningAlgorithm: "ECDSA_SHA_256",
      });
      return { Signature: await signer.sign(command.input.Message!) };
    },
  } as unknown as KMSClient;
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

context("awsKmsToAccount (mock KMS)", () => {
  for (const forceHighS of [false, true]) {
    describe(`forceHighS=${forceHighS}`, () => {
      const account = () =>
        awsKmsToAccount({
          keyId: KEY_ID,
          client: mockClient({ forceHighS }),
        });

      // RFC 6979 signatures are deterministic, so every result must match a
      // plain private key account byte for byte.
      it("exposes address, publicKey and source", async () => {
        const kms = await account();
        expect(kms.address).to.equal(reference.address);
        expect(kms.publicKey).to.equal(reference.publicKey);
        expect(kms.source).to.equal("awsKms");
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
    const account = await awsKmsToAccount({
      keyId: KEY_ID,
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
