import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from "@aws-sdk/client-kms";
import { createLocalKmsBackend } from "@cuonghx.gu-tech/kms-signer-core";
import { expect } from "chai";
import {
  N,
  parseEther,
  Transaction,
  verifyMessage,
  verifyTypedData,
  Wallet,
} from "ethers";

import { AwsKmsSigner } from "../src";

const wallet = new Wallet(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
);
const KEY_ID = "alias/test-key";

function mockClient(options: { forceHighS?: boolean } = {}) {
  const backend = createLocalKmsBackend(
    Buffer.from(wallet.privateKey.slice(2), "hex"),
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
      return { Signature: await backend.sign(command.input.Message!) };
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
  value: {
    name: "Bob",
    wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
  },
};

context("AwsKmsSigner (mock KMS)", () => {
  for (const forceHighS of [false, true]) {
    describe(`forceHighS=${forceHighS}`, () => {
      let signer: AwsKmsSigner;

      beforeEach(() => {
        signer = new AwsKmsSigner({
          keyId: KEY_ID,
          client: mockClient({ forceHighS }),
        });
      });

      it("returns the checksummed address", async () => {
        expect(await signer.getAddress()).to.equal(wallet.address);
      });

      it("signs a message", async () => {
        const signature = await signer.signMessage("hello world");
        expect(verifyMessage("hello world", signature)).to.equal(
          wallet.address
        );
        expect(signature).to.equal(await wallet.signMessage("hello world"));
      });

      it("signs typed data", async () => {
        const { domain, types, value } = TYPED_DATA;
        const signature = await signer.signTypedData(domain, types, value);
        expect(verifyTypedData(domain, types, value, signature)).to.equal(
          wallet.address
        );
      });

      it("signs a transaction", async () => {
        const serialized = await signer.signTransaction({
          from: wallet.address,
          to: "0x0000000000000000000000000000000000007e57",
          value: parseEther("0.001"),
          chainId: 1,
          nonce: 0,
          gasLimit: 21000,
          maxFeePerGas: 20_000_000_000,
          maxPriorityFeePerGas: 1_000_000_000,
        });
        const tx = Transaction.from(serialized);
        expect(tx.from).to.equal(wallet.address);
        expect(BigInt(tx.signature!.s) <= N / BigInt(2)).to.equal(true);
      });
    });
  }

  it("rejects a transaction from another address", async () => {
    const signer = new AwsKmsSigner({
      keyId: KEY_ID,
      client: mockClient(),
    });
    try {
      await signer.signTransaction({
        from: "0x0000000000000000000000000000000000000001",
        to: "0x0000000000000000000000000000000000007e57",
        chainId: 1,
      });
    } catch (error) {
      expect((error as Error).message).to.include(
        "transaction from address mismatch"
      );
      return;
    }
    expect.fail("Expected signTransaction to reject");
  });
});
