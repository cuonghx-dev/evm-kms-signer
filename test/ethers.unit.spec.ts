import { expect } from "chai";
import {
  JsonRpcProvider,
  N,
  parseEther,
  Transaction,
  verifyMessage,
  verifyTypedData,
  Wallet,
} from "ethers";

import { createEvmKmsSigner } from "../src";
import { KmsEthersSigner } from "../src/ethers";
import { localKms } from "../src/kms/local";

const wallet = new Wallet(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
);

function kmsSigner(options: { forceHighS?: boolean } = {}) {
  return createEvmKmsSigner({
    kms: localKms({
      privateKey: Buffer.from(wallet.privateKey.slice(2), "hex"),
      forceHighS: options.forceHighS,
    }),
  });
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

context("KmsEthersSigner", () => {
  for (const forceHighS of [false, true]) {
    describe(`forceHighS=${forceHighS}`, () => {
      let signer: KmsEthersSigner;

      beforeEach(() => {
        signer = new KmsEthersSigner(kmsSigner({ forceHighS }));
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
        expect(signature).to.equal(
          await wallet.signTypedData(domain, types, value)
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
        expect(serialized).to.equal(
          await wallet.signTransaction({
            to: "0x0000000000000000000000000000000000007e57",
            value: parseEther("0.001"),
            chainId: 1,
            nonce: 0,
            gasLimit: 21000,
            maxFeePerGas: 20_000_000_000,
            maxPriorityFeePerGas: 1_000_000_000,
          })
        );
        const tx = Transaction.from(serialized);
        expect(tx.from).to.equal(wallet.address);
        expect(BigInt(tx.signature!.s) <= N / BigInt(2)).to.equal(true);
      });
    });
  }

  it("keeps the KMS signer when connecting a provider", () => {
    const signer = new KmsEthersSigner(kmsSigner());
    const provider = new JsonRpcProvider();
    const connected = signer.connect(provider);
    expect(connected.signer).to.equal(signer.signer);
    expect(connected.provider).to.equal(provider);
    provider.destroy();
  });

  it("rejects a transaction from another address", async () => {
    const signer = new KmsEthersSigner(kmsSigner());
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
