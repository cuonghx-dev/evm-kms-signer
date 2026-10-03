import { expect } from "chai";
import dotenv from "dotenv";

import { AwsKmsSigner } from "../src/aws-kms-signer";
import { ethers, recoverAddress, solidityPackedKeccak256 } from "ethers";

dotenv.config();

context("AwsKmsSigner", () => {
  let signer: AwsKmsSigner;

  describe("explicit credentials", () => {
    beforeEach(() => {
      signer = new AwsKmsSigner({
        keyId: process.env.TEST_KMS_KEY_ID!,
        region: process.env.TEST_KMS_REGION_ID!,
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
      });
    });

    it("Should return correct public key", async () => {
      expect(await signer.getAddress()).to.eql(
        "0x27d30941a21923e25a7429e3e576e9609c012a27"
      );
    });

    it("Should get sign a message", async () => {
      const testMessage = "test";
      const publicAddress = await signer.getAddress();

      const signature = await signer.signMessage(testMessage);

      const eip191Hash = solidityPackedKeccak256(
        ["string", "string"],
        ["\x19Ethereum Signed Message:\n4", testMessage]
      );

      const recoveredAddress = recoverAddress(eip191Hash, signature);

      expect(recoveredAddress.toLowerCase()).to.equal(
        publicAddress.toLowerCase()
      );
    });
  });

  describe("AWS SSO", () => {
    it("Should get sign a message", async () => {
      signer = new AwsKmsSigner({
        keyId: process.env.TEST_KMS_KEY_ID!,
        region: process.env.TEST_KMS_REGION_ID!,
      });
      const testMessage = "test";
      const publicAddress = await signer.getAddress();

      const signature = await signer.signMessage(testMessage);

      const eip191Hash = solidityPackedKeccak256(
        ["string", "string"],
        ["\x19Ethereum Signed Message:\n4", testMessage]
      );

      const recoveredAddress = recoverAddress(eip191Hash, signature);

      expect(recoveredAddress.toLowerCase()).to.equal(
        publicAddress.toLowerCase()
      );
    });
  });

  it("should send a signed transaction using KMS signer", async () => {
    const provider = new ethers.JsonRpcProvider(process.env.TEST_RPC_URL);
    const connectedSigner = signer.connect(provider);
    const tx = await connectedSigner.sendTransaction({
      to: "0xBac8ECdbc45A50d3bda7246bB2AA64Fc449C7924",
      value: ethers.parseEther("0.001"),
    });
    await tx.wait();
  });
});
