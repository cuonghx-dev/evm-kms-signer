import { expect } from "chai";
import dotenv from "dotenv";

import { GcpKmsSigner } from "../src/gcp-kms-signer";
import { ethers, recoverAddress, solidityPackedKeccak256 } from "ethers";

dotenv.config();

context("GcpKmsSigner", () => {
  let signer: GcpKmsSigner;

  beforeEach(() => {
    signer = new GcpKmsSigner({
      projectId: process.env.TEST_GCP_PROJECT_ID!,
      locationId: process.env.TEST_GCP_LOCATION_ID!,
      keyRingId: process.env.TEST_GCP_KEYRING_ID!,
      keyId: process.env.TEST_GCP_KEY_ID!,
      versionId: process.env.TEST_GCP_VERSION_ID!,
    });
  });

  it("Should return correct public key", async () => {
    expect(await signer.getAddress()).to.eql(
      "0x4fde0bb456be6ccc6ee38c04cec17ceff737c125"
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
