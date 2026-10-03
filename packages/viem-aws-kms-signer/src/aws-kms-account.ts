import {
  GetPublicKeyCommand,
  KMSClient,
  KMSClientConfig,
  SignCommand,
} from "@aws-sdk/client-kms";
import { KmsBackend, KmsKey } from "@cuonghx.gu-tech/kms-signer-core";
import { LocalAccount } from "viem";

import { kmsKeyToAccount } from "./kms-key-to-account";

export type AwsKmsAccount = LocalAccount<"awsKms">;

export type AwsKmsToAccountParameters = {
  keyId: string;
  region?: string;
  /** Falls back to the AWS SDK default credential chain when omitted */
  credentials?: KMSClientConfig["credentials"];
  /** Pre-configured KMS client; takes precedence over `region`/`credentials` */
  client?: KMSClient;
};

/**
 * Creates a viem `LocalAccount` backed by an AWS KMS `ECC_SECG_P256K1` key.
 */
export async function awsKmsToAccount(
  parameters: AwsKmsToAccountParameters
): Promise<AwsKmsAccount> {
  const client =
    parameters.client ??
    new KMSClient({
      region: parameters.region,
      credentials: parameters.credentials,
    });

  return kmsKeyToAccount(
    new KmsKey(createAwsKmsBackend(client, parameters.keyId)),
    "awsKms"
  );
}

function createAwsKmsBackend(client: KMSClient, keyId: string): KmsBackend {
  return {
    async getPublicKey() {
      const response = await client.send(
        new GetPublicKeyCommand({ KeyId: keyId })
      );
      if (!response.PublicKey) {
        throw new Error("Could not get Public Key from KMS.");
      }
      return response.PublicKey;
    },
    async sign(digest) {
      const response = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: digest,
          MessageType: "DIGEST",
          SigningAlgorithm: "ECDSA_SHA_256",
        })
      );
      if (!response.Signature) {
        throw new Error("Could not fetch Signature from KMS.");
      }
      return response.Signature;
    },
  };
}
