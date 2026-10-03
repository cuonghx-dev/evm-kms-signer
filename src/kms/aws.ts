import {
  GetPublicKeyCommand,
  KMSClient,
  KMSClientConfig,
  SignCommand,
} from "@aws-sdk/client-kms";

import { Kms } from "../utils";

export type AwsKmsParameters = {
  keyId: string;
  region?: string;
  /** Falls back to the AWS SDK default credential chain when omitted */
  credentials?: KMSClientConfig["credentials"];
  /** Pre-configured KMS client; takes precedence over `region`/`credentials` */
  client?: KMSClient;
};

/**
 * AWS KMS backend for an `ECC_SECG_P256K1` key.
 */
export function awsKms(parameters: AwsKmsParameters): Kms<"awsKms"> {
  const { keyId } = parameters;
  const client =
    parameters.client ??
    new KMSClient({
      region: parameters.region,
      credentials: parameters.credentials,
    });

  return {
    type: "awsKms",
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
