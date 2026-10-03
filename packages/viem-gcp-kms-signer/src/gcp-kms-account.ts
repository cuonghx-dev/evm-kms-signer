import { KmsBackend, KmsKey, pemToDer } from "@cuonghx/kms-signer-core";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { ClientOptions } from "google-gax";
import { LocalAccount } from "viem";

import { kmsKeyToAccount } from "./kms-key-to-account";

export type GcpKmsAccount = LocalAccount<"gcpKms">;

type GcpKeyVersionPath = {
  projectId: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  versionId: string;
};

export type GcpKmsToAccountParameters = {
  clientOptions?: ClientOptions;
  /** Pre-configured KMS client; takes precedence over `clientOptions` */
  client?: KeyManagementServiceClient;
} & (
  | GcpKeyVersionPath
  | {
      /** Full key version resource name, e.g. `projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1` */
      keyVersionName: string;
    }
);

/**
 * Creates a viem `LocalAccount` backed by a GCP Cloud KMS secp256k1 key.
 */
export async function gcpKmsToAccount(
  parameters: GcpKmsToAccountParameters
): Promise<GcpKmsAccount> {
  const client =
    parameters.client ??
    new KeyManagementServiceClient(parameters.clientOptions);
  const name =
    "keyVersionName" in parameters
      ? parameters.keyVersionName
      : client.cryptoKeyVersionPath(
          parameters.projectId,
          parameters.locationId,
          parameters.keyRingId,
          parameters.keyId,
          parameters.versionId
        );

  return kmsKeyToAccount(new KmsKey(createGcpKmsBackend(client, name)), "gcpKms");
}

function createGcpKmsBackend(
  client: KeyManagementServiceClient,
  name: string
): KmsBackend {
  return {
    async getPublicKey() {
      const [publicKey] = await client.getPublicKey({ name });
      if (!publicKey?.pem) {
        throw new Error("Could not get Public Key from KMS.");
      }
      return pemToDer(publicKey.pem);
    },
    async sign(digest) {
      const [response] = await client.asymmetricSign({
        name,
        digest: { sha256: digest },
      });
      if (!response?.signature) {
        throw new Error("Could not fetch Signature from KMS.");
      }
      return new Uint8Array(response.signature as Uint8Array);
    },
  };
}
