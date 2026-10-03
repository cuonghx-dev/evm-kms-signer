import { KeyManagementServiceClient } from "@google-cloud/kms";

import { Kms, pemToDer } from "../utils";

type GcpKeyVersionPath = {
  projectId: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  versionId: string;
};

export type GcpKmsParameters = {
  clientOptions?: ConstructorParameters<typeof KeyManagementServiceClient>[0];
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
 * GCP Cloud KMS backend for an `EC_SIGN_SECP256K1_SHA256` key.
 */
export function gcpKms(parameters: GcpKmsParameters): Kms<"gcpKms"> {
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

  return {
    type: "gcpKms",
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
