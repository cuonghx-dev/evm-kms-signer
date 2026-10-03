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

  // Integrity checks follow https://cloud.google.com/kms/docs/data-integrity-guidelines
  return {
    type: "gcpKms",
    async getPublicKey() {
      const [publicKey] = await client.getPublicKey({ name });
      if (!publicKey?.pem) {
        throw new Error("Could not get Public Key from KMS.");
      }
      if (publicKey.name !== name) {
        throw new Error("GCP KMS returned the public key of another key.");
      }
      if (
        crc32c(Buffer.from(publicKey.pem)) !==
        Number(publicKey.pemCrc32c?.value)
      ) {
        throw new Error("GCP KMS public key failed the CRC32C check.");
      }
      return pemToDer(publicKey.pem);
    },
    async sign(digest) {
      const [response] = await client.asymmetricSign({
        name,
        digest: { sha256: digest },
        digestCrc32c: { value: crc32c(digest) },
      });
      if (!response?.signature) {
        throw new Error("Could not fetch Signature from KMS.");
      }
      if (response.name !== name) {
        throw new Error("GCP KMS signed with another key.");
      }
      if (!response.verifiedDigestCrc32c) {
        throw new Error("GCP KMS digest failed the CRC32C check.");
      }
      const signature =
        typeof response.signature === "string"
          ? new Uint8Array(Buffer.from(response.signature, "base64"))
          : new Uint8Array(response.signature);
      if (crc32c(signature) !== Number(response.signatureCrc32c?.value)) {
        throw new Error("GCP KMS signature failed the CRC32C check.");
      }
      return signature;
    },
  };
}

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? (c >>> 1) ^ 0x82f63b78 : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

/** CRC32C (Castagnoli), as used by GCP KMS integrity fields */
export function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC32C_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
