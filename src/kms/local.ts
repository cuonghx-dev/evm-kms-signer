import { secp256k1 } from "@noble/curves/secp256k1";

import { Kms } from "../utils";

// DER header of a SubjectPublicKeyInfo for an uncompressed secp256k1 key:
// SEQUENCE { SEQUENCE { id-ecPublicKey, secp256k1 }, BIT STRING (65 bytes) }
const SECP256K1_SPKI_PREFIX = Buffer.from(
  "3056301006072a8648ce3d020106052b8104000a034200",
  "hex"
);

export type LocalKmsParameters = {
  privateKey: Uint8Array;
  /** Return high-s signatures, as a real KMS may, to exercise normalization */
  forceHighS?: boolean;
};

/**
 * A `Kms` backed by an in-memory private key. Intended for tests and local
 * development only.
 */
export function localKms({
  privateKey,
  forceHighS,
}: LocalKmsParameters): Kms<"local"> & { publicKeyPem(): string } {
  const spki = new Uint8Array(
    Buffer.concat([
      SECP256K1_SPKI_PREFIX,
      secp256k1.getPublicKey(privateKey, false),
    ])
  );

  return {
    type: "local",
    async getPublicKey() {
      return spki;
    },
    async sign(digest) {
      const { r, s } = secp256k1.sign(digest, privateKey);
      const highS = forceHighS ? secp256k1.CURVE.n - s : s;
      return new secp256k1.Signature(r, highS).toDERRawBytes();
    },
    publicKeyPem() {
      const base64 = Buffer.from(spki).toString("base64");
      return `-----BEGIN PUBLIC KEY-----\n${base64
        .match(/.{1,64}/g)!
        .join("\n")}\n-----END PUBLIC KEY-----\n`;
    },
  };
}
