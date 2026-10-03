import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";

/**
 * Minimal interface a KMS must provide to back an EVM signer. Implement it to
 * plug in any key store (Azure Key Vault, HashiCorp Vault, an HSM, ...).
 */
export type Kms<type extends string = string> = {
  /** Identifies the KMS, e.g. `"awsKms"`; used as the viem account `source` */
  type: type;
  /** DER-encoded `SubjectPublicKeyInfo` of a secp256k1 key */
  getPublicKey(): Promise<Uint8Array>;
  /** DER-encoded `ECDSA-Sig-Value` over the given 32-byte digest */
  sign(digest: Uint8Array): Promise<Uint8Array>;
};

export type RecoveredSignature = {
  r: bigint;
  s: bigint;
  yParity: 0 | 1;
};

const UNCOMPRESSED_PUBLIC_KEY_LENGTH = 65;
const EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";
// DER-encoded OBJECT IDENTIFIER 1.3.132.0.10 (secp256k1)
const SECP256K1_CURVE_OID_DER = Uint8Array.from([
  0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a,
]);

export function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s/g, "");
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Extracts the uncompressed secp256k1 public key (`0x04 || x || y`) from a
 * DER-encoded `SubjectPublicKeyInfo`.
 */
export function publicKeyFromSpki(der: Uint8Array): Uint8Array {
  const spki = AsnConvert.parse(der, SubjectPublicKeyInfo);
  const { algorithm, parameters } = spki.algorithm;
  // Other EC curves (e.g. P-256) share the same 65-byte encoding, so check the
  // curve explicitly instead of deriving a wrong address from them.
  if (
    algorithm !== EC_PUBLIC_KEY_OID ||
    !parameters ||
    !equalBytes(new Uint8Array(parameters), SECP256K1_CURVE_OID_DER)
  ) {
    throw new Error("KMS public key is not a secp256k1 key.");
  }

  const publicKey = new Uint8Array(spki.subjectPublicKey);
  if (
    publicKey.length !== UNCOMPRESSED_PUBLIC_KEY_LENGTH ||
    publicKey[0] !== 0x04
  ) {
    throw new Error("KMS public key is not an uncompressed secp256k1 key.");
  }
  try {
    secp256k1.ProjectivePoint.fromHex(publicKey).assertValidity();
  } catch {
    throw new Error("KMS public key is not a valid secp256k1 point.");
  }
  return publicKey;
}

/**
 * Derives the EIP-55 checksummed Ethereum address from an uncompressed public
 * key.
 */
export function publicKeyToAddress(publicKey: Uint8Array): `0x${string}` {
  // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
  const hash = keccak_256(publicKey.subarray(1));
  return toChecksumAddress(Buffer.from(hash.subarray(-20)).toString("hex"));
}

function toChecksumAddress(lowercaseHex: string): `0x${string}` {
  const hash = keccak_256(new TextEncoder().encode(lowercaseHex));
  let address = "0x";
  for (let i = 0; i < lowercaseHex.length; i++) {
    const nibble = (hash[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    address += nibble >= 8 ? lowercaseHex[i].toUpperCase() : lowercaseHex[i];
  }
  return address as `0x${string}`;
}

/**
 * Signs a 32-byte digest with the KMS key and returns an Ethereum-ready
 * signature: low-s normalized (EIP-2) with the recovery bit resolved.
 */
export async function signDigest(
  kms: Kms,
  publicKey: Uint8Array,
  digest: Uint8Array
): Promise<RecoveredSignature> {
  if (digest.length !== 32) {
    throw new Error(`Invalid digest length: ${digest.length}, expected 32.`);
  }

  const der = await kms.sign(digest);
  const signature = secp256k1.Signature.fromDER(der).normalizeS();

  for (const yParity of [0, 1] as const) {
    const recovered = signature
      .addRecoveryBit(yParity)
      .recoverPublicKey(digest)
      .toRawBytes(false);
    if (equalBytes(recovered, publicKey)) {
      return { r: signature.r, s: signature.s, yParity };
    }
  }

  throw new Error("KMS signature does not match the key's public key.");
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
