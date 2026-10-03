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
  const publicKey = new Uint8Array(
    AsnConvert.parse(der, SubjectPublicKeyInfo).subjectPublicKey
  );
  if (
    publicKey.length !== UNCOMPRESSED_PUBLIC_KEY_LENGTH ||
    publicKey[0] !== 0x04
  ) {
    throw new Error("KMS public key is not an uncompressed secp256k1 key.");
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
