import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";

/**
 * Minimal interface a cloud KMS must provide to back an EVM signer.
 */
export type KmsBackend = {
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
 * Derives the lowercase Ethereum address from an uncompressed public key.
 */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
  const hash = keccak_256(publicKey.subarray(1));
  return `0x${Buffer.from(hash.subarray(-20)).toString("hex")}`;
}

/**
 * Signs a 32-byte digest with the KMS key and returns an Ethereum-ready
 * signature: low-s normalized (EIP-2) with the recovery bit resolved.
 */
export async function signDigest(
  backend: KmsBackend,
  publicKey: Uint8Array,
  digest: Uint8Array
): Promise<RecoveredSignature> {
  if (digest.length !== 32) {
    throw new Error(`Invalid digest length: ${digest.length}, expected 32.`);
  }

  const der = await backend.sign(digest);
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

/**
 * A KMS-backed secp256k1 key with cached public key and address.
 */
export class KmsKey {
  private publicKey?: Promise<Uint8Array>;

  constructor(private readonly backend: KmsBackend) {}

  getPublicKey(): Promise<Uint8Array> {
    if (!this.publicKey) {
      this.publicKey = this.backend
        .getPublicKey()
        .then(publicKeyFromSpki)
        .catch((error) => {
          this.publicKey = undefined;
          throw error;
        });
    }
    return this.publicKey;
  }

  async getAddress(): Promise<string> {
    return publicKeyToAddress(await this.getPublicKey());
  }

  async sign(digest: Uint8Array): Promise<RecoveredSignature> {
    return signDigest(this.backend, await this.getPublicKey(), digest);
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
