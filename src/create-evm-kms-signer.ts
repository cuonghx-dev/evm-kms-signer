import {
  Kms,
  publicKeyFromSpki,
  publicKeyToAddress,
  RecoveredSignature,
  signDigest,
} from "./utils";

export type CreateEvmKmsSignerParameters<type extends string = string> = {
  kms: Kms<type>;
};

/**
 * A library-agnostic EVM signer backed by a KMS key. Pass it to an adapter
 * (`toViemAccount`, `KmsEthersSigner`) to use it with viem or ethers.
 */
export type EvmKmsSigner<type extends string = string> = {
  kms: Kms<type>;
  /** Uncompressed secp256k1 public key (`0x04 || x || y`), fetched once */
  getPublicKey(): Promise<Uint8Array>;
  /** EIP-55 checksummed address */
  getAddress(): Promise<`0x${string}`>;
  /** Signs a 32-byte digest; low-s normalized with the recovery bit resolved */
  sign(digest: Uint8Array): Promise<RecoveredSignature>;
};

/**
 * Creates an EVM signer from a KMS. Nothing is fetched until first use.
 *
 * @example
 * const signer = createEvmKmsSigner({ kms: awsKms({ keyId: "alias/my-key" }) });
 */
export function createEvmKmsSigner<type extends string>({
  kms,
}: CreateEvmKmsSignerParameters<type>): EvmKmsSigner<type> {
  let publicKey: Promise<Uint8Array> | undefined;

  const getPublicKey = () => {
    if (!publicKey) {
      publicKey = kms
        .getPublicKey()
        .then(publicKeyFromSpki)
        .catch((error) => {
          publicKey = undefined;
          throw error;
        });
    }
    return publicKey;
  };

  return {
    kms,
    getPublicKey,
    async getAddress() {
      return publicKeyToAddress(await getPublicKey());
    },
    async sign(digest) {
      return signDigest(kms, await getPublicKey(), digest);
    },
  };
}
