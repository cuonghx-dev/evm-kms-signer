import { KmsKey } from "@cuonghx.gu-tech/kms-signer-core";
import {
  getAddress,
  hashMessage,
  hashTypedData,
  Hex,
  hexToBytes,
  keccak256,
  LocalAccount,
  numberToHex,
  serializeSignature,
  serializeTransaction,
  Signature,
  toHex,
} from "viem";
import { toAccount } from "viem/accounts";
import { hashAuthorization } from "viem/utils";

/**
 * Wraps a `KmsKey` into a viem `LocalAccount`.
 */
export async function kmsKeyToAccount<source extends string>(
  key: KmsKey,
  source: source
): Promise<LocalAccount<source>> {
  const publicKey = toHex(await key.getPublicKey());
  const address = getAddress(await key.getAddress());

  const sign = async (hash: Hex): Promise<Signature> => {
    const { r, s, yParity } = await key.sign(hexToBytes(hash));
    return {
      r: numberToHex(r, { size: 32 }),
      s: numberToHex(s, { size: 32 }),
      v: BigInt(yParity) + BigInt(27),
      yParity,
    };
  };

  const account = toAccount({
    address,
    async sign({ hash }) {
      return serializeSignature(await sign(hash));
    },
    async signAuthorization(authorization) {
      const { chainId, nonce } = authorization;
      const address = authorization.contractAddress ?? authorization.address;
      const signature = await sign(
        hashAuthorization({ address, chainId, nonce })
      );
      return { address, chainId, nonce, ...signature };
    },
    async signMessage({ message }) {
      return serializeSignature(await sign(hashMessage(message)));
    },
    async signTransaction(
      transaction,
      { serializer = serializeTransaction } = {}
    ) {
      // For EIP-4844 transactions, sign the payload body without the sidecars
      // (same as viem's own `signTransaction`)
      const signableTransaction =
        transaction.type === "eip4844"
          ? { ...transaction, sidecars: false as const }
          : transaction;
      const signature = await sign(
        keccak256(await serializer(signableTransaction))
      );
      return serializer(transaction, signature);
    },
    async signTypedData(typedData) {
      return serializeSignature(await sign(hashTypedData(typedData)));
    },
  });

  return {
    ...account,
    publicKey,
    source,
  } as LocalAccount<source>;
}
