import {
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

import { EvmKmsSigner } from "../create-evm-kms-signer";

/**
 * Wraps an `EvmKmsSigner` into a viem `LocalAccount` whose `source` is the
 * KMS `type`.
 */
export async function toViemAccount<type extends string>(
  signer: EvmKmsSigner<type>
): Promise<LocalAccount<type>> {
  const publicKey = toHex(await signer.getPublicKey());
  const address = await signer.getAddress();

  const sign = async (hash: Hex): Promise<Signature> => {
    const { r, s, yParity } = await signer.sign(hexToBytes(hash));
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
    source: signer.kms.type,
  } as LocalAccount<type>;
}
