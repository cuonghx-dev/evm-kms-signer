import {
  AbstractSigner,
  assert,
  assertArgument,
  BytesLike,
  dataLength,
  getAddress,
  getBytes,
  hashMessage,
  Provider,
  resolveAddress,
  resolveProperties,
  Signature,
  toBeHex,
  Transaction,
  TransactionLike,
  TransactionRequest,
  TypedDataDomain,
  TypedDataEncoder,
  TypedDataField,
} from "ethers";

import { EvmKmsSigner } from "../create-evm-kms-signer";

/**
 * An ethers v6 signer backed by an `EvmKmsSigner`.
 */
export class KmsEthersSigner<
  P extends null | Provider = null | Provider
> extends AbstractSigner<P> {
  readonly signer: EvmKmsSigner;

  constructor(signer: EvmKmsSigner, provider?: P) {
    super(provider);
    this.signer = signer;
  }

  connect(provider: Provider | null): KmsEthersSigner {
    return new KmsEthersSigner(this.signer, provider);
  }

  async getAddress(): Promise<string> {
    return this.signer.getAddress();
  }

  async signTransaction(tx: TransactionRequest): Promise<string> {
    // Replace any Addressable or ENS name with an address
    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this.provider) : undefined,
      from: tx.from ? resolveAddress(tx.from, this.provider) : undefined,
    });

    if (to != null) {
      tx.to = to;
    }
    if (from != null) {
      tx.from = from;
    }

    const address = await this.getAddress();

    if (tx.from != null) {
      assertArgument(
        getAddress(tx.from as string) === address,
        "transaction from address mismatch",
        "tx.from",
        tx.from
      );
      delete tx.from;
    }

    // Build the transaction
    const btx = Transaction.from(tx as TransactionLike<string>);
    btx.signature = await this._sign(btx.unsignedHash);

    return btx.serialized;
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    const signature = await this._sign(hashMessage(message));
    return signature.serialized;
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, any>
  ): Promise<string> {
    // Populate any ENS names
    const populated = await TypedDataEncoder.resolveNames(
      domain,
      types,
      value,
      async (name: string) => {
        // @TODO: this should use resolveName; addresses don't
        //        need a provider

        assert(
          this.provider != null,
          "cannot resolve ENS names without a provider",
          "UNSUPPORTED_OPERATION",
          {
            operation: "resolveName",
            info: { name },
          }
        );

        const address = await this.provider.resolveName(name);
        assert(address != null, "unconfigured ENS name", "UNCONFIGURED_NAME", {
          value: name,
        });

        return address;
      }
    );

    const signature = await this._sign(
      TypedDataEncoder.hash(populated.domain, types, populated.value)
    );

    return signature.serialized;
  }

  private async _sign(digest: BytesLike): Promise<Signature> {
    assertArgument(
      dataLength(digest) === 32,
      "invalid digest length",
      "digest",
      digest
    );

    const { r, s, yParity } = await this.signer.sign(getBytes(digest));

    return Signature.from({
      r: toBeHex(r, 32),
      s: toBeHex(s, 32),
      yParity,
    });
  }
}
