/* eslint-disable import/no-extraneous-dependencies */
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from "@aws-sdk/client-kms";
import { KmsBackend, KmsKey } from "@cuonghx/kms-signer-core";
import {
  AwsCredentialIdentity,
  AwsCredentialIdentityProvider,
} from "@smithy/types";
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

export type EthersAwsKmsSignerConfig = {
  /** Falls back to the AWS SDK default credential chain when omitted */
  credentials?: AwsCredentialIdentityProvider | AwsCredentialIdentity;
  region?: string;
  keyId: string;
  /** Pre-configured KMS client; takes precedence over `region`/`credentials` */
  client?: KMSClient;
};

export class AwsKmsSigner<
  P extends null | Provider = null | Provider
> extends AbstractSigner {
  private config: EthersAwsKmsSignerConfig;
  private key: KmsKey;

  constructor(config: EthersAwsKmsSignerConfig, provider?: P) {
    super(provider);
    this.config = config;
    const client =
      config.client ??
      new KMSClient({ region: config.region, credentials: config.credentials });
    this.key = new KmsKey(createAwsKmsBackend(client, config.keyId));
  }

  connect(provider: Provider | null): AwsKmsSigner {
    return new AwsKmsSigner(this.config, provider);
  }

  async getAddress(): Promise<string> {
    return getAddress(await this.key.getAddress());
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

    const { r, s, yParity } = await this.key.sign(getBytes(digest));

    return Signature.from({
      r: toBeHex(r, 32),
      s: toBeHex(s, 32),
      yParity,
    });
  }
}

function createAwsKmsBackend(client: KMSClient, keyId: string): KmsBackend {
  return {
    async getPublicKey() {
      const response = await client.send(
        new GetPublicKeyCommand({ KeyId: keyId })
      );
      if (!response.PublicKey) {
        throw new Error("Could not get Public Key from KMS.");
      }
      return response.PublicKey;
    },
    async sign(digest) {
      const response = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: digest,
          MessageType: "DIGEST",
          SigningAlgorithm: "ECDSA_SHA_256",
        })
      );
      if (!response.Signature) {
        throw new Error("Could not fetch Signature from KMS.");
      }
      return response.Signature;
    },
  };
}
