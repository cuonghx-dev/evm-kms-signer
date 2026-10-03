import {
  KmsBackend,
  KmsKey,
  pemToDer,
} from "@cuonghx.gu-tech/kms-signer-core";
import { KeyManagementServiceClient } from "@google-cloud/kms";
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
import { ClientOptions } from "google-gax";

type GcpKeyVersionPath = {
  projectId: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  versionId: string;
};

export type EthersGcpKmsSignerConfig = {
  clientOptions?: ClientOptions;
  /** Pre-configured KMS client; takes precedence over `clientOptions` */
  client?: KeyManagementServiceClient;
} & (
  | GcpKeyVersionPath
  | {
      /** Full key version resource name, e.g. `projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1` */
      keyVersionName: string;
    }
);

export class GcpKmsSigner<
  P extends null | Provider = null | Provider
> extends AbstractSigner {
  private config: EthersGcpKmsSignerConfig;
  private key: KmsKey;

  constructor(config: EthersGcpKmsSignerConfig, provider?: P) {
    super(provider);
    this.config = config;
    const client =
      config.client ?? new KeyManagementServiceClient(config.clientOptions);
    this.key = new KmsKey(
      createGcpKmsBackend(client, resolveKeyVersionName(client, config))
    );
  }

  connect(provider: Provider | null): GcpKmsSigner {
    return new GcpKmsSigner(this.config, provider);
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

function resolveKeyVersionName(
  client: KeyManagementServiceClient,
  config: EthersGcpKmsSignerConfig
): string {
  if ("keyVersionName" in config) {
    return config.keyVersionName;
  }
  return client.cryptoKeyVersionPath(
    config.projectId,
    config.locationId,
    config.keyRingId,
    config.keyId,
    config.versionId
  );
}

function createGcpKmsBackend(
  client: KeyManagementServiceClient,
  name: string
): KmsBackend {
  return {
    async getPublicKey() {
      const [publicKey] = await client.getPublicKey({ name });
      if (!publicKey?.pem) {
        throw new Error("Could not get Public Key from KMS.");
      }
      return pemToDer(publicKey.pem);
    },
    async sign(digest) {
      const [response] = await client.asymmetricSign({
        name,
        digest: { sha256: digest },
      });
      if (!response?.signature) {
        throw new Error("Could not fetch Signature from KMS.");
      }
      return new Uint8Array(response.signature as Uint8Array);
    },
  };
}
