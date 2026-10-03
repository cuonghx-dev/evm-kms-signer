# evm-kms-signer

Sign Ethereum transactions, messages, and typed data with keys held in a KMS. Ships backends for **AWS KMS** and **GCP Cloud KMS**, accepts any KMS you plug in yourself, and works with **viem v2** and **ethers v6**.

```typescript
import { createEvmKmsSigner } from "@cuonghx/evm-kms-signer";
import { awsKms } from "@cuonghx/evm-kms-signer/aws";
import { toViemAccount } from "@cuonghx/evm-kms-signer/viem";

const signer = createEvmKmsSigner({
  kms: awsKms({ keyId: "your-kms-key-id", region: "us-east-1" }),
});
const account = await toViemAccount(signer);
```

## Install

The cloud SDKs and signing libraries are optional peer dependencies. Install only the ones you use:

```sh
npm install @cuonghx/evm-kms-signer

npm install @aws-sdk/client-kms   # for /aws
npm install @google-cloud/kms     # for /gcp
npm install viem                  # for /viem (>= 2.24.0)
npm install ethers                # for /ethers (v6)
```

| Import | Exports |
| --- | --- |
| `@cuonghx/evm-kms-signer` | `createEvmKmsSigner`, `Kms`, `EvmKmsSigner`, key helpers |
| `@cuonghx/evm-kms-signer/aws` | `awsKms` |
| `@cuonghx/evm-kms-signer/gcp` | `gcpKms`, `crc32c` |
| `@cuonghx/evm-kms-signer/local` | `localKms` (in-memory key, for tests only) |
| `@cuonghx/evm-kms-signer/viem` | `toViemAccount` |
| `@cuonghx/evm-kms-signer/ethers` | `KmsEthersSigner` |

## Key setup

- **AWS KMS**: create an asymmetric **Sign and verify** key with key spec `ECC_SECG_P256K1`.
- **GCP Cloud KMS**: create a key with purpose **Asymmetric sign** and algorithm **Elliptic Curve secp256k1 - SHA256 Digest** (HSM protection level).

Keys on any other curve (e.g. P-256) are rejected when the public key is fetched, rather than producing a wrong address.

## Usage

### 1. Pick a KMS

```typescript
import { awsKms } from "@cuonghx/evm-kms-signer/aws";
import { gcpKms } from "@cuonghx/evm-kms-signer/gcp";

const aws = awsKms({ keyId: "your-kms-key-id", region: "us-east-1" });

const gcp = gcpKms({
  keyVersionName:
    "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1",
});
```

GCP also accepts the key path as separate fields (`projectId`, `locationId`, `keyRingId`, `keyId`, `versionId`).

Both use the cloud SDK's default credential chain when no credentials are passed. To control the client (credentials, endpoint, retries), pass your own:

```typescript
import { KMSClient } from "@aws-sdk/client-kms";
import { KeyManagementServiceClient } from "@google-cloud/kms";

awsKms({ keyId, client: new KMSClient({ region, credentials }) });
gcpKms({ keyVersionName, client: new KeyManagementServiceClient({ keyFilename }) });
```

`gcpKms` follows GCP's [data integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines): it sends a CRC32C of each digest and verifies the returned `name`, `pemCrc32c`, `signatureCrc32c` and `verifiedDigestCrc32c`. The official client returns all of these; a custom or mocked client must too.

### 2. Create the signer

```typescript
import { createEvmKmsSigner } from "@cuonghx/evm-kms-signer";

const signer = createEvmKmsSigner({ kms: aws });

await signer.getAddress(); // EIP-55 checksummed
await signer.sign(digest); // { r, s, yParity }, low-s normalized
```

Nothing is fetched until first use. The public key is fetched once and cached.

### 3. Use it with viem or ethers

**viem**

```typescript
import { toViemAccount } from "@cuonghx/evm-kms-signer/viem";
import { createWalletClient, http, parseEther } from "viem";
import { mainnet } from "viem/chains";

const account = await toViemAccount(signer);
const client = createWalletClient({ account, chain: mainnet, transport: http() });
await client.sendTransaction({ to: "0x...", value: parseEther("0.001") });
```

The account supports `sign`, `signMessage`, `signTypedData`, `signTransaction` (including EIP-4844), and `signAuthorization` (EIP-7702). Its `source` is the KMS `type` (`"awsKms"`, `"gcpKms"`, ...).

**ethers v6**

```typescript
import { KmsEthersSigner } from "@cuonghx/evm-kms-signer/ethers";
import { JsonRpcProvider } from "ethers";

const wallet = new KmsEthersSigner(signer, new JsonRpcProvider("https://..."));
await wallet.sendTransaction({ to: "0x...", value: 1n });
```

### Custom KMS

Any object implementing `Kms` works, so you can back the signer with Azure Key Vault, HashiCorp Vault, an HSM, or a remote signing service:

```typescript
import { createEvmKmsSigner, Kms } from "@cuonghx/evm-kms-signer";

const myKms: Kms<"myKms"> = {
  type: "myKms",
  // DER-encoded SubjectPublicKeyInfo of a secp256k1 key
  async getPublicKey() { /* ... */ },
  // DER-encoded ECDSA signature over the 32-byte digest
  async sign(digest) { /* ... */ },
};

const signer = createEvmKmsSigner({ kms: myKms });
```

`createEvmKmsSigner` handles DER parsing, curve validation, low-s normalization (EIP-2), and recovery bit resolution. If your KMS returns PEM, convert it with `pemToDer`.

## Migrating from the per-cloud packages

| Before | After |
| --- | --- |
| `new AwsKmsSigner({ keyId, region }, provider)` from `@cuonghx/ethers-aws-kms-signer` | `new KmsEthersSigner(createEvmKmsSigner({ kms: awsKms({ keyId, region }) }), provider)` |
| `new GcpKmsSigner({ keyVersionName }, provider)` from `@cuonghx/ethers-gcp-kms-signer` | `new KmsEthersSigner(createEvmKmsSigner({ kms: gcpKms({ keyVersionName }) }), provider)` |
| `await awsKmsToAccount({ keyId })` from `@cuonghx/viem-aws-kms-signer` | `await toViemAccount(createEvmKmsSigner({ kms: awsKms({ keyId }) }))` |
| `await gcpKmsToAccount({ keyVersionName })` from `@cuonghx/viem-gcp-kms-signer` | `await toViemAccount(createEvmKmsSigner({ kms: gcpKms({ keyVersionName }) }))` |
| `createLocalKmsBackend(privateKey, { forceHighS })` from `@cuonghx/kms-signer-core` | `localKms({ privateKey, forceHighS })` |

## Development

```bash
npm install
npm run build      # tsup: ESM + CJS + types per entry
npm test           # unit tests with a mocked KMS, no credentials needed
npm run typecheck
npm run eslint
```

End-to-end tests run against a real KMS. Copy `.env.example` to `.env`, fill it in, then run `npm run test:e2e`.

## License

MIT
