# evm-kms-signer

Sign Ethereum transactions, messages, and typed data with keys held in cloud KMS (AWS KMS, GCP Cloud KMS). Works with **ethers v6** and **viem**.

## Packages

| Package | Library | Cloud | Version |
| --- | --- | --- | --- |
| [`@cuonghx.gu-tech/ethers-aws-kms-signer`](./packages/ethers-aws-kms-signer) | ethers v6 | AWS KMS | 0.10.0 |
| [`@cuonghx.gu-tech/ethers-gcp-kms-signer`](./packages/ethers-gcp-kms-signer) | ethers v6 | GCP Cloud KMS | 0.10.0 |
| [`@cuonghx.gu-tech/viem-aws-kms-signer`](./packages/viem-aws-kms-signer) | viem v2 | AWS KMS | 0.1.0 |
| [`@cuonghx.gu-tech/viem-gcp-kms-signer`](./packages/viem-gcp-kms-signer) | viem v2 | GCP Cloud KMS | 0.1.0 |
| [`@cuonghx.gu-tech/kms-signer-core`](./packages/kms-signer-core) | — | — | 0.1.0 |

`kms-signer-core` holds the shared, library-agnostic signing logic. You don't need to install it directly.

## Key setup

- **AWS KMS**: create an asymmetric **Sign and verify** key with key spec `ECC_SECG_P256K1`.
- **GCP Cloud KMS**: create a key with purpose **Asymmetric sign** and algorithm **Elliptic Curve secp256k1 - SHA256 Digest** (HSM protection level).

## Usage

### ethers v6

```sh
npm install @cuonghx.gu-tech/ethers-aws-kms-signer
# or
npm install @cuonghx.gu-tech/ethers-gcp-kms-signer
```

```typescript
import { AwsKmsSigner } from "@cuonghx.gu-tech/ethers-aws-kms-signer";
import { GcpKmsSigner } from "@cuonghx.gu-tech/ethers-gcp-kms-signer";
import { JsonRpcProvider } from "ethers";

const provider = new JsonRpcProvider("https://...");

const awsSigner = new AwsKmsSigner(
  { keyId: "your-kms-key-id", region: "us-east-1" },
  provider
);

const gcpSigner = new GcpKmsSigner(
  {
    keyVersionName:
      "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1",
  },
  provider
);

await awsSigner.sendTransaction({ to: "0x...", value: 1n });
```

### viem

```sh
npm install viem @cuonghx.gu-tech/viem-aws-kms-signer
# or
npm install viem @cuonghx.gu-tech/viem-gcp-kms-signer
```

```typescript
import { awsKmsToAccount } from "@cuonghx.gu-tech/viem-aws-kms-signer";
import { gcpKmsToAccount } from "@cuonghx.gu-tech/viem-gcp-kms-signer";
import { createWalletClient, http, parseEther } from "viem";
import { mainnet } from "viem/chains";

const account = await gcpKmsToAccount({
  keyVersionName:
    "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1",
});
// or: await awsKmsToAccount({ keyId: "your-kms-key-id", region: "us-east-1" })

const client = createWalletClient({ account, chain: mainnet, transport: http() });
await client.sendTransaction({ to: "0x...", value: parseEther("0.001") });
```

The viem account supports `sign`, `signMessage`, `signTypedData`, `signTransaction` (including EIP-4844), and `signAuthorization` (EIP-7702).

### Credentials and custom clients

All packages use the cloud SDK's default credential chain when no credentials are passed. To control the client (credentials, endpoint, retries), pass your own:

```typescript
import { KMSClient } from "@aws-sdk/client-kms";
import { KeyManagementServiceClient } from "@google-cloud/kms";

new AwsKmsSigner({ keyId, client: new KMSClient({ region, credentials }) });
await gcpKmsToAccount({ keyVersionName, client: new KeyManagementServiceClient({ keyFilename }) });
```

GCP also accepts the key path as separate fields (`projectId`, `locationId`, `keyRingId`, `keyId`, `versionId`) instead of `keyVersionName`.

## Development

```bash
npm install       # install all workspaces
npm run build     # build all packages (core first)
npm test          # unit tests with a mocked KMS, no credentials needed
npm run eslint
```

End-to-end tests against a real KMS live in the ethers packages. Copy `.env.example` to `.env`, fill it in, then run `npm run test:e2e` inside the package.

## License

MIT
