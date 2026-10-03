# viem-aws-kms-signer

AWS KMS account for [viem](https://viem.sh).

## Install

```sh
npm install viem @cuonghx.gu-tech/viem-aws-kms-signer
```

## Usage

```typescript
import { awsKmsToAccount } from "@cuonghx.gu-tech/viem-aws-kms-signer";
import { createWalletClient, http } from "viem";
import { mainnet } from "viem/chains";

const account = await awsKmsToAccount({ keyId: "your-kms-key-id", region: "us-east-1" });

const client = createWalletClient({ account, chain: mainnet, transport: http() });
```

See the [repository README](https://github.com/cuonghx-dev/evm-kms-signer#readme) for key setup and credential options.
