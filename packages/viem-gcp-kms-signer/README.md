# viem-gcp-kms-signer

GCP Cloud KMS account for [viem](https://viem.sh).

## Install

```sh
npm install viem @cuonghx/viem-gcp-kms-signer
```

## Usage

```typescript
import { gcpKmsToAccount } from "@cuonghx/viem-gcp-kms-signer";
import { createWalletClient, http } from "viem";
import { mainnet } from "viem/chains";

const account = await gcpKmsToAccount({
  keyVersionName:
    "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
});

const client = createWalletClient({ account, chain: mainnet, transport: http() });
```

See the [repository README](https://github.com/cuonghx-dev/evm-kms-signer#readme) for key setup and credential options.
