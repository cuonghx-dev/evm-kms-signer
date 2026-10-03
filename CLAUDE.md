# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`@cuonghx/evm-kms-signer`: a single package of EVM signers backed by a pluggable KMS (AWS, GCP, or custom), with adapters for viem v2 and ethers v6. Users compose `createEvmKmsSigner({ kms: awsKms(...) })` with `toViemAccount` / `KmsEthersSigner`.

## Layout

- `src/utils.ts`: `Kms` type, SPKI/PEM parsing, EIP-55 address, `signDigest` (low-s + yParity recovery)
- `src/create-evm-kms-signer.ts`: `createEvmKmsSigner` → `EvmKmsSigner` (caches public key, retries after failure)
- `src/kms/{aws,gcp,local}.ts`: `awsKms`, `gcpKms`, `localKms` factories returning `Kms`
- `src/viem/index.ts`: `toViemAccount` (viem `LocalAccount`, `source` = `kms.type`)
- `src/ethers/index.ts`: `KmsEthersSigner` (ethers `AbstractSigner`)

Each file under `src/kms`, `src/viem`, `src/ethers` is its own subpath export (`/aws`, `/gcp`, `/local`, `/viem`, `/ethers`), mapped in `tsup.config.ts` and `package.json` `exports`/`typesVersions`. Keep them in sync when adding an entry.

## Commands

```bash
npm install
npm run build        # tsup → dist/ (CJS .js + ESM .mjs + .d.ts/.d.mts)
npm test             # test/**/*.unit.spec.ts, mocked KMS, no credentials
npm run typecheck
npm run eslint
npm run test:e2e     # real KMS, needs .env (see .env.example)
npx ts-mocha --files --extension ts test/some-file.unit.spec.ts
```

Tests run against `src/` directly; no build needed.

## Conventions

- `@aws-sdk/client-kms`, `@google-cloud/kms`, `viem`, `ethers` are optional peer dependencies. Only import them from their own subpath entry, never from `src/index.ts` or `src/utils.ts`.
- Every cloud factory accepts an optional `client` so tests can inject a mock.
- Unit tests compare viem/ethers output byte-for-byte with `privateKeyToAccount` / `ethers.Wallet` (RFC 6979 is deterministic).
- `@noble/curves`, `@noble/hashes` stay on v1 (CJS-compatible). TypeScript pinned to 5 so TS 7 isn't hoisted (breaks typescript-eslint).

## npm Scope

Publishes as `@cuonghx/evm-kms-signer` with public access.
