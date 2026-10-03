# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`evm-kms-signer`: a Lerna + npm workspaces monorepo of EVM signers backed by cloud KMS (AWS and GCP), for both ethers.js v6 and viem v2.

## Packages

- `packages/kms-signer-core`: library-agnostic signing logic (`KmsKey`, `KmsBackend`, SPKI/PEM parsing, `createLocalKmsBackend` for tests)
- `packages/ethers-aws-kms-signer`: `AwsKmsSigner` (ethers `AbstractSigner`) using `@aws-sdk/client-kms`
- `packages/ethers-gcp-kms-signer`: `GcpKmsSigner` (ethers `AbstractSigner`) using `@google-cloud/kms`
- `packages/viem-aws-kms-signer`: `awsKmsToAccount()` returns a viem `LocalAccount`
- `packages/viem-gcp-kms-signer`: `gcpKmsToAccount()` returns a viem `LocalAccount`

## Commands

From repo root:

```bash
npm install      # all workspaces
npm run build    # lerna run build (core builds first; adapters import core's dist/)
npm test         # unit tests with mocked KMS, no credentials
npm run eslint
```

From a package directory:

```bash
npm run build
npm test                 # test/**/*.unit.spec.ts
npm run test:e2e         # ethers packages only, real KMS, needs .env (see .env.example)
npx ts-mocha --files -r tsconfig-paths/register test/some-file.unit.spec.ts
```

Rebuild `kms-signer-core` after changing it. Adapters resolve it through the workspace symlink to its `dist/`.

## Architecture

- `kms-signer-core` defines `KmsBackend { getPublicKey(): DER SPKI; sign(digest): DER ECDSA sig }`. `KmsKey` caches the public key and address. `sign()` parses the DER signature with `@noble/curves`, normalizes to low-s (EIP-2), and resolves `yParity` by recovering the public key. It throws if neither parity matches.
- Each adapter has a small cloud backend (`createAwsKmsBackend` / `createGcpKmsBackend`). It is duplicated between the ethers and viem packages for the same cloud.
- ethers adapters extend `AbstractSigner` and delegate `_sign(digest)` to `KmsKey`.
- viem adapters share `kms-key-to-account.ts` (duplicated in both viem packages), which wraps `KmsKey` with `toAccount`.
- Every config accepts an optional `client` so tests can inject a mock. Unit tests compare viem output byte-for-byte with `privateKeyToAccount` (RFC 6979 is deterministic).

## Key Dependencies

- `ethers` v6 (dependency of the ethers packages), `viem` v2 (peer dependency of the viem packages)
- `@noble/curves`, `@noble/hashes` v1 (CJS-compatible), `@peculiar/asn1-x509` for SPKI parsing
- TypeScript 5 (root pins it so TS 7 isn't hoisted, which would break typescript-eslint)
- Testing: Mocha + Chai via `ts-mocha`

## npm Scope

All packages publish under `@cuonghx.gu-tech/` with public access.
