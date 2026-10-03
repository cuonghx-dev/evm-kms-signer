# kms-signer-core

Library-agnostic secp256k1 signing primitives shared by the `evm-kms-signer` packages:

- `KmsKey`: wraps a `KmsBackend`, caches the public key and address, and returns low-s (EIP-2) signatures with the recovery bit resolved
- `publicKeyFromSpki`, `pemToDer`, `publicKeyToAddress`: KMS public key parsing
- `createLocalKmsBackend`: in-memory backend for tests

You normally depend on one of the ethers or viem packages instead of this one. See the [repository README](https://github.com/cuonghx-dev/evm-kms-signer#readme).
