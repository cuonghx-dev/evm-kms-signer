# ethers-gcp-kms-signer

The @google-cloud/kms integration with ethers@v6 signer

## Feature

- ethers@v6 signer compatible

## Install

```sh
npm install @cuonghx/ethers-gcp-kms-signer
```

## Usage

### Google cloud

- Go to key management
- Create key with HSM and Elliptic Curve secp256k1 - SHA256 Digest Algorithm

```javascript
signer = new GcpKmsSigner({
  keyVersionName:
    "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
});

// or
signer = new GcpKmsSigner({
  projectId: "",
  locationId: "",
  keyRingId: "",
  keyId: "",
  versionId: "",
});
```
