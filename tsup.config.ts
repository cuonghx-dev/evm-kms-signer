import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "aws/index": "src/kms/aws.ts",
    "gcp/index": "src/kms/gcp.ts",
    "local/index": "src/kms/local.ts",
    "viem/index": "src/viem/index.ts",
    "ethers/index": "src/ethers/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  target: "es2022",
});
