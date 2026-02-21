import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import path from "node:path";

import { RuntimeBuilder, TxCreateRequestBuilder, WalletAbiSdkValidationError } from "../../src";
import {
  TESTNET_POLICY_ASSET,
  baseRequest,
  entropy32,
  providedInput,
  scriptOutput,
  simfFinalizer,
  walletInput,
} from "../fixtures";

const repoRoot = path.resolve(import.meta.dir, "../../../../");

function runRustValidator(payload: unknown, runtimeNetwork = "testnet-liquid") {
  const process = spawnSync(
    "cargo",
    ["run", "-q", "-p", "wallet-abi", "--bin", "wallet_abi_sdk_validate", "--", "--runtime-network", runtimeNetwork],
    {
      cwd: repoRoot,
      input: JSON.stringify(payload),
      encoding: "utf8",
    },
  );

  return {
    exitCode: process.status,
    stdout: process.stdout,
    stderr: process.stderr,
  };
}

describe("Rust compatibility (wallet_abi_sdk_validate)", () => {
  it("accepts a minimal transfer-like request", () => {
    const request = new TxCreateRequestBuilder({
      request_id: "integration-minimal",
      network: "testnet-liquid",
      broadcast: false,
      params: new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()),
    }).build();

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(0);
  });

  it("accepts provided outpoint input request", () => {
    const request = new TxCreateRequestBuilder({
      request_id: "integration-provided",
      network: "testnet-liquid",
      params: new RuntimeBuilder().addInput(providedInput()).addOutput(scriptOutput()),
    }).build();

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(0);
  });

  it("accepts new issuance asset+token shape", () => {
    const request = new TxCreateRequestBuilder({
      request_id: "integration-new-issuance",
      network: "testnet-liquid",
      params: new RuntimeBuilder()
        .addInput({
          ...walletInput(),
          issuance: {
            kind: "new",
            asset_amount_sat: 50,
            token_amount_sat: 1,
            entropy: entropy32(11),
          },
        })
        .addOutput({
          ...scriptOutput("token", 1),
          asset: { type: "new_issuance_token", input_index: 0 },
        })
        .addOutput({
          ...scriptOutput("asset", 50),
          asset: { type: "new_issuance_asset", input_index: 0 },
        }),
    }).build();

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(0);
  });

  it("accepts reissuance shape", () => {
    const request = new TxCreateRequestBuilder({
      request_id: "integration-reissuance",
      network: "testnet-liquid",
      params: new RuntimeBuilder()
        .addInput({
          ...walletInput(),
          issuance: {
            kind: "reissue",
            asset_amount_sat: 25,
            token_amount_sat: 0,
            entropy: entropy32(23),
          },
        })
        .addOutput({
          ...scriptOutput("token-keep", 1),
          asset: {
            type: "asset_id",
            asset_id: TESTNET_POLICY_ASSET,
          },
        })
        .addOutput({
          ...scriptOutput("reissued-asset", 25),
          asset: { type: "re_issuance_asset", input_index: 0 },
        }),
    }).build();

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(0);
  });

  it("accepts simf finalizer shape", () => {
    const request = new TxCreateRequestBuilder({
      request_id: "integration-simf",
      network: "testnet-liquid",
      params: new RuntimeBuilder()
        .addInput({
          ...walletInput(),
          finalizer: simfFinalizer(),
        })
        .addOutput({
          ...scriptOutput("simf-lock"),
          lock: {
            type: "finalizer",
            finalizer: {
              type: "wallet",
            },
          },
        }),
    }).build();

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(0);
  });

  it("rejects mismatched network against runtime network", () => {
    const request = baseRequest("testnet-liquid");
    const result = runRustValidator(request, "liquid");

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("request network mismatch");
  });

  it("rejects wrong abi version", () => {
    const request = {
      ...baseRequest(),
      abi_version: "wallet-create-0.0",
    };

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("abi_version mismatch");
  });

  it("rejects malformed issuance entropy length", () => {
    const request = {
      ...baseRequest(),
      params: {
        ...baseRequest().params,
        inputs: [
          {
            ...walletInput(),
            issuance: {
              kind: "new",
              asset_amount_sat: 1,
              token_amount_sat: 1,
              entropy: entropy32(5).slice(0, 31),
            },
          },
        ],
      },
    };

    const result = runRustValidator(request);
    expect(result.exitCode).toBe(1);
  });

  it("rejects invalid fee in SDK validation before submit", () => {
    expect(() => {
      new TxCreateRequestBuilder({
        request_id: "integration-invalid-fee",
        network: "testnet-liquid",
        params: new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()).setFeeRateSatVb(-0.1),
      }).build();
    }).toThrow(WalletAbiSdkValidationError);
  });
});
