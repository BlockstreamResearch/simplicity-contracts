import { describe, expect, it } from "bun:test";

import {
  RuntimeBuilder,
  TX_CREATE_ABI_VERSION,
  TxCreateRequestBuilder,
  WalletAbiSdkValidationError,
  toWalletRequestJson,
  toWalletRequestObject,
} from "../../src";
import { baseRequest, scriptOutput, simfFinalizer, walletInput } from "../fixtures";

describe("RuntimeBuilder", () => {
  it("builds a valid runtime payload", () => {
    const runtime = new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()).setFeeRateSatVb(0.1).build();

    expect(runtime.inputs).toHaveLength(1);
    expect(runtime.outputs).toHaveLength(1);
    expect(runtime.fee_rate_sat_vb).toBe(0.1);
  });

  it("rejects invalid fee rate", () => {
    expect(() => {
      new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()).setFeeRateSatVb(-1).build();
    }).toThrow(WalletAbiSdkValidationError);
  });

  it("rejects invalid issuance entropy length", () => {
    expect(() => {
      new RuntimeBuilder()
        .addInput({
          ...walletInput(),
          issuance: {
            kind: "new",
            asset_amount_sat: 10,
            token_amount_sat: 1,
            entropy: Array.from({ length: 31 }, () => 1),
          },
        })
        .addOutput(scriptOutput())
        .build();
    }).toThrow(WalletAbiSdkValidationError);
  });

  it("supports simf finalizer shape", () => {
    const runtime = new RuntimeBuilder()
      .addInput({
        ...walletInput(),
        finalizer: simfFinalizer(),
      })
      .addOutput({
        ...scriptOutput("simf-out"),
        lock: {
          type: "finalizer",
          finalizer: {
            type: "wallet",
          },
        },
      })
      .build();

    expect(runtime.inputs[0]?.finalizer.type).toBe("simf");
  });
});

describe("TxCreateRequestBuilder", () => {
  it("builds a wallet request envelope", () => {
    const runtimeBuilder = new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()).setFeeRateSatVb(0.1);

    const request = new TxCreateRequestBuilder({
      abi_version: TX_CREATE_ABI_VERSION,
      request_id: "request-builders-1",
      network: "testnet-liquid",
      broadcast: false,
    })
      .setRuntime(runtimeBuilder)
      .build();

    expect(request.abi_version).toBe(TX_CREATE_ABI_VERSION);
    expect(request.request_id).toBe("request-builders-1");
    expect(request.network).toBe("testnet-liquid");
  });

  it("serializes request JSON", () => {
    const request = baseRequest();
    const json = toWalletRequestJson(request, true);
    const parsed = JSON.parse(json) as unknown;

    expect(typeof parsed).toBe("object");
    expect(parsed).not.toBeNull();
    if (parsed === null || typeof parsed !== "object") {
      throw new Error("Expected request JSON to parse into an object");
    }

    const parsedRequest = parsed as { abi_version: unknown; params: { inputs: unknown[] } };

    expect(parsedRequest.abi_version).toBe(TX_CREATE_ABI_VERSION);
    expect(parsedRequest.params.inputs).toHaveLength(1);
  });

  it("normalizes from builder or object", () => {
    const builder = new TxCreateRequestBuilder({
      request_id: "request-builders-2",
      network: "testnet-liquid",
      params: new RuntimeBuilder().addInput(walletInput()).addOutput(scriptOutput()),
    });

    const built = toWalletRequestObject(builder);
    const objectBuilt = toWalletRequestObject(baseRequest());

    expect(built.request_id).toBe("request-builders-2");
    expect(objectBuilt.request_id).toBe("request-1");
  });
});
