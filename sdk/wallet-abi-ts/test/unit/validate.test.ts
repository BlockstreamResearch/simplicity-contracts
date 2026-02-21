import { describe, expect, it } from "bun:test";

import {
  WalletAbiSdkValidationError,
  validateNetwork,
  validateRuntimeParams,
  validateTxCreateRequest,
} from "../../src";
import { TEST_SECRET_KEY, baseRequest, baseRuntimeParams, entropy32, providedInput, scriptOutput } from "../fixtures";

function requireValue<T>(value: T | undefined, message: string): T {
  if (value === undefined) {
    throw new Error(message);
  }

  return value;
}

describe("validateNetwork", () => {
  it("accepts supported networks", () => {
    expect(() => {
      validateNetwork("liquid");
    }).not.toThrow();
    expect(() => {
      validateNetwork("testnet-liquid");
    }).not.toThrow();
    expect(() => {
      validateNetwork("localtest-liquid");
    }).not.toThrow();
  });

  it("rejects unsupported networks", () => {
    expect(() => {
      validateNetwork("testnet");
    }).toThrow(WalletAbiSdkValidationError);
  });
});

describe("validateRuntimeParams", () => {
  it("accepts provided outpoint source", () => {
    const runtime = {
      inputs: [providedInput("provided-0")],
      outputs: [scriptOutput("out-0")],
      fee_rate_sat_vb: 0.5,
    };

    expect(() => {
      validateRuntimeParams(runtime);
    }).not.toThrow();
  });

  it("accepts provided blinder variants", () => {
    const runtime = baseRuntimeParams();
    const firstInput = requireValue(runtime.inputs[0], "expected at least one runtime input");
    runtime.inputs[0] = {
      ...firstInput,
      blinder: {
        provided: {
          secret_key: TEST_SECRET_KEY,
        },
      },
    };

    expect(() => {
      validateRuntimeParams(runtime);
    }).not.toThrow();
  });

  it("rejects negative satoshi amounts", () => {
    const runtime = baseRuntimeParams();
    const firstOutput = requireValue(runtime.outputs[0], "expected at least one runtime output");
    runtime.outputs[0] = {
      ...firstOutput,
      amount_sat: -1,
    };

    expect(() => {
      validateRuntimeParams(runtime);
    }).toThrow(WalletAbiSdkValidationError);
  });

  it("rejects invalid issuance entropy", () => {
    const runtime = baseRuntimeParams();
    const firstInput = requireValue(runtime.inputs[0], "expected at least one runtime input");
    runtime.inputs[0] = {
      ...firstInput,
      issuance: {
        kind: "new",
        asset_amount_sat: 1,
        token_amount_sat: 1,
        entropy: entropy32(7).slice(0, 30),
      },
    };

    expect(() => {
      validateRuntimeParams(runtime);
    }).toThrow(WalletAbiSdkValidationError);
  });
});

describe("validateTxCreateRequest", () => {
  it("accepts a valid request", () => {
    expect(() => {
      validateTxCreateRequest(baseRequest());
    }).not.toThrow();
  });

  it("rejects wrong abi version", () => {
    const request = {
      ...baseRequest(),
      abi_version: "wallet-create-0.0",
    };

    expect(() => {
      validateTxCreateRequest(request);
    }).toThrow(WalletAbiSdkValidationError);
  });

  it("rejects request with invalid network", () => {
    const request = {
      ...baseRequest(),
      network: "testnet" as unknown as "testnet-liquid",
    };

    expect(() => {
      validateTxCreateRequest(request);
    }).toThrow(WalletAbiSdkValidationError);
  });
});
