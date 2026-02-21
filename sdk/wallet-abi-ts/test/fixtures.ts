import type { FinalizerSpec, InputSchema, Network, OutputSchema, RuntimeParams, TxCreateRequest } from "../src";
import { TX_CREATE_ABI_VERSION } from "../src";

export const TESTNET_POLICY_ASSET = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

export const TEST_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

export const TEST_SECRET_KEY = "1111111111111111111111111111111111111111111111111111111111111111";

export function entropy32(seed = 1): number[] {
  return Array.from({ length: 32 }, (_, index) => (seed + index) % 256);
}

export function walletInput(id = "input0"): InputSchema {
  return {
    id,
    utxo_source: {
      wallet: {
        filter: {
          asset: "none",
          amount: "none",
          lock: "none",
        },
      },
    },
    blinder: "wallet",
    sequence: 0xffff_ffff,
    finalizer: {
      type: "wallet",
    },
  };
}

export function providedInput(id = "input0"): InputSchema {
  return {
    id,
    utxo_source: {
      provided: {
        outpoint: "0000000000000000000000000000000000000000000000000000000000000001:0",
      },
    },
    blinder: "wallet",
    sequence: 0xffff_ffff,
    finalizer: {
      type: "wallet",
    },
  };
}

export function scriptOutput(id = "out0", amountSat = 1): OutputSchema {
  return {
    id,
    amount_sat: amountSat,
    lock: {
      type: "script",
      script: "51",
    },
    asset: {
      type: "asset_id",
      asset_id: TESTNET_POLICY_ASSET,
    },
    blinder: "explicit",
  };
}

export function simfFinalizer(): FinalizerSpec {
  return {
    type: "simf",
    source_simf: "main := unit",
    internal_key: {
      local: {
        key: TEST_PUBKEY,
      },
    },
    arguments: [1, 2, 3],
    witness: [4, 5, 6],
  };
}

export function baseRuntimeParams(): RuntimeParams {
  return {
    inputs: [walletInput()],
    outputs: [scriptOutput()],
    fee_rate_sat_vb: 0.1,
  };
}

export function baseRequest(network: Network = "testnet-liquid"): TxCreateRequest {
  return {
    abi_version: TX_CREATE_ABI_VERSION,
    request_id: "request-1",
    network,
    params: baseRuntimeParams(),
    broadcast: false,
  };
}
