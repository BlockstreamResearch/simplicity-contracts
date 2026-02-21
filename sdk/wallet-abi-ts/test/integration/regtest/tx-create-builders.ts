import { TX_CREATE_ABI_VERSION } from "../../../src";
import type { AssetId, ScriptHex, TxCreateRequest } from "../../../src";

const DEFAULT_NETWORK = "localtest-liquid" as const;
const DEFAULT_SEQUENCE = 0xffff_ffff;
const DEFAULT_FEE_RATE_SAT_VB = 0.1;

interface BaseRequestInput {
  requestId: string;
  broadcast: boolean;
}

interface WalletScriptOutput {
  id: string;
  amountSat: number;
  scriptHex: ScriptHex;
  assetId: AssetId;
}

function baseRequest({ requestId, broadcast }: BaseRequestInput): TxCreateRequest {
  return {
    abi_version: TX_CREATE_ABI_VERSION,
    request_id: requestId,
    network: DEFAULT_NETWORK,
    params: {
      inputs: [],
      outputs: [],
      fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
    },
    broadcast,
  };
}

function walletInputExactAsset(assetId: AssetId, id = "input0"): TxCreateRequest["params"]["inputs"][number] {
  return {
    id,
    utxo_source: {
      wallet: {
        filter: {
          asset: {
            exact: {
              asset_id: assetId,
            },
          },
          amount: "none",
          lock: "none",
        },
      },
    },
    blinder: "wallet",
    sequence: DEFAULT_SEQUENCE,
    finalizer: {
      type: "wallet",
    },
  };
}

function walletScriptOutput({
  id,
  amountSat,
  scriptHex,
  assetId,
}: WalletScriptOutput): TxCreateRequest["params"]["outputs"][number] {
  return {
    id,
    amount_sat: amountSat,
    lock: {
      type: "script",
      script: scriptHex,
    },
    asset: {
      type: "asset_id",
      asset_id: assetId,
    },
    blinder: "wallet",
  };
}

export function createTransferRequest(input: {
  requestId: string;
  broadcast: boolean;
  policyAssetId: AssetId;
  signerScriptHex: ScriptHex;
  amountSat: number;
}): TxCreateRequest {
  const request = baseRequest({
    requestId: input.requestId,
    broadcast: input.broadcast,
  });

  request.params.inputs.push(walletInputExactAsset(input.policyAssetId));
  request.params.outputs.push(
    walletScriptOutput({
      id: "to-signer",
      amountSat: input.amountSat,
      scriptHex: input.signerScriptHex,
      assetId: input.policyAssetId,
    }),
  );

  return request;
}

export function createSplitRequest(input: {
  requestId: string;
  broadcast: boolean;
  policyAssetId: AssetId;
  signerScriptHex: ScriptHex;
  splitParts: number;
  partAmountSat: number;
}): TxCreateRequest {
  const request = baseRequest({
    requestId: input.requestId,
    broadcast: input.broadcast,
  });

  request.params.inputs.push(walletInputExactAsset(input.policyAssetId));
  for (let index = 0; index < input.splitParts; index += 1) {
    request.params.outputs.push(
      walletScriptOutput({
        id: `out${String(index)}`,
        amountSat: input.partAmountSat,
        scriptHex: input.signerScriptHex,
        assetId: input.policyAssetId,
      }),
    );
  }

  return request;
}

export function createIssueAssetRequest(input: {
  requestId: string;
  broadcast: boolean;
  policyAssetId: AssetId;
  signerScriptHex: ScriptHex;
  issueAmountSat: number;
  issuanceEntropy: number[];
}): TxCreateRequest {
  const request = baseRequest({
    requestId: input.requestId,
    broadcast: input.broadcast,
  });

  request.params.inputs.push({
    ...walletInputExactAsset(input.policyAssetId, "input0"),
    issuance: {
      kind: "new",
      asset_amount_sat: input.issueAmountSat,
      token_amount_sat: 1,
      entropy: input.issuanceEntropy,
    },
  });

  request.params.outputs.push({
    id: "token-output",
    amount_sat: 1,
    lock: {
      type: "script",
      script: input.signerScriptHex,
    },
    asset: {
      type: "new_issuance_token",
      input_index: 0,
    },
    blinder: "wallet",
  });

  request.params.outputs.push({
    id: "asset-output",
    amount_sat: input.issueAmountSat,
    lock: {
      type: "script",
      script: input.signerScriptHex,
    },
    asset: {
      type: "new_issuance_asset",
      input_index: 0,
    },
    blinder: "wallet",
  });

  return request;
}

export function createReissueAssetRequest(input: {
  requestId: string;
  broadcast: boolean;
  signerScriptHex: ScriptHex;
  reissueTokenAssetId: AssetId;
  reissueAmountSat: number;
  assetEntropy: number[];
}): TxCreateRequest {
  const request = baseRequest({
    requestId: input.requestId,
    broadcast: input.broadcast,
  });

  request.params.inputs.push({
    id: "input0",
    utxo_source: {
      wallet: {
        filter: {
          asset: {
            exact: {
              asset_id: input.reissueTokenAssetId,
            },
          },
          amount: {
            min: {
              satoshi: 1,
            },
          },
          lock: "none",
        },
      },
    },
    blinder: "wallet",
    sequence: DEFAULT_SEQUENCE,
    issuance: {
      kind: "reissue",
      asset_amount_sat: input.reissueAmountSat,
      token_amount_sat: 0,
      entropy: input.assetEntropy,
    },
    finalizer: {
      type: "wallet",
    },
  });

  request.params.outputs.push({
    id: "token-change",
    amount_sat: 1,
    lock: {
      type: "script",
      script: input.signerScriptHex,
    },
    asset: {
      type: "asset_id",
      asset_id: input.reissueTokenAssetId,
    },
    blinder: "wallet",
  });

  request.params.outputs.push({
    id: "reissued-asset",
    amount_sat: input.reissueAmountSat,
    lock: {
      type: "script",
      script: input.signerScriptHex,
    },
    asset: {
      type: "re_issuance_asset",
      input_index: 0,
    },
    blinder: "wallet",
  });

  return request;
}
