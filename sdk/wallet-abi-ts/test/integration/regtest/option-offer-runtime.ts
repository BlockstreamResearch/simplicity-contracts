import fs from "node:fs";
import path from "node:path";

import * as lwk from "lwk_wasm";

import type { AssetId, FinalizerSpec, InputSchema, ScriptHex, TxCreateRequest } from "../../../src";
import type { SignerInfoResult } from "./harness";

const OPTION_OFFER_SIMF_SOURCE_PATH = path.join(
  "crates",
  "contracts",
  "src",
  "finance",
  "option_offer",
  "source_simf",
  "option_offer.simf",
);
const DEFAULT_NETWORK = "localtest-liquid" as const;
const DEFAULT_SEQUENCE = 0xffff_ffff;
const ENABLE_LOCKTIME_NO_RBF_SEQUENCE = 0xffff_fffe;
const DEFAULT_FEE_RATE_SAT_VB = 0.1;
const PATH_WITNESS_TYPE = "Either<(u64, bool), Either<(), ()>>";
const USER_SIGHASH_WITNESS_NAME = "USER_SIGHASH_ALL";

export interface OptionOfferTerms {
  collateral_per_contract: number;
  premium_per_collateral: number;
  expiry_time: number;
}

export const DEFAULT_OPTION_OFFER_TERMS: OptionOfferTerms = Object.freeze({
  collateral_per_contract: 100,
  premium_per_collateral: 10,
  expiry_time: 1_700_000_000,
});

export interface OptionOfferRuntimeInit {
  repoRoot: string;
  policyAssetId: AssetId;
  premiumAssetId: AssetId;
  settlementAssetId: AssetId;
  signerInfo: SignerInfoResult;
  terms?: Partial<OptionOfferTerms>;
}

export interface BuildDepositRequestInput {
  collateralDepositAmount: number;
  requestId?: string;
  broadcast?: boolean;
}

export interface BuildExerciseRequestInput {
  creationTxId: string;
  collateralAmount: number;
  creationCollateralAmount: number;
  creationPremiumAmount: number;
  requestId?: string;
  broadcast?: boolean;
}

export interface BuildWithdrawRequestInput {
  exerciseTxHex: string;
  exerciseTxId: string;
  requestId?: string;
  broadcast?: boolean;
}

export interface BuildExpiryRequestInput {
  creationTxId: string;
  collateralAmount: number;
  premiumAmount: number;
  requestId?: string;
  broadcast?: boolean;
}

interface OptionOfferRuntimeState {
  sourceSimf: string;
  policyAssetId: AssetId;
  premiumAssetId: AssetId;
  settlementAssetId: AssetId;
  signerScriptHex: ScriptHex;
  signerXOnlyPubkey: string;
  terms: OptionOfferTerms;
  covenantAddress: string;
  covenantScriptHex: ScriptHex;
  internalXOnlyPubkey: string;
  internalPubkey: string;
  simfArgumentsBytes: number[];
}

interface SimfValueEntry {
  value: string;
  type: string;
}

export class OptionOfferRegtestRuntime {
  private readonly state: OptionOfferRuntimeState;

  private constructor(state: OptionOfferRuntimeState) {
    this.state = state;
  }

  static create(init: OptionOfferRuntimeInit): OptionOfferRegtestRuntime {
    const terms = normalizeTerms(init.terms);
    const sourceSimf = fs.readFileSync(path.join(init.repoRoot, OPTION_OFFER_SIMF_SOURCE_PATH), "utf8");
    const { internalXOnlyPubkey, internalPubkey } = deterministicInternalKeypair();

    const argumentsBuilder = buildProgramArguments({
      policyAssetId: init.policyAssetId,
      premiumAssetId: init.premiumAssetId,
      settlementAssetId: init.settlementAssetId,
      terms,
      signerXOnlyPubkey: init.signerInfo.xonly_pubkey,
    });
    const program = new lwk.SimplicityProgram(sourceSimf, argumentsBuilder);
    const covenantAddress = program.createP2trAddress(
      lwk.XOnlyPublicKey.fromHex(internalXOnlyPubkey),
      lwk.Network.regtestDefault(),
    );

    const simfArgumentsBytes = serializeSimfArguments({
      policyAssetId: init.policyAssetId,
      premiumAssetId: init.premiumAssetId,
      settlementAssetId: init.settlementAssetId,
      terms,
      signerXOnlyPubkey: init.signerInfo.xonly_pubkey,
    });

    return new OptionOfferRegtestRuntime({
      sourceSimf,
      policyAssetId: init.policyAssetId,
      premiumAssetId: init.premiumAssetId,
      settlementAssetId: init.settlementAssetId,
      signerScriptHex: init.signerInfo.script_hex,
      signerXOnlyPubkey: init.signerInfo.xonly_pubkey,
      terms,
      covenantAddress: covenantAddress.toString(),
      covenantScriptHex: covenantAddress.scriptPubkey().toString(),
      internalXOnlyPubkey,
      internalPubkey,
      simfArgumentsBytes,
    });
  }

  premiumAmount(collateralAmount: number): number {
    assertSafeUint(collateralAmount, "collateralAmount");
    return checkedMultiply(collateralAmount, this.state.terms.premium_per_collateral, "premium amount");
  }

  settlementAmount(collateralAmount: number): number {
    assertSafeUint(collateralAmount, "collateralAmount");
    return checkedMultiply(collateralAmount, this.state.terms.collateral_per_contract, "settlement amount");
  }

  covenantScriptHex(): ScriptHex {
    return this.state.covenantScriptHex;
  }

  buildDepositRequest(input: BuildDepositRequestInput): TxCreateRequest {
    assertSafeUint(input.collateralDepositAmount, "collateralDepositAmount");
    const premiumDepositAmount = this.premiumAmount(input.collateralDepositAmount);

    return {
      abi_version: "wallet-create-0.1",
      request_id: input.requestId ?? "request-option_offer.deposit.ts",
      network: DEFAULT_NETWORK,
      params: {
        inputs: [walletInput("input0"), walletInput("input1")],
        outputs: [
          explicitScriptOutput({
            id: "out0",
            amountSat: input.collateralDepositAmount,
            scriptHex: this.state.covenantScriptHex,
            assetId: this.state.policyAssetId,
          }),
          explicitScriptOutput({
            id: "out1",
            amountSat: premiumDepositAmount,
            scriptHex: this.state.covenantScriptHex,
            assetId: this.state.premiumAssetId,
          }),
        ],
        fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
      },
      broadcast: input.broadcast ?? true,
    };
  }

  buildExerciseRequest(input: BuildExerciseRequestInput): TxCreateRequest {
    assertSafeUint(input.collateralAmount, "collateralAmount");
    assertSafeUint(input.creationCollateralAmount, "creationCollateralAmount");
    assertSafeUint(input.creationPremiumAmount, "creationPremiumAmount");

    const premiumAmount = this.premiumAmount(input.collateralAmount);
    const settlementAmount = this.settlementAmount(input.collateralAmount);

    if (input.collateralAmount > input.creationCollateralAmount) {
      throw new Error("collateralAmount exceeds creationCollateralAmount");
    }
    if (premiumAmount > input.creationPremiumAmount) {
      throw new Error("requested premium exceeds creationPremiumAmount");
    }

    const collateralChange = input.creationCollateralAmount - input.collateralAmount;
    const premiumChange = input.creationPremiumAmount - premiumAmount;
    const isChangeNeeded = collateralChange !== 0;

    const finalizer = this.buildFinalizer(`Left((${String(input.collateralAmount)}, ${String(isChangeNeeded)}))`);

    const outputs: TxCreateRequest["params"]["outputs"] = [];
    if (isChangeNeeded) {
      outputs.push(
        explicitScriptOutput({
          id: "covenant-collateral-change",
          amountSat: collateralChange,
          scriptHex: this.state.covenantScriptHex,
          assetId: this.state.policyAssetId,
        }),
      );
      outputs.push(
        explicitScriptOutput({
          id: "covenant-premium-change",
          amountSat: premiumChange,
          scriptHex: this.state.covenantScriptHex,
          assetId: this.state.premiumAssetId,
        }),
      );
    }

    outputs.push(
      explicitScriptOutput({
        id: "covenant-settlement-change",
        amountSat: settlementAmount,
        scriptHex: this.state.covenantScriptHex,
        assetId: this.state.settlementAssetId,
      }),
    );
    outputs.push(
      explicitScriptOutput({
        id: "user-collateral-requested",
        amountSat: input.collateralAmount,
        scriptHex: this.state.signerScriptHex,
        assetId: this.state.policyAssetId,
      }),
    );
    outputs.push(
      explicitScriptOutput({
        id: "user-premium-requested",
        amountSat: premiumAmount,
        scriptHex: this.state.signerScriptHex,
        assetId: this.state.premiumAssetId,
      }),
    );

    return {
      abi_version: "wallet-create-0.1",
      request_id: input.requestId ?? "request-option_offer.exercise.ts",
      network: DEFAULT_NETWORK,
      params: {
        inputs: [
          providedInput("input0", `${input.creationTxId}:0`, finalizer),
          providedInput("input1", `${input.creationTxId}:1`, finalizer),
          walletInput("input2"),
        ],
        outputs,
        fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
      },
      broadcast: input.broadcast ?? true,
    };
  }

  buildWithdrawRequest(input: BuildWithdrawRequestInput): TxCreateRequest {
    const settlement = this.findSettlementOutpoint(input.exerciseTxHex, input.exerciseTxId);
    const finalizer = this.buildFinalizer("Right(Left(()))");

    return {
      abi_version: "wallet-create-0.1",
      request_id: input.requestId ?? "request-option_offer.withdraw.ts",
      network: DEFAULT_NETWORK,
      params: {
        inputs: [providedInput("input0", settlement.outpoint, finalizer)],
        outputs: [
          explicitScriptOutput({
            id: "out0",
            amountSat: settlement.amountSat,
            scriptHex: this.state.signerScriptHex,
            assetId: this.state.settlementAssetId,
          }),
        ],
        fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
      },
      broadcast: input.broadcast ?? true,
    };
  }

  buildExpiryRequest(input: BuildExpiryRequestInput): TxCreateRequest {
    assertSafeUint(input.collateralAmount, "collateralAmount");
    assertSafeUint(input.premiumAmount, "premiumAmount");

    const finalizer = this.buildFinalizer("Right(Right(()))");

    return {
      abi_version: "wallet-create-0.1",
      request_id: input.requestId ?? "request-option_offer.expiry.ts",
      network: DEFAULT_NETWORK,
      params: {
        inputs: [
          providedInput("input0", `${input.creationTxId}:0`, finalizer, ENABLE_LOCKTIME_NO_RBF_SEQUENCE),
          providedInput("input1", `${input.creationTxId}:1`, finalizer, ENABLE_LOCKTIME_NO_RBF_SEQUENCE),
        ],
        outputs: [
          explicitScriptOutput({
            id: "out0",
            amountSat: input.collateralAmount,
            scriptHex: this.state.signerScriptHex,
            assetId: this.state.policyAssetId,
          }),
          explicitScriptOutput({
            id: "out1",
            amountSat: input.premiumAmount,
            scriptHex: this.state.signerScriptHex,
            assetId: this.state.premiumAssetId,
          }),
        ],
        fee_rate_sat_vb: DEFAULT_FEE_RATE_SAT_VB,
        locktime: {
          Seconds: this.state.terms.expiry_time,
        },
      },
      broadcast: input.broadcast ?? true,
    };
  }

  private buildFinalizer(pathValue: string): FinalizerSpec {
    const witnessBytes = serializeSimfWitness(pathValue, this.state.signerXOnlyPubkey);

    return {
      type: "simf",
      source_simf: this.state.sourceSimf,
      internal_key: {
        external: {
          key: {
            identity: {
              ExternalXOnly: this.state.internalXOnlyPubkey,
            },
            pubkey: this.state.internalPubkey,
            address: this.state.covenantAddress,
          },
        },
      },
      arguments: [...this.state.simfArgumentsBytes],
      witness: witnessBytes,
    };
  }

  private findSettlementOutpoint(exerciseTxHex: string, exerciseTxId: string): { outpoint: string; amountSat: number } {
    const tx = lwk.Transaction.fromHex(exerciseTxHex);
    const outputs = tx.outputs();

    for (let index = outputs.length - 1; index >= 0; index -= 1) {
      const output = outputs[index];
      if (!output) {
        continue;
      }

      if (output.scriptPubkey().toString() !== this.state.covenantScriptHex) {
        continue;
      }

      const asset = output.asset();
      if (asset?.toString() !== this.state.settlementAssetId) {
        continue;
      }

      const amount = output.value();
      if (amount === undefined) {
        continue;
      }

      if (amount > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("settlement output amount exceeds Number.MAX_SAFE_INTEGER");
      }

      return {
        outpoint: `${exerciseTxId}:${String(index)}`,
        amountSat: Number(amount),
      };
    }

    throw new Error("exercise transaction does not contain explicit settlement output for covenant script");
  }
}

export function createOptionOfferRuntime(init: OptionOfferRuntimeInit): OptionOfferRegtestRuntime {
  return OptionOfferRegtestRuntime.create(init);
}

function normalizeTerms(terms: Partial<OptionOfferTerms> | undefined): OptionOfferTerms {
  const merged = {
    ...DEFAULT_OPTION_OFFER_TERMS,
    ...terms,
  };

  assertSafeUint(merged.collateral_per_contract, "terms.collateral_per_contract");
  assertSafeUint(merged.premium_per_collateral, "terms.premium_per_collateral");
  assertSafeUint(merged.expiry_time, "terms.expiry_time");

  if (merged.collateral_per_contract === 0) {
    throw new Error("terms.collateral_per_contract must be > 0");
  }
  if (merged.premium_per_collateral === 0) {
    throw new Error("terms.premium_per_collateral must be > 0");
  }

  return merged;
}

function deterministicInternalKeypair(): { internalXOnlyPubkey: string; internalPubkey: string } {
  const bytes = new Uint8Array(32);
  bytes[31] = 1;

  const secretKey = lwk.SecretKey.fromBytes(bytes);
  const publicKey = lwk.PublicKey.fromSecretKey(secretKey);

  return {
    internalXOnlyPubkey: publicKey.toXOnly().toHex(),
    internalPubkey: publicKey.toHex(),
  };
}

function buildProgramArguments(input: {
  policyAssetId: AssetId;
  premiumAssetId: AssetId;
  settlementAssetId: AssetId;
  terms: OptionOfferTerms;
  signerXOnlyPubkey: string;
}): lwk.SimplicityArguments {
  let argumentsBuilder = new lwk.SimplicityArguments();

  argumentsBuilder = argumentsBuilder.addValue(
    "COLLATERAL_ASSET_ID",
    lwk.SimplicityTypedValue.fromU256Hex(assetInnerHex(input.policyAssetId)),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "PREMIUM_ASSET_ID",
    lwk.SimplicityTypedValue.fromU256Hex(assetInnerHex(input.premiumAssetId)),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "SETTLEMENT_ASSET_ID",
    lwk.SimplicityTypedValue.fromU256Hex(assetInnerHex(input.settlementAssetId)),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "COLLATERAL_PER_CONTRACT",
    lwk.SimplicityTypedValue.fromU64(BigInt(input.terms.collateral_per_contract)),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "PREMIUM_PER_COLLATERAL",
    lwk.SimplicityTypedValue.fromU64(BigInt(input.terms.premium_per_collateral)),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "EXPIRY_TIME",
    lwk.SimplicityTypedValue.fromU32(input.terms.expiry_time),
  );
  argumentsBuilder = argumentsBuilder.addValue(
    "USER_PUBKEY",
    lwk.SimplicityTypedValue.fromU256Hex(input.signerXOnlyPubkey),
  );

  return argumentsBuilder;
}

function serializeSimfArguments(input: {
  policyAssetId: AssetId;
  premiumAssetId: AssetId;
  settlementAssetId: AssetId;
  terms: OptionOfferTerms;
  signerXOnlyPubkey: string;
}): number[] {
  const resolved: Record<string, SimfValueEntry> = {
    COLLATERAL_ASSET_ID: {
      value: `0x${assetInnerHex(input.policyAssetId)}`,
      type: "u256",
    },
    PREMIUM_ASSET_ID: {
      value: `0x${assetInnerHex(input.premiumAssetId)}`,
      type: "u256",
    },
    SETTLEMENT_ASSET_ID: {
      value: `0x${assetInnerHex(input.settlementAssetId)}`,
      type: "u256",
    },
    COLLATERAL_PER_CONTRACT: {
      value: String(input.terms.collateral_per_contract),
      type: "u64",
    },
    PREMIUM_PER_COLLATERAL: {
      value: String(input.terms.premium_per_collateral),
      type: "u64",
    },
    EXPIRY_TIME: {
      value: String(input.terms.expiry_time),
      type: "u32",
    },
    USER_PUBKEY: {
      value: `0x${input.signerXOnlyPubkey}`,
      type: "u256",
    },
  };

  return encodeJsonUtf8Bytes({
    resolved,
    runtime_arguments: {},
  });
}

function serializeSimfWitness(pathValue: string, signerXOnlyPubkey: string): number[] {
  return encodeJsonUtf8Bytes({
    resolved: {
      PATH: {
        value: pathValue,
        type: PATH_WITNESS_TYPE,
      },
    },
    runtime_arguments: [
      {
        sig_hash_all: {
          name: USER_SIGHASH_WITNESS_NAME,
          public_key: signerXOnlyPubkey,
        },
      },
    ],
  });
}

function assetInnerHex(assetId: AssetId): string {
  return new lwk.AssetId(assetId).innerHex();
}

function encodeJsonUtf8Bytes(value: unknown): number[] {
  return Array.from(new TextEncoder().encode(JSON.stringify(value)));
}

function walletInput(id: string): InputSchema {
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
    sequence: DEFAULT_SEQUENCE,
    finalizer: {
      type: "wallet",
    },
  };
}

function providedInput(
  id: string,
  outpoint: string,
  finalizer: FinalizerSpec,
  sequence = DEFAULT_SEQUENCE,
): InputSchema {
  return {
    id,
    utxo_source: {
      provided: {
        outpoint,
      },
    },
    blinder: "explicit",
    sequence,
    finalizer,
  };
}

function explicitScriptOutput(input: {
  id: string;
  amountSat: number;
  scriptHex: ScriptHex;
  assetId: AssetId;
}): TxCreateRequest["params"]["outputs"][number] {
  assertSafeUint(input.amountSat, `${input.id}.amountSat`);

  return {
    id: input.id,
    amount_sat: input.amountSat,
    lock: {
      type: "script",
      script: input.scriptHex,
    },
    asset: {
      type: "asset_id",
      asset_id: input.assetId,
    },
    blinder: "explicit",
  };
}

function checkedMultiply(left: number, right: number, context: string): number {
  const result = left * right;
  if (!Number.isSafeInteger(result)) {
    throw new Error(`${context} overflow`);
  }
  return result;
}

function assertSafeUint(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
}
