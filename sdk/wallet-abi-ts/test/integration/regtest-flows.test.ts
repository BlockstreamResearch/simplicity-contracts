import { afterAll, describe, expect, it } from "bun:test";
import path from "node:path";

import type { TxCreateResponse } from "../../src";
import { RegtestHarness } from "./regtest/harness";
import type { InitResult, IssuanceInfoResult } from "./regtest/harness";
import { createOptionOfferRuntime, type OptionOfferRegtestRuntime } from "./regtest/option-offer-runtime";
import {
  createIssueAssetRequest,
  createReissueAssetRequest,
  createSplitRequest,
  createTransferRequest,
} from "./regtest/tx-create-builders";

const repoRoot = path.resolve(import.meta.dir, "../../../../");

const hasRegtestEnv = Boolean(process.env.ELEMENTSD_EXEC && process.env.ELECTRS_LIQUID_EXEC);
const regtestIt = hasRegtestEnv ? it : it.skip;
const FLOW_TIMEOUT_MS = 15 * 60 * 1000;
const OPTION_OFFER_COLLATERAL_DEPOSIT_SAT = 1_000;
const OPTION_OFFER_PARTIAL_EXERCISE_COLLATERAL_SAT = 500;
const OPTION_OFFER_PREMIUM_ASSET_FUND_SAT = 250_000;
const OPTION_OFFER_SETTLEMENT_ASSET_FUND_SAT = 250_000;

let harness: RegtestHarness | undefined;
let init: InitResult | undefined;
let issuanceInfo: IssuanceInfoResult | undefined;

let flowQueue: Promise<void> = Promise.resolve();

function entropy32(seed = 1): number[] {
  return Array.from({ length: 32 }, (_, index) => (seed + index) % 256);
}

function assertBroadcastOk(
  response: TxCreateResponse,
  label: string,
): asserts response is TxCreateResponse & {
  transaction: NonNullable<TxCreateResponse["transaction"]>;
} {
  expect(response.status, `${label} should succeed`).toBe("ok");
  expect(response.transaction, `${label} should include transaction info`).toBeDefined();
}

function runSequentialFlow<T>(flow: () => Promise<T>): Promise<T> {
  const run = flowQueue.then(flow);
  flowQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

async function ensureHarnessReady(): Promise<{ harness: RegtestHarness; init: InitResult }> {
  harness ??= RegtestHarness.start(repoRoot);

  if (!init) {
    init = await harness.init();
    await harness.fundLbtc(8_000_000);
  }

  return { harness, init };
}

async function ensureIssueFlow(): Promise<IssuanceInfoResult> {
  if (issuanceInfo) {
    return issuanceInfo;
  }

  const { harness, init } = await ensureHarnessReady();
  const issuanceEntropy = entropy32(17);
  const issueRequest = createIssueAssetRequest({
    requestId: "request-basic.issue.ts",
    broadcast: true,
    policyAssetId: init.policy_asset_id,
    signerScriptHex: init.signer_script_hex,
    issueAmountSat: 5_000,
    issuanceEntropy,
  });
  const issueResponse = await harness.processTxCreate(issueRequest);
  assertBroadcastOk(issueResponse, "basic.issue");
  await harness.mineBlocks(1);

  issuanceInfo = await harness.extractIssuanceInfo(issueResponse.transaction.tx_hex, issuanceEntropy);

  return issuanceInfo;
}

interface OptionOfferFixture {
  harness: RegtestHarness;
  init: InitResult;
  runtime: OptionOfferRegtestRuntime;
}

async function createOptionOfferFixture(): Promise<OptionOfferFixture> {
  const ready = await ensureHarnessReady();
  const signerInfo = await ready.harness.signerInfo();
  const premiumFunding = await ready.harness.issueAndFundAsset(OPTION_OFFER_PREMIUM_ASSET_FUND_SAT);
  const settlementFunding = await ready.harness.issueAndFundAsset(OPTION_OFFER_SETTLEMENT_ASSET_FUND_SAT);

  const runtime = createOptionOfferRuntime({
    repoRoot,
    policyAssetId: ready.init.policy_asset_id,
    premiumAssetId: premiumFunding.asset_id,
    settlementAssetId: settlementFunding.asset_id,
    signerInfo,
  });

  return {
    harness: ready.harness,
    init: ready.init,
    runtime,
  };
}

describe("Regtest typed TxCreateRequest flows", () => {
  regtestIt(
    "bootstraps regtest harness",
    async () => {
      await runSequentialFlow(async () => {
        const { init } = await ensureHarnessReady();
        expect(init.network).toBe("localtest-liquid");
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs basic.transfer flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, init } = await ensureHarnessReady();
        const transferRequest = createTransferRequest({
          requestId: "request-basic.transfer.ts",
          broadcast: true,
          policyAssetId: init.policy_asset_id,
          signerScriptHex: init.signer_script_hex,
          amountSat: 2_000,
        });
        const transferResponse = await harness.processTxCreate(transferRequest);
        assertBroadcastOk(transferResponse, "basic.transfer");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs basic.split flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, init } = await ensureHarnessReady();
        const splitRequest = createSplitRequest({
          requestId: "request-basic.split.ts",
          broadcast: true,
          policyAssetId: init.policy_asset_id,
          signerScriptHex: init.signer_script_hex,
          splitParts: 2,
          partAmountSat: 1_000,
        });
        const splitResponse = await harness.processTxCreate(splitRequest);
        assertBroadcastOk(splitResponse, "basic.split");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs basic.issue flow",
    async () => {
      await runSequentialFlow(async () => {
        const issueInfo = await ensureIssueFlow();
        expect(issueInfo.reissuance_token_asset_id.length).toBeGreaterThan(0);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs basic.reissue flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, init } = await ensureHarnessReady();
        const issueInfo = await ensureIssueFlow();

        const reissueRequest = createReissueAssetRequest({
          requestId: "request-basic.reissue.ts",
          broadcast: true,
          signerScriptHex: init.signer_script_hex,
          reissueTokenAssetId: issueInfo.reissuance_token_asset_id,
          reissueAmountSat: 3_000,
          assetEntropy: issueInfo.asset_entropy,
        });
        const reissueResponse = await harness.processTxCreate(reissueRequest);
        assertBroadcastOk(reissueResponse, "basic.reissue");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs option_offer.deposit flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, runtime } = await createOptionOfferFixture();
        const depositRequest = runtime.buildDepositRequest({
          requestId: "request-option_offer.deposit.ts",
          broadcast: true,
          collateralDepositAmount: OPTION_OFFER_COLLATERAL_DEPOSIT_SAT,
        });
        const depositResponse = await harness.processTxCreate(depositRequest);
        assertBroadcastOk(depositResponse, "option_offer.deposit");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs option_offer.exercise flow (full)",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, runtime } = await createOptionOfferFixture();
        const creationCollateralAmount = OPTION_OFFER_COLLATERAL_DEPOSIT_SAT;
        const creationPremiumAmount = runtime.premiumAmount(creationCollateralAmount);

        const depositRequest = runtime.buildDepositRequest({
          requestId: "request-option_offer.exercise.full.deposit.ts",
          broadcast: true,
          collateralDepositAmount: creationCollateralAmount,
        });
        const depositResponse = await harness.processTxCreate(depositRequest);
        assertBroadcastOk(depositResponse, "option_offer.exercise.full.deposit");
        await harness.mineBlocks(1);

        const exerciseRequest = runtime.buildExerciseRequest({
          requestId: "request-option_offer.exercise.full.ts",
          broadcast: true,
          creationTxId: depositResponse.transaction.txid,
          collateralAmount: creationCollateralAmount,
          creationCollateralAmount,
          creationPremiumAmount,
        });
        const exerciseResponse = await harness.processTxCreate(exerciseRequest);
        assertBroadcastOk(exerciseResponse, "option_offer.exercise.full");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs option_offer.exercise flow (with change)",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, runtime } = await createOptionOfferFixture();
        const creationCollateralAmount = OPTION_OFFER_COLLATERAL_DEPOSIT_SAT;
        const creationPremiumAmount = runtime.premiumAmount(creationCollateralAmount);

        const depositRequest = runtime.buildDepositRequest({
          requestId: "request-option_offer.exercise.change.deposit.ts",
          broadcast: true,
          collateralDepositAmount: creationCollateralAmount,
        });
        const depositResponse = await harness.processTxCreate(depositRequest);
        assertBroadcastOk(depositResponse, "option_offer.exercise.change.deposit");
        await harness.mineBlocks(1);

        const exerciseRequest = runtime.buildExerciseRequest({
          requestId: "request-option_offer.exercise.change.ts",
          broadcast: true,
          creationTxId: depositResponse.transaction.txid,
          collateralAmount: OPTION_OFFER_PARTIAL_EXERCISE_COLLATERAL_SAT,
          creationCollateralAmount,
          creationPremiumAmount,
        });
        const exerciseResponse = await harness.processTxCreate(exerciseRequest);
        assertBroadcastOk(exerciseResponse, "option_offer.exercise.change");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs option_offer.withdraw flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, runtime } = await createOptionOfferFixture();
        const creationCollateralAmount = OPTION_OFFER_COLLATERAL_DEPOSIT_SAT;
        const creationPremiumAmount = runtime.premiumAmount(creationCollateralAmount);
        const expectedSettlementAmount = runtime.settlementAmount(OPTION_OFFER_PARTIAL_EXERCISE_COLLATERAL_SAT);

        const depositRequest = runtime.buildDepositRequest({
          requestId: "request-option_offer.withdraw.deposit.ts",
          broadcast: true,
          collateralDepositAmount: creationCollateralAmount,
        });
        const depositResponse = await harness.processTxCreate(depositRequest);
        assertBroadcastOk(depositResponse, "option_offer.withdraw.deposit");
        await harness.mineBlocks(1);

        const exerciseRequest = runtime.buildExerciseRequest({
          requestId: "request-option_offer.withdraw.exercise.ts",
          broadcast: true,
          creationTxId: depositResponse.transaction.txid,
          collateralAmount: OPTION_OFFER_PARTIAL_EXERCISE_COLLATERAL_SAT,
          creationCollateralAmount,
          creationPremiumAmount,
        });
        const exerciseResponse = await harness.processTxCreate(exerciseRequest);
        assertBroadcastOk(exerciseResponse, "option_offer.withdraw.exercise");
        await harness.mineBlocks(1);

        const withdrawRequest = runtime.buildWithdrawRequest({
          requestId: "request-option_offer.withdraw.ts",
          broadcast: true,
          exerciseTxHex: exerciseResponse.transaction.tx_hex,
          exerciseTxId: exerciseResponse.transaction.txid,
        });

        const withdrawInput = withdrawRequest.params.inputs[0];
        if (!withdrawInput || !("provided" in withdrawInput.utxo_source)) {
          throw new Error("option_offer.withdraw should use provided covenant settlement outpoint");
        }
        expect(withdrawInput.utxo_source.provided.outpoint.startsWith(`${exerciseResponse.transaction.txid}:`)).toBe(
          true,
        );

        const withdrawOutput = withdrawRequest.params.outputs[0];
        if (!withdrawOutput) {
          throw new Error("option_offer.withdraw request must include settlement transfer output");
        }
        expect(withdrawOutput.amount_sat).toBe(expectedSettlementAmount);

        const withdrawResponse = await harness.processTxCreate(withdrawRequest);
        assertBroadcastOk(withdrawResponse, "option_offer.withdraw");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );

  regtestIt(
    "runs option_offer.expiry flow",
    async () => {
      await runSequentialFlow(async () => {
        const { harness, runtime } = await createOptionOfferFixture();
        const creationCollateralAmount = OPTION_OFFER_COLLATERAL_DEPOSIT_SAT;
        const creationPremiumAmount = runtime.premiumAmount(creationCollateralAmount);

        const depositRequest = runtime.buildDepositRequest({
          requestId: "request-option_offer.expiry.deposit.ts",
          broadcast: true,
          collateralDepositAmount: creationCollateralAmount,
        });
        const depositResponse = await harness.processTxCreate(depositRequest);
        assertBroadcastOk(depositResponse, "option_offer.expiry.deposit");
        await harness.mineBlocks(1);

        const expiryRequest = runtime.buildExpiryRequest({
          requestId: "request-option_offer.expiry.ts",
          broadcast: true,
          creationTxId: depositResponse.transaction.txid,
          collateralAmount: creationCollateralAmount,
          premiumAmount: creationPremiumAmount,
        });
        expect(expiryRequest.params.locktime).toEqual({ Seconds: 1_700_000_000 });

        const expiryResponse = await harness.processTxCreate(expiryRequest);
        assertBroadcastOk(expiryResponse, "option_offer.expiry");
        await harness.mineBlocks(1);
      });
    },
    FLOW_TIMEOUT_MS,
  );
});

afterAll(async () => {
  if (harness) {
    await harness.close();
  }
});
