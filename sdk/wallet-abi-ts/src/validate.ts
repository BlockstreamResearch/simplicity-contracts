import { SUPPORTED_NETWORKS, TX_CREATE_ABI_VERSION } from "./constants";
import { WalletAbiSdkValidationError } from "./errors";
import type {
  AmountFilter,
  AssetFilter,
  AssetVariant,
  BlinderVariant,
  FinalizerSpec,
  InputBlinder,
  InputSchema,
  InputIssuance,
  InternalKeySource,
  LockFilter,
  LockTime,
  LockVariant,
  Network,
  OutputSchema,
  RuntimeParams,
  TxCreateRequest,
  UTXOSource,
} from "./types";

const MAX_U32 = 0xffff_ffff;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new WalletAbiSdkValidationError(message);
  }
}

function assertNonEmptyString(value: unknown, field: string): asserts value is string {
  assert(isString(value), `${field} must be a string`);
  assert(value.trim().length > 0, `${field} must not be empty`);
}

function assertBoolean(value: unknown, field: string): asserts value is boolean {
  assert(typeof value === "boolean", `${field} must be a boolean`);
}

function assertSafeUint(value: unknown, field: string, max = Number.MAX_SAFE_INTEGER): asserts value is number {
  assert(typeof value === "number", `${field} must be a number`);
  assert(Number.isFinite(value), `${field} must be finite`);
  assert(Number.isInteger(value), `${field} must be an integer`);
  assert(value >= 0, `${field} must be non-negative`);
  assert(value <= max, `${field} must be <= ${String(max)}`);
}

function assertByteArray(value: unknown, field: string): asserts value is number[] {
  assert(Array.isArray(value), `${field} must be an array of bytes`);
  for (let index = 0; index < value.length; index += 1) {
    assertSafeUint(value[index], `${field}[${String(index)}]`, 255);
  }
}

function assertEntropy32(entropy: unknown, field: string): asserts entropy is number[] {
  assertByteArray(entropy, field);
  assert(entropy.length === 32, `${field} must contain exactly 32 bytes`);
}

function assertLockTime(locktime: unknown, field: string): asserts locktime is LockTime {
  assert(isRecord(locktime), `${field} must be an object`);

  const hasBlocks = Object.prototype.hasOwnProperty.call(locktime, "Blocks");
  const hasSeconds = Object.prototype.hasOwnProperty.call(locktime, "Seconds");

  assert(hasBlocks !== hasSeconds, `${field} must have exactly one of Blocks or Seconds`);

  if (hasBlocks) {
    assertSafeUint((locktime as { Blocks: unknown }).Blocks, `${field}.Blocks`, MAX_U32);
  }

  if (hasSeconds) {
    assertSafeUint((locktime as { Seconds: unknown }).Seconds, `${field}.Seconds`, MAX_U32);
  }
}

export function validateNetwork(network: unknown): asserts network is Network {
  assertNonEmptyString(network, "network");
  assert(
    (SUPPORTED_NETWORKS as readonly string[]).includes(network),
    `network must be one of: ${SUPPORTED_NETWORKS.join(", ")}`,
  );
}

function validateAssetFilter(assetFilter: unknown, field: string): asserts assetFilter is AssetFilter {
  if (assetFilter === "none") {
    return;
  }

  assert(isRecord(assetFilter), `${field} must be "none" or an object variant`);
  const exact = assetFilter.exact;
  assert(isRecord(exact), `${field}.exact must be an object`);
  assertNonEmptyString(exact.asset_id, `${field}.exact.asset_id`);
}

function validateAmountFilter(amountFilter: unknown, field: string): asserts amountFilter is AmountFilter {
  if (amountFilter === "none") {
    return;
  }

  assert(isRecord(amountFilter), `${field} must be "none" or an object variant`);

  if ("exact" in amountFilter) {
    assert(isRecord(amountFilter.exact), `${field}.exact must be an object`);
    assertSafeUint(amountFilter.exact.satoshi, `${field}.exact.satoshi`);
    return;
  }

  if ("min" in amountFilter) {
    assert(isRecord(amountFilter.min), `${field}.min must be an object`);
    assertSafeUint(amountFilter.min.satoshi, `${field}.min.satoshi`);
    return;
  }

  throw new WalletAbiSdkValidationError(`${field} must be "none", "exact", or "min"`);
}

function validateLockFilter(lockFilter: unknown, field: string): asserts lockFilter is LockFilter {
  if (lockFilter === "none") {
    return;
  }

  assert(isRecord(lockFilter), `${field} must be "none" or an object variant`);
  assert(isRecord(lockFilter.script), `${field}.script must be an object`);
  assert(isString(lockFilter.script.script), `${field}.script.script must be a string`);
}

function validateUtxoSource(utxoSource: unknown, field: string): asserts utxoSource is UTXOSource {
  assert(isRecord(utxoSource), `${field} must be an object`);

  if ("wallet" in utxoSource) {
    assert(isRecord(utxoSource.wallet), `${field}.wallet must be an object`);
    assert(isRecord(utxoSource.wallet.filter), `${field}.wallet.filter must be an object`);

    validateAssetFilter(utxoSource.wallet.filter.asset, `${field}.wallet.filter.asset`);
    validateAmountFilter(utxoSource.wallet.filter.amount, `${field}.wallet.filter.amount`);
    validateLockFilter(utxoSource.wallet.filter.lock, `${field}.wallet.filter.lock`);
    return;
  }

  if ("provided" in utxoSource) {
    assert(isRecord(utxoSource.provided), `${field}.provided must be an object`);
    assertNonEmptyString(utxoSource.provided.outpoint, `${field}.provided.outpoint`);
    return;
  }

  throw new WalletAbiSdkValidationError(`${field} must be either wallet or provided`);
}

function validateInputIssuance(issuance: unknown, field: string): asserts issuance is InputIssuance {
  assert(isRecord(issuance), `${field} must be an object`);
  assert(issuance.kind === "new" || issuance.kind === "reissue", `${field}.kind must be "new" or "reissue"`);
  assertSafeUint(issuance.asset_amount_sat, `${field}.asset_amount_sat`);
  assertSafeUint(issuance.token_amount_sat, `${field}.token_amount_sat`);
  assertEntropy32(issuance.entropy, `${field}.entropy`);
}

function validateInternalKeySource(source: unknown, field: string): asserts source is InternalKeySource {
  assert(isRecord(source), `${field} must be an object`);

  if ("local" in source) {
    assert(isRecord(source.local), `${field}.local must be an object`);
    assertNonEmptyString(source.local.key, `${field}.local.key`);
    return;
  }

  if ("external" in source) {
    assert(isRecord(source.external), `${field}.external must be an object`);
    assert(isRecord(source.external.key), `${field}.external.key must be an object`);

    const taproot = source.external.key;
    assert(isRecord(taproot.identity), `${field}.external.key.identity must be an object`);
    assertNonEmptyString(taproot.pubkey, `${field}.external.key.pubkey`);
    assertNonEmptyString(taproot.address, `${field}.external.key.address`);

    if ("Seed" in taproot.identity) {
      assertByteArray(taproot.identity.Seed, `${field}.external.key.identity.Seed`);
      return;
    }

    if ("ExternalXOnly" in taproot.identity) {
      assertNonEmptyString(taproot.identity.ExternalXOnly, `${field}.external.key.identity.ExternalXOnly`);
      return;
    }

    throw new WalletAbiSdkValidationError(`${field}.external.key.identity must contain Seed or ExternalXOnly`);
  }

  throw new WalletAbiSdkValidationError(`${field} must be either local or external`);
}

function validateFinalizerSpec(finalizer: unknown, field: string): asserts finalizer is FinalizerSpec {
  assert(isRecord(finalizer), `${field} must be an object`);
  assertNonEmptyString(finalizer.type, `${field}.type`);

  if (finalizer.type === "wallet") {
    return;
  }

  if (finalizer.type === "simf") {
    assertNonEmptyString(finalizer.source_simf, `${field}.source_simf`);
    validateInternalKeySource(finalizer.internal_key, `${field}.internal_key`);
    assertByteArray(finalizer.arguments, `${field}.arguments`);
    assertByteArray(finalizer.witness, `${field}.witness`);
    return;
  }

  throw new WalletAbiSdkValidationError(`${field}.type must be "wallet" or "simf"`);
}

function validateInputBlinder(blinder: unknown, field: string): asserts blinder is InputBlinder {
  if (blinder === "wallet" || blinder === "explicit") {
    return;
  }

  assert(isRecord(blinder), `${field} must be a supported blinder variant`);
  assert(isRecord(blinder.provided), `${field}.provided must be an object`);
  assertNonEmptyString(blinder.provided.secret_key, `${field}.provided.secret_key`);
}

function validateLockVariant(lock: unknown, field: string): asserts lock is LockVariant {
  assert(isRecord(lock), `${field} must be an object`);
  assertNonEmptyString(lock.type, `${field}.type`);

  if (lock.type === "script") {
    assert(isString(lock.script), `${field}.script must be a string`);
    return;
  }

  if (lock.type === "finalizer") {
    validateFinalizerSpec(lock.finalizer, `${field}.finalizer`);
    return;
  }

  throw new WalletAbiSdkValidationError(`${field}.type must be "script" or "finalizer"`);
}

function validateAssetVariant(asset: unknown, field: string): asserts asset is AssetVariant {
  assert(isRecord(asset), `${field} must be an object`);
  assertNonEmptyString(asset.type, `${field}.type`);

  if (asset.type === "asset_id") {
    assertNonEmptyString(asset.asset_id, `${field}.asset_id`);
    return;
  }

  if (
    asset.type === "new_issuance_asset" ||
    asset.type === "new_issuance_token" ||
    asset.type === "re_issuance_asset"
  ) {
    assertSafeUint(asset.input_index, `${field}.input_index`, MAX_U32);
    return;
  }

  throw new WalletAbiSdkValidationError(
    `${field}.type must be one of asset_id, new_issuance_asset, new_issuance_token, re_issuance_asset`,
  );
}

function validateOutputBlinder(blinder: unknown, field: string): asserts blinder is BlinderVariant {
  if (blinder === "wallet" || blinder === "explicit") {
    return;
  }

  assert(isRecord(blinder), `${field} must be a supported blinder variant`);
  assert(isRecord(blinder.provided), `${field}.provided must be an object`);
  assertNonEmptyString(blinder.provided.pubkey, `${field}.provided.pubkey`);
}

function validateInputSchema(input: unknown, field: string): asserts input is InputSchema {
  assert(isRecord(input), `${field} must be an object`);
  assertNonEmptyString(input.id, `${field}.id`);
  validateUtxoSource(input.utxo_source, `${field}.utxo_source`);
  validateInputBlinder(input.blinder, `${field}.blinder`);
  assertSafeUint(input.sequence, `${field}.sequence`, MAX_U32);

  if (input.issuance !== undefined) {
    validateInputIssuance(input.issuance, `${field}.issuance`);
  }

  validateFinalizerSpec(input.finalizer, `${field}.finalizer`);
}

function validateOutputSchema(output: unknown, field: string): asserts output is OutputSchema {
  assert(isRecord(output), `${field} must be an object`);
  assertNonEmptyString(output.id, `${field}.id`);
  assertSafeUint(output.amount_sat, `${field}.amount_sat`);
  validateLockVariant(output.lock, `${field}.lock`);
  validateAssetVariant(output.asset, `${field}.asset`);
  validateOutputBlinder(output.blinder, `${field}.blinder`);
}

export function validateRuntimeParams(params: unknown): asserts params is RuntimeParams {
  assert(isRecord(params), "params must be an object");
  assert(Array.isArray(params.inputs), "params.inputs must be an array");
  assert(Array.isArray(params.outputs), "params.outputs must be an array");

  for (let index = 0; index < params.inputs.length; index += 1) {
    validateInputSchema(params.inputs[index], `params.inputs[${String(index)}]`);
  }

  for (let index = 0; index < params.outputs.length; index += 1) {
    validateOutputSchema(params.outputs[index], `params.outputs[${String(index)}]`);
  }

  if (params.fee_rate_sat_vb !== undefined) {
    assert(typeof params.fee_rate_sat_vb === "number", "params.fee_rate_sat_vb must be a number");
    assert(Number.isFinite(params.fee_rate_sat_vb), "params.fee_rate_sat_vb must be finite");
    assert(params.fee_rate_sat_vb >= 0, "params.fee_rate_sat_vb must be non-negative");
  }

  if (params.locktime !== undefined) {
    assertLockTime(params.locktime, "params.locktime");
  }
}

export function validateTxCreateRequest(request: unknown): asserts request is TxCreateRequest {
  assert(isRecord(request), "request must be an object");

  assertNonEmptyString(request.abi_version, "abi_version");
  assert(request.abi_version === TX_CREATE_ABI_VERSION, `abi_version must be ${TX_CREATE_ABI_VERSION}`);

  assertNonEmptyString(request.request_id, "request_id");
  validateNetwork(request.network);
  assertBoolean(request.broadcast, "broadcast");
  validateRuntimeParams(request.params);
}
