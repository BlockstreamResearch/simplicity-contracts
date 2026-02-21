import { TX_CREATE_ABI_VERSION } from "./constants";
import { WalletAbiSdkValidationError } from "./errors";
import { validateTxCreateRequest } from "./validate";
import type { WalletAbiTransportRequestV1, WalletAbiTransportResponseV1 } from "./transport-types";
import {
  WALLET_ABI_TRANSPORT_KIND_TX_CREATE,
  WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
  WALLET_ABI_TRANSPORT_VERSION,
} from "./transport-types";

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new WalletAbiSdkValidationError(message);
  }
}

function assertNonEmptyString(value: unknown, field: string): asserts value is string {
  assert(typeof value === "string", `${field} must be a string`);
  assert(value.trim().length > 0, `${field} must not be empty`);
}

function assertSafeInteger(value: unknown, field: string): asserts value is number {
  assert(typeof value === "number", `${field} must be a number`);
  assert(Number.isInteger(value), `${field} must be an integer`);
  assert(value >= 0, `${field} must be non-negative`);
}

function assertHttpsUrl(value: string, field: string): void {
  try {
    const parsed = new URL(value);
    assert(parsed.protocol === "https:", `${field} must use https`);
  } catch {
    throw new WalletAbiSdkValidationError(`${field} must be a valid https URL`);
  }
}

export function validateWalletAbiTransportRequest(
  request: unknown,
  nowMs = Date.now(),
): asserts request is WalletAbiTransportRequestV1 {
  assert(typeof request === "object" && request !== null, "request must be an object");

  const input = request as Record<string, unknown>;

  assert(input.v === WALLET_ABI_TRANSPORT_VERSION, `v must be ${String(WALLET_ABI_TRANSPORT_VERSION)}`);
  assert(input.kind === WALLET_ABI_TRANSPORT_KIND_TX_CREATE, `kind must be ${WALLET_ABI_TRANSPORT_KIND_TX_CREATE}`);

  assertNonEmptyString(input.request_id, "request_id");
  assertNonEmptyString(input.origin, "origin");
  assertHttpsUrl(input.origin, "origin");

  assertSafeInteger(input.created_at_ms, "created_at_ms");
  assertSafeInteger(input.expires_at_ms, "expires_at_ms");

  assert(input.expires_at_ms >= input.created_at_ms, "expires_at_ms must be greater than or equal to created_at_ms");

  assert(
    input.expires_at_ms - input.created_at_ms <= WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
    `request ttl must be <= ${String(WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS)} ms`,
  );

  assert(nowMs <= input.expires_at_ms, "request has expired");

  assert(typeof input.callback === "object" && input.callback !== null, "callback must be an object");

  const callback = input.callback as Record<string, unknown>;
  assertNonEmptyString(callback.mode, "callback.mode");

  if (callback.mode === "same_device_https" || callback.mode === "backend_push") {
    assertNonEmptyString(callback.url, "callback.url");
    assertHttpsUrl(callback.url, "callback.url");
  } else if (callback.mode === "qr_roundtrip") {
    assert(callback.url === undefined, "callback.url must be omitted for qr_roundtrip");
  } else {
    throw new WalletAbiSdkValidationError("callback.mode is invalid");
  }

  assert(
    typeof input.tx_create_request === "object" && input.tx_create_request !== null,
    "tx_create_request must be an object",
  );
  validateTxCreateRequest(input.tx_create_request);

  const txCreateRequest = input.tx_create_request as unknown as Record<string, unknown>;
  assert(
    txCreateRequest.abi_version === TX_CREATE_ABI_VERSION,
    `tx_create_request.abi_version must be ${TX_CREATE_ABI_VERSION}`,
  );
}

export function validateWalletAbiTransportResponse(
  response: unknown,
): asserts response is WalletAbiTransportResponseV1 {
  assert(typeof response === "object" && response !== null, "response must be an object");

  const input = response as Record<string, unknown>;

  assert(input.v === WALLET_ABI_TRANSPORT_VERSION, `v must be ${String(WALLET_ABI_TRANSPORT_VERSION)}`);
  assertNonEmptyString(input.request_id, "request_id");
  assertNonEmptyString(input.origin, "origin");
  assertHttpsUrl(input.origin, "origin");
  assertSafeInteger(input.processed_at_ms, "processed_at_ms");

  if (input.tx_create_response === undefined && input.error === undefined) {
    throw new WalletAbiSdkValidationError("response must include tx_create_response or error");
  }

  if (input.error !== undefined) {
    assert(typeof input.error === "object" && input.error !== null, "error must be an object");
    const error = input.error as Record<string, unknown>;
    assertNonEmptyString(error.code, "error.code");
    assertNonEmptyString(error.message, "error.message");
  }
}
