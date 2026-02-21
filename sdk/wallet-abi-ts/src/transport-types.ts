import type { TxCreateRequest, TxCreateResponse } from "./types";

export const WALLET_ABI_TRANSPORT_VERSION = 1 as const;
export const WALLET_ABI_TRANSPORT_KIND_TX_CREATE = "tx_create" as const;
export const WALLET_ABI_TRANSPORT_REQUEST_PARAM = "wa_v1" as const;
export const WALLET_ABI_TRANSPORT_RESPONSE_PARAM = "wa_resp_v1" as const;
export const WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES = 64 * 1024;
export const WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS = 120_000;
export const WALLET_ABI_TRANSPORT_REPLAY_WINDOW_MS = 10 * 60 * 1000;

export type WalletAbiTransportKind = typeof WALLET_ABI_TRANSPORT_KIND_TX_CREATE;

export type WalletAbiTransportCallbackMode = "same_device_https" | "backend_push" | "qr_roundtrip";

export interface WalletAbiTransportCallback {
  mode: WalletAbiTransportCallbackMode;
  url?: string;
  session_id?: string;
}

export interface WalletAbiTransportRequestV1 {
  v: typeof WALLET_ABI_TRANSPORT_VERSION;
  kind: WalletAbiTransportKind;
  request_id: string;
  origin: string;
  created_at_ms: number;
  expires_at_ms: number;
  callback: WalletAbiTransportCallback;
  tx_create_request: TxCreateRequest;
}

export interface WalletAbiTransportErrorInfo {
  code: string;
  message: string;
}

export interface WalletAbiTransportResponseV1 {
  v: typeof WALLET_ABI_TRANSPORT_VERSION;
  request_id: string;
  origin: string;
  processed_at_ms: number;
  tx_create_response?: TxCreateResponse;
  error?: WalletAbiTransportErrorInfo;
}

export interface WalletAbiTransportDecodeOptions {
  maxDecodedBytes?: number;
}

export interface WalletAbiTransportChunk {
  index: number;
  total: number;
  payload: string;
}
