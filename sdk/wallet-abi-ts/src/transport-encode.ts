import { WalletAbiSdkValidationError } from "./errors";
import { zstdCompressSync, zstdDecompressSync } from "node:zlib";
import type {
  WalletAbiTransportChunk,
  WalletAbiTransportDecodeOptions,
  WalletAbiTransportRequestV1,
  WalletAbiTransportResponseV1,
} from "./transport-types";
import {
  WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES,
  WALLET_ABI_TRANSPORT_REQUEST_PARAM,
  WALLET_ABI_TRANSPORT_RESPONSE_PARAM,
} from "./transport-types";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

function compress(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(zstdCompressSync(bytes));
}

function decompressOrRaw(bytes: Uint8Array): Uint8Array {
  try {
    return new Uint8Array(zstdDecompressSync(bytes));
  } catch {
    // Backward-compatibility for already-issued uncompressed payloads.
    return bytes;
  }
}

export function encodeWalletAbiTransport(value: unknown): string {
  const serialized = JSON.stringify(value);
  const compressed = compress(textEncoder.encode(serialized));
  return base64urlEncode(compressed);
}

export function decodeWalletAbiTransport<T>(
  encoded: string,
  options: WalletAbiTransportDecodeOptions = {},
  parse: (value: unknown) => T = (value) => value as T,
): T {
  const bytes = decompressOrRaw(base64urlDecode(encoded));
  const maxDecodedBytes = options.maxDecodedBytes ?? WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES;

  if (bytes.length > maxDecodedBytes) {
    throw new WalletAbiSdkValidationError(`transport payload exceeds ${String(maxDecodedBytes)} bytes`);
  }

  return parse(JSON.parse(textDecoder.decode(bytes)) as unknown);
}

export function encodeWalletAbiTransportRequest(envelope: WalletAbiTransportRequestV1): string {
  return encodeWalletAbiTransport(envelope);
}

export function encodeWalletAbiTransportResponse(envelope: WalletAbiTransportResponseV1): string {
  return encodeWalletAbiTransport(envelope);
}

export function decodeWalletAbiTransportRequest(encoded: string): WalletAbiTransportRequestV1 {
  return decodeWalletAbiTransport<WalletAbiTransportRequestV1>(encoded);
}

export function decodeWalletAbiTransportResponse(encoded: string): WalletAbiTransportResponseV1 {
  return decodeWalletAbiTransport<WalletAbiTransportResponseV1>(encoded);
}

function parseChunkPrefix(value: string): WalletAbiTransportChunk {
  const match = /^wa1:(\d+)\/(\d+):(.*)$/u.exec(value);
  if (match === null) {
    throw new WalletAbiSdkValidationError("invalid chunk encoding");
  }

  const index = Number.parseInt(match[1] ?? "", 10);
  const total = Number.parseInt(match[2] ?? "", 10);
  const payload = match[3] ?? "";

  if (!Number.isInteger(index) || !Number.isInteger(total) || index < 0 || total < 1 || index >= total) {
    throw new WalletAbiSdkValidationError("invalid chunk metadata");
  }

  return { index, total, payload };
}

export function chunkWalletAbiTransportPayload(encodedPayload: string, maxChunkSize = 1024): string[] {
  if (!Number.isInteger(maxChunkSize) || maxChunkSize < 64) {
    throw new WalletAbiSdkValidationError("maxChunkSize must be an integer >= 64");
  }

  if (encodedPayload.length <= maxChunkSize) {
    return [encodedPayload];
  }

  const estimatedChunks = Math.ceil(encodedPayload.length / Math.max(1, maxChunkSize - 16));
  const rawChunkSize = Math.ceil(encodedPayload.length / estimatedChunks);
  const chunks: string[] = [];

  for (let index = 0; index < estimatedChunks; index += 1) {
    const start = index * rawChunkSize;
    const end = Math.min(encodedPayload.length, (index + 1) * rawChunkSize);
    chunks.push(`wa1:${String(index)}/${String(estimatedChunks)}:${encodedPayload.slice(start, end)}`);
  }

  return chunks;
}

export function joinWalletAbiTransportChunks(chunks: string[]): string {
  if (chunks.length === 0) {
    throw new WalletAbiSdkValidationError("at least one chunk is required");
  }

  if (chunks.length === 1 && !chunks[0]?.startsWith("wa1:")) {
    return chunks[0] ?? "";
  }

  const parsed = chunks.map(parseChunkPrefix);
  const expectedTotal = parsed[0]?.total ?? 0;

  if (!parsed.every((chunk) => chunk.total === expectedTotal)) {
    throw new WalletAbiSdkValidationError("chunk total mismatch");
  }

  if (parsed.length !== expectedTotal) {
    throw new WalletAbiSdkValidationError("missing chunk(s)");
  }

  const parts = Array<string>(expectedTotal).fill("");
  for (const chunk of parsed) {
    if (parts[chunk.index] !== "") {
      throw new WalletAbiSdkValidationError("duplicate chunk index");
    }
    parts[chunk.index] = chunk.payload;
  }

  if (parts.some((part) => part.length === 0)) {
    throw new WalletAbiSdkValidationError("incomplete chunk set");
  }

  return parts.join("");
}

export function extractTransportFromFragment(
  fragment: string,
  key: typeof WALLET_ABI_TRANSPORT_REQUEST_PARAM | typeof WALLET_ABI_TRANSPORT_RESPONSE_PARAM,
): string | null {
  const normalized = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const params = new URLSearchParams(normalized);
  return params.get(key);
}
