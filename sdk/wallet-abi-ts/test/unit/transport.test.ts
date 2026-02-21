import { describe, expect, it } from "bun:test";

import {
  DEFAULT_WALLET_ABI_APP_LINK,
  WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
  buildWalletAbiAppLink,
  buildWalletAbiCallbackUrl,
  chunkWalletAbiTransportPayload,
  decodeWalletAbiTransportRequest,
  encodeWalletAbiTransportRequest,
  joinWalletAbiTransportChunks,
  parseWalletAbiCallback,
  validateWalletAbiTransportRequest,
} from "../../src";
import { baseRequest } from "../fixtures";

const now = 1_700_000_000_000;

function buildEnvelope() {
  return {
    v: 1 as const,
    kind: "tx_create" as const,
    request_id: "req-transport-1",
    origin: "https://dapp.example",
    created_at_ms: now,
    expires_at_ms: now + WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
    callback: {
      mode: "same_device_https" as const,
      url: "https://dapp.example/walletabi/callback",
    },
    tx_create_request: baseRequest(),
  };
}

describe("transport encode/decode", () => {
  it("roundtrips a request envelope", () => {
    const envelope = buildEnvelope();
    const encoded = encodeWalletAbiTransportRequest(envelope);
    const decoded = decodeWalletAbiTransportRequest(encoded);

    expect(decoded.request_id).toBe(envelope.request_id);
    expect(decoded.tx_create_request.request_id).toBe(envelope.tx_create_request.request_id);
  });

  it("decodes legacy uncompressed payloads", () => {
    const envelope = buildEnvelope();
    const legacyEncoded = Buffer.from(JSON.stringify(envelope))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    const decoded = decodeWalletAbiTransportRequest(legacyEncoded);
    expect(decoded.request_id).toBe(envelope.request_id);
  });

  it("chunks and rejoins encoded payload", () => {
    const envelope = buildEnvelope();
    const encoded = encodeWalletAbiTransportRequest(envelope);

    const chunks = chunkWalletAbiTransportPayload(encoded, 96);
    const rejoined = joinWalletAbiTransportChunks(chunks);

    expect(rejoined).toBe(encoded);
  });
});

describe("transport validation", () => {
  it("accepts valid request", () => {
    const envelope = buildEnvelope();

    expect(() => {
      validateWalletAbiTransportRequest(envelope, now + 1);
    }).not.toThrow();
  });

  it("rejects expired request", () => {
    const envelope = {
      ...buildEnvelope(),
      expires_at_ms: now + 1,
    };

    expect(() => {
      validateWalletAbiTransportRequest(envelope, now + 5);
    }).toThrow();
  });

  it("rejects qr callback with url", () => {
    const envelope = {
      ...buildEnvelope(),
      callback: {
        mode: "qr_roundtrip" as const,
        url: "https://dapp.example/should-not-be-here",
      },
    };

    expect(() => {
      validateWalletAbiTransportRequest(envelope, now + 1);
    }).toThrow();
  });
});

describe("transport links", () => {
  it("builds app link with transport fragment", () => {
    const link = buildWalletAbiAppLink(buildEnvelope());

    expect(link.startsWith(DEFAULT_WALLET_ABI_APP_LINK)).toBe(true);
    expect(link.includes("#wa_v1=")).toBe(true);
  });

  it("builds and parses callback response", () => {
    const callbackUrl = "https://dapp.example/walletabi/callback";
    const response = {
      v: 1 as const,
      request_id: "req-transport-1",
      origin: "https://dapp.example",
      processed_at_ms: now,
      tx_create_response: {
        abi_version: "wallet-create-0.1",
        request_id: "req-transport-1",
        network: "testnet-liquid" as const,
        status: "ok" as const,
      },
    };

    const callback = buildWalletAbiCallbackUrl(callbackUrl, response);
    const parsed = parseWalletAbiCallback(callback);

    expect(parsed.request_id).toBe("req-transport-1");
    expect(parsed.tx_create_response?.status).toBe("ok");
  });
});
