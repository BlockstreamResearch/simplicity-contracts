import { WalletAbiSdkValidationError } from "./errors";
import {
  decodeWalletAbiTransportResponse,
  encodeWalletAbiTransportRequest,
  encodeWalletAbiTransportResponse,
  extractTransportFromFragment,
} from "./transport-encode";
import type { WalletAbiTransportRequestV1, WalletAbiTransportResponseV1 } from "./transport-types";
import { WALLET_ABI_TRANSPORT_REQUEST_PARAM, WALLET_ABI_TRANSPORT_RESPONSE_PARAM } from "./transport-types";
import { validateWalletAbiTransportResponse } from "./transport-validate";

export interface BuildWalletAbiAppLinkOptions {
  baseUrl?: string;
}

export const DEFAULT_WALLET_ABI_APP_LINK = "https://blockstream.com/walletabi/request";

export function buildWalletAbiAppLink(
  envelope: WalletAbiTransportRequestV1,
  options: BuildWalletAbiAppLinkOptions = {},
): string {
  const baseUrl = options.baseUrl ?? DEFAULT_WALLET_ABI_APP_LINK;
  const encoded = encodeWalletAbiTransportRequest(envelope);
  return `${baseUrl}#${WALLET_ABI_TRANSPORT_REQUEST_PARAM}=${encoded}`;
}

export function buildWalletAbiCallbackUrl(callbackUrl: string, responseEnvelope: WalletAbiTransportResponseV1): string {
  const encoded = encodeWalletAbiTransportResponse(responseEnvelope);

  let parsed: URL;
  try {
    parsed = new URL(callbackUrl);
  } catch {
    throw new WalletAbiSdkValidationError("callbackUrl must be a valid URL");
  }

  if (parsed.protocol !== "https:") {
    throw new WalletAbiSdkValidationError("callbackUrl must use https");
  }

  parsed.hash = `${WALLET_ABI_TRANSPORT_RESPONSE_PARAM}=${encoded}`;
  return parsed.toString();
}

export function parseWalletAbiCallback(fragmentOrUrl: string): WalletAbiTransportResponseV1 {
  const fragment = fragmentOrUrl.includes("#") ? (fragmentOrUrl.split("#")[1] ?? "") : fragmentOrUrl;

  const encoded = extractTransportFromFragment(fragment, WALLET_ABI_TRANSPORT_RESPONSE_PARAM);
  if (encoded === null || encoded.length === 0) {
    throw new WalletAbiSdkValidationError(`${WALLET_ABI_TRANSPORT_RESPONSE_PARAM} fragment parameter is missing`);
  }

  const envelope = decodeWalletAbiTransportResponse(encoded);
  validateWalletAbiTransportResponse(envelope);
  return envelope;
}
