import { RuntimeBuilder } from "./runtime-builder";
import { TxCreateRequestBuilder } from "./request-builder";
import type { RuntimeParams, TxCreateRequest } from "./types";
import { validateRuntimeParams, validateTxCreateRequest } from "./validate";

function cloneRuntimeParams(params: RuntimeParams): RuntimeParams {
  return {
    inputs: params.inputs.map((input) => ({ ...input })),
    outputs: params.outputs.map((output) => ({ ...output })),
    ...(params.fee_rate_sat_vb !== undefined ? { fee_rate_sat_vb: params.fee_rate_sat_vb } : {}),
    ...(params.locktime !== undefined ? { locktime: params.locktime } : {}),
  };
}

function cloneTxCreateRequest(request: TxCreateRequest): TxCreateRequest {
  return {
    abi_version: request.abi_version,
    request_id: request.request_id,
    network: request.network,
    params: cloneRuntimeParams(request.params),
    broadcast: request.broadcast,
  };
}

export function toWalletRuntimeObject(input: RuntimeParams | RuntimeBuilder): RuntimeParams {
  const runtime = input instanceof RuntimeBuilder ? input.build() : cloneRuntimeParams(input);
  validateRuntimeParams(runtime);
  return runtime;
}

export function toWalletRequestObject(input: TxCreateRequest | TxCreateRequestBuilder): TxCreateRequest {
  const request = input instanceof TxCreateRequestBuilder ? input.build() : cloneTxCreateRequest(input);

  validateTxCreateRequest(request);
  return request;
}

export function toWalletRequestJson(input: TxCreateRequest | TxCreateRequestBuilder, pretty = false): string {
  const request = toWalletRequestObject(input);
  return JSON.stringify(request, null, pretty ? 2 : undefined);
}
