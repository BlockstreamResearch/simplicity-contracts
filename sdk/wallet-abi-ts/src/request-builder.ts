import { TX_CREATE_ABI_VERSION } from "./constants";
import { RuntimeBuilder } from "./runtime-builder";
import type { Network, RuntimeParams, TxCreateRequest } from "./types";
import { validateNetwork, validateTxCreateRequest } from "./validate";

function cloneRequest(request: TxCreateRequest): TxCreateRequest {
  return {
    abi_version: request.abi_version,
    request_id: request.request_id,
    network: request.network,
    params: {
      inputs: request.params.inputs.map((input) => ({ ...input })),
      outputs: request.params.outputs.map((output) => ({ ...output })),
      ...(request.params.fee_rate_sat_vb !== undefined ? { fee_rate_sat_vb: request.params.fee_rate_sat_vb } : {}),
      ...(request.params.locktime !== undefined ? { locktime: request.params.locktime } : {}),
    },
    broadcast: request.broadcast,
  };
}

function runtimeBuilderFrom(params: RuntimeParams | RuntimeBuilder): RuntimeBuilder {
  if (params instanceof RuntimeBuilder) {
    return RuntimeBuilder.create(params.build());
  }

  return RuntimeBuilder.create(params);
}

export interface TxCreateRequestBuilderInit {
  request_id?: string;
  network?: Network;
  broadcast?: boolean;
  abi_version?: string;
  params?: RuntimeParams | RuntimeBuilder;
}

export class TxCreateRequestBuilder {
  private abiVersion: string = TX_CREATE_ABI_VERSION;
  private requestId = "request-0";
  private network: Network = "testnet-liquid";
  private broadcast = false;
  private runtimeBuilder = RuntimeBuilder.create();

  constructor(init: TxCreateRequestBuilderInit = {}) {
    if (init.abi_version !== undefined) {
      this.abiVersion = init.abi_version;
    }

    if (init.request_id !== undefined) {
      this.requestId = init.request_id;
    }

    if (init.network !== undefined) {
      validateNetwork(init.network);
      this.network = init.network;
    }

    if (init.broadcast !== undefined) {
      this.broadcast = init.broadcast;
    }

    if (init.params !== undefined) {
      this.runtimeBuilder = runtimeBuilderFrom(init.params);
    }
  }

  static create(init: TxCreateRequestBuilderInit = {}): TxCreateRequestBuilder {
    return new TxCreateRequestBuilder(init);
  }

  setAbiVersion(abiVersion: string): this {
    this.abiVersion = abiVersion;
    return this;
  }

  setRequestId(requestId: string): this {
    this.requestId = requestId;
    return this;
  }

  setNetwork(network: Network): this {
    validateNetwork(network);
    this.network = network;
    return this;
  }

  setBroadcast(broadcast: boolean): this {
    this.broadcast = broadcast;
    return this;
  }

  setRuntime(runtime: RuntimeParams | RuntimeBuilder): this {
    this.runtimeBuilder = runtimeBuilderFrom(runtime);
    return this;
  }

  runtime(): RuntimeBuilder {
    return this.runtimeBuilder;
  }

  build(): TxCreateRequest {
    const built: TxCreateRequest = {
      abi_version: this.abiVersion,
      request_id: this.requestId,
      network: this.network,
      params: this.runtimeBuilder.build(),
      broadcast: this.broadcast,
    };

    validateTxCreateRequest(built);

    return cloneRequest(built);
  }

  toWalletJson(pretty = false): string {
    return JSON.stringify(this.build(), null, pretty ? 2 : undefined);
  }
}
