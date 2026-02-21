import type { InputSchema, LockTime, OutputSchema, RuntimeParams } from "./types";
import { validateRuntimeParams } from "./validate";

function cloneRuntimeParams(params: RuntimeParams): RuntimeParams {
  return {
    inputs: params.inputs.map((input) => ({ ...input })),
    outputs: params.outputs.map((output) => ({ ...output })),
    ...(params.fee_rate_sat_vb !== undefined ? { fee_rate_sat_vb: params.fee_rate_sat_vb } : {}),
    ...(params.locktime !== undefined ? { locktime: params.locktime } : {}),
  };
}

export interface RuntimeBuilderInit {
  inputs?: InputSchema[];
  outputs?: OutputSchema[];
  fee_rate_sat_vb?: number;
  locktime?: LockTime;
}

export class RuntimeBuilder {
  private readonly state: RuntimeParams;

  constructor(init: RuntimeBuilderInit = {}) {
    this.state = {
      inputs: [...(init.inputs ?? [])],
      outputs: [...(init.outputs ?? [])],
      ...(init.fee_rate_sat_vb !== undefined ? { fee_rate_sat_vb: init.fee_rate_sat_vb } : {}),
      ...(init.locktime !== undefined ? { locktime: init.locktime } : {}),
    };
  }

  static create(init: RuntimeBuilderInit = {}): RuntimeBuilder {
    return new RuntimeBuilder(init);
  }

  addInput(input: InputSchema): this {
    this.state.inputs.push(input);
    return this;
  }

  addOutput(output: OutputSchema): this {
    this.state.outputs.push(output);
    return this;
  }

  setInputs(inputs: InputSchema[]): this {
    this.state.inputs = [...inputs];
    return this;
  }

  setOutputs(outputs: OutputSchema[]): this {
    this.state.outputs = [...outputs];
    return this;
  }

  setFeeRateSatVb(feeRateSatVb: number | undefined): this {
    if (feeRateSatVb === undefined) {
      delete this.state.fee_rate_sat_vb;
      return this;
    }

    this.state.fee_rate_sat_vb = feeRateSatVb;
    return this;
  }

  setLocktime(locktime: LockTime | undefined): this {
    if (locktime === undefined) {
      delete this.state.locktime;
      return this;
    }

    this.state.locktime = locktime;
    return this;
  }

  build(): RuntimeParams {
    const built = cloneRuntimeParams(this.state);
    validateRuntimeParams(built);
    return built;
  }

  toWalletJson(pretty = false): string {
    return JSON.stringify(this.build(), null, pretty ? 2 : undefined);
  }
}
