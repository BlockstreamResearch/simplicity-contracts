import type { SupportedNetwork } from "./constants";

export type Network = SupportedNetwork;

export type Txid = string;
export type AssetId = string;
export type ScriptHex = string;
export type AddressString = string;
export type PublicKeyHex = string;
export type SecretKeyHex = string;
export type XOnlyPublicKeyHex = string;
export type OutPointString = string;

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export type LockTime = { Blocks: number } | { Seconds: number };

export type AssetFilter =
  | "none"
  | {
      exact: {
        asset_id: AssetId;
      };
    };

export type AmountFilter =
  | "none"
  | {
      exact: {
        satoshi: number;
      };
    }
  | {
      min: {
        satoshi: number;
      };
    };

export type LockFilter =
  | "none"
  | {
      script: {
        script: ScriptHex;
      };
    };

export interface WalletSourceFilter {
  asset: AssetFilter;
  amount: AmountFilter;
  lock: LockFilter;
}

export type UTXOSource =
  | {
      wallet: {
        filter: WalletSourceFilter;
      };
    }
  | {
      provided: {
        outpoint: OutPointString;
      };
    };

export type InputIssuanceKind = "new" | "reissue";

export interface InputIssuance {
  kind: InputIssuanceKind;
  asset_amount_sat: number;
  token_amount_sat: number;
  entropy: number[];
}

export type TaprootIdentity =
  | {
      Seed: number[];
    }
  | {
      ExternalXOnly: XOnlyPublicKeyHex;
    };

export interface TaprootPubkeyGen {
  identity: TaprootIdentity;
  pubkey: PublicKeyHex;
  address: AddressString;
}

export type InternalKeySource =
  | {
      local: {
        key: PublicKeyHex;
      };
    }
  | {
      external: {
        key: TaprootPubkeyGen;
      };
    };

export type FinalizerSpec =
  | {
      type: "wallet";
    }
  | {
      type: "simf";
      source_simf: string;
      internal_key: InternalKeySource;
      arguments: number[];
      witness: number[];
    };

export type InputBlinder =
  | "wallet"
  | "explicit"
  | {
      provided: {
        secret_key: SecretKeyHex;
      };
    };

export interface InputSchema {
  id: string;
  utxo_source: UTXOSource;
  blinder: InputBlinder;
  sequence: number;
  issuance?: InputIssuance;
  finalizer: FinalizerSpec;
}

export type LockVariant =
  | {
      type: "script";
      script: ScriptHex;
    }
  | {
      type: "finalizer";
      finalizer: FinalizerSpec;
    };

export type AssetVariant =
  | {
      type: "asset_id";
      asset_id: AssetId;
    }
  | {
      type: "new_issuance_asset";
      input_index: number;
    }
  | {
      type: "new_issuance_token";
      input_index: number;
    }
  | {
      type: "re_issuance_asset";
      input_index: number;
    };

export type BlinderVariant =
  | "wallet"
  | "explicit"
  | {
      provided: {
        pubkey: PublicKeyHex;
      };
    };

export interface OutputSchema {
  id: string;
  amount_sat: number;
  lock: LockVariant;
  asset: AssetVariant;
  blinder: BlinderVariant;
}

export interface RuntimeParams {
  inputs: InputSchema[];
  outputs: OutputSchema[];
  fee_rate_sat_vb?: number;
  locktime?: LockTime;
}

export interface TxCreateRequest {
  abi_version: string;
  request_id: string;
  network: Network;
  params: RuntimeParams;
  broadcast: boolean;
}

export interface TransactionInfo {
  tx_hex: string;
  txid: Txid;
}

export type TxCreateArtifacts = Record<string, JsonValue>;

export type Status = "ok" | "error";

export interface ErrorInfo {
  code: string;
  message: string;
  details?: JsonValue;
}

export interface TxCreateResponse {
  abi_version: string;
  request_id: string;
  network: Network;
  status: Status;
  transaction?: TransactionInfo;
  artifacts?: TxCreateArtifacts;
  error?: ErrorInfo;
}
