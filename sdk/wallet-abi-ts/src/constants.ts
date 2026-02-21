export const TX_CREATE_ABI_VERSION = "wallet-create-0.1" as const;

export const SUPPORTED_NETWORKS = ["liquid", "testnet-liquid", "localtest-liquid"] as const;

export type SupportedNetwork = (typeof SUPPORTED_NETWORKS)[number];
