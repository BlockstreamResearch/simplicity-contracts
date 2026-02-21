import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";

import type { TxCreateRequest, TxCreateResponse } from "../../../src";

type JsonObject = Record<string, unknown>;
const GRACEFUL_SHUTDOWN_TIMEOUT_MS = 5_000;
const FORCE_SHUTDOWN_TIMEOUT_MS = 2_000;

interface HarnessEnvelope {
  id: number;
  ok: boolean;
  result?: unknown;
  error?: string;
}

interface PendingRequest {
  command: string;
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}

export interface InitResult {
  network: string;
  policy_asset_id: string;
  signer_address: string;
  signer_script_hex: string;
  esplora_url: string;
  workdir: string;
  wallet_data_dir: string;
}

export interface IssueAndFundAssetResult {
  asset_id: string;
  funded_amount_sat: number;
}

export interface SignerInfoResult {
  address: string;
  script_hex: string;
  xonly_pubkey: string;
}

export interface SingleMempoolTxidResult {
  txid: string;
}

export interface IssuanceInfoResult {
  asset_id: string;
  reissuance_token_asset_id: string;
  asset_entropy: number[];
}

export class RegtestHarness {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly pending = new Map<number, PendingRequest>();
  private readonly stderrLines: string[] = [];
  private readonly exitPromise: Promise<void>;
  private resolveExitPromise!: () => void;
  private hasExited = false;
  private closingPromise: Promise<void> | undefined;
  private nextId = 1;

  private constructor(child: ChildProcessWithoutNullStreams) {
    this.child = child;
    this.exitPromise = new Promise<void>((resolve) => {
      this.resolveExitPromise = resolve;
    });

    const lineReader = readline.createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });

    lineReader.on("line", (line) => {
      if (!line.trim()) {
        return;
      }

      let envelope: HarnessEnvelope;
      try {
        envelope = JSON.parse(line) as HarnessEnvelope;
      } catch {
        this.rejectAll(new Error(`harness produced non-JSON output: ${line}\nstderr:\n${this.stderrLines.join("\n")}`));
        return;
      }

      const pending = this.pending.get(envelope.id);
      if (!pending) {
        return;
      }

      this.pending.delete(envelope.id);

      if (!envelope.ok) {
        pending.reject(new Error(`harness command '${pending.command}' failed: ${envelope.error ?? "unknown error"}`));
        return;
      }

      pending.resolve(envelope.result);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const line = chunk.toString("utf8").trim();
      if (line.length > 0) {
        this.stderrLines.push(line);
      }
    });

    child.on("exit", (code, signal) => {
      if (this.hasExited) {
        return;
      }

      this.hasExited = true;
      this.resolveExitPromise();

      if (this.pending.size === 0) {
        return;
      }

      this.rejectAll(
        new Error(
          `harness exited unexpectedly (code=${String(code ?? "null")}, signal=${signal ?? "null"})\nstderr:\n${this.stderrLines.join("\n")}`,
        ),
      );
    });
  }

  static start(repoRoot: string): RegtestHarness {
    const command = ["ulimit -n 8192 >/dev/null 2>&1 || true", "cargo run -q -p wallet-abi-regtest-harness"].join(
      " && ",
    );
    const env = { ...process.env };
    delete env.RUST_LOG;
    const detached = process.platform !== "win32";

    const child = spawn("bash", ["-lc", command], {
      cwd: repoRoot,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      detached,
    });

    return new RegtestHarness(child);
  }

  async init(): Promise<InitResult> {
    return this.request<InitResult>("init", {});
  }

  async fundLbtc(amountSat: number): Promise<void> {
    await this.request("fund_lbtc", {
      amount_sat: amountSat,
    });
  }

  async signerInfo(): Promise<SignerInfoResult> {
    return this.request<SignerInfoResult>("signer_info", {});
  }

  async issueAndFundAsset(amountSat: number): Promise<IssueAndFundAssetResult> {
    return this.request<IssueAndFundAssetResult>("issue_and_fund_asset", {
      amount_sat: amountSat,
    });
  }

  async mineBlocks(blocks: number): Promise<void> {
    await this.request("mine_blocks", { blocks });
  }

  async singleMempoolTxid(label: string): Promise<SingleMempoolTxidResult> {
    return this.request<SingleMempoolTxidResult>("single_mempool_txid", { label });
  }

  async processTxCreate(request: TxCreateRequest): Promise<TxCreateResponse> {
    return this.request<TxCreateResponse>("process_tx_create", { request });
  }

  async extractIssuanceInfo(txHex: string, issuanceEntropy: number[]): Promise<IssuanceInfoResult> {
    return this.request<IssuanceInfoResult>("extract_issuance_info", {
      tx_hex: txHex,
      issuance_entropy: issuanceEntropy,
    });
  }

  async close(): Promise<void> {
    this.closingPromise ??= this.closeInternal();
    return this.closingPromise;
  }

  private async closeInternal(): Promise<void> {
    try {
      await this.request("shutdown", {});
    } catch {
      // If shutdown fails because the process has already exited, fallback to signal-based teardown.
    }

    await this.waitForExit(GRACEFUL_SHUTDOWN_TIMEOUT_MS);
    if (this.hasExited) {
      return;
    }

    this.signalHarnessTree("SIGTERM");
    await this.waitForExit(FORCE_SHUTDOWN_TIMEOUT_MS);
    if (this.hasExited) {
      return;
    }

    this.signalHarnessTree("SIGKILL");
    await this.waitForExit(FORCE_SHUTDOWN_TIMEOUT_MS);
  }

  private async waitForExit(timeoutMs: number): Promise<void> {
    if (this.hasExited) {
      return;
    }

    await Promise.race([this.exitPromise, this.sleep(timeoutMs)]);
  }

  private signalHarnessTree(signal: NodeJS.Signals): void {
    const pid = this.child.pid;
    if (!pid) {
      return;
    }

    if (process.platform !== "win32") {
      try {
        process.kill(-pid, signal);
        return;
      } catch {
        // Fallback to the direct child PID if process-group signaling is unavailable.
      }
    }

    try {
      process.kill(pid, signal);
    } catch {
      // Process may have already exited.
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  private request<T = unknown>(command: string, payload: JsonObject): Promise<T> {
    const id = this.nextId++;
    const message = JSON.stringify({
      id,
      command,
      ...payload,
    });

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        command,
        resolve: (value: unknown) => {
          resolve(value as T);
        },
        reject,
      });

      this.child.stdin.write(`${message}\n`, "utf8", (error) => {
        if (error) {
          this.pending.delete(id);
          reject(error);
        }
      });
    });
  }

  private rejectAll(error: Error): void {
    for (const [, pending] of this.pending) {
      pending.reject(error);
    }
    this.pending.clear();
  }
}
