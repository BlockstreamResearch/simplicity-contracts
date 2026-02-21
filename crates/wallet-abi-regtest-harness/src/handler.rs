use anyhow::anyhow;
use serde::Serialize;
use serde_json::Value;

use crate::nodes::{self, NodeContext};
use crate::protocol::HarnessCommand;
use crate::wallet::WalletSession;

pub struct CommandOutcome {
    pub result: Value,
    pub shutdown: bool,
}

struct HarnessSession {
    node: NodeContext,
    wallet: WalletSession,
}

pub struct HarnessState {
    session: Option<HarnessSession>,
}

impl HarnessState {
    #[must_use]
    pub const fn new() -> Self {
        Self { session: None }
    }
}

fn session_mut(state: &mut HarnessState) -> anyhow::Result<&mut HarnessSession> {
    state
        .session
        .as_mut()
        .ok_or_else(|| anyhow!("harness is not initialized; call init first"))
}

fn session_ref(state: &HarnessState) -> anyhow::Result<&HarnessSession> {
    state
        .session
        .as_ref()
        .ok_or_else(|| anyhow!("harness is not initialized; call init first"))
}

fn to_json_value<T: Serialize>(value: T) -> anyhow::Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| anyhow!("failed to serialize response payload: {error}"))
}

pub async fn handle_command(
    state: &mut HarnessState,
    command: HarnessCommand,
) -> anyhow::Result<CommandOutcome> {
    let result = match command {
        HarnessCommand::Init { mnemonic } => {
            nodes::ensure_finite_nofile_limit()?;

            if let Some(existing) = state.session.as_ref() {
                to_json_value(
                    existing
                        .wallet
                        .init_result(existing.node.esplora_url.clone())?,
                )?
            } else {
                let node = nodes::ensure_node_context()?;
                let wallet = WalletSession::bootstrap(node.esplora_url.clone(), mnemonic)?;
                let init_result = wallet.init_result(node.esplora_url.clone())?;
                state.session = Some(HarnessSession { node, wallet });

                to_json_value(init_result)?
            }
        }
        HarnessCommand::SignerInfo => {
            let session = session_ref(state)?;
            to_json_value(session.wallet.signer_info()?)?
        }
        HarnessCommand::FundLbtc { amount_sat } => {
            let session = session_ref(state)?;
            let signer_address = session.wallet.signer_receive_address()?;
            let policy_asset = session.wallet.policy_asset_id();

            nodes::fund_lbtc(
                &session.node.test_env,
                &signer_address,
                policy_asset,
                amount_sat,
            )?;

            to_json_value(serde_json::json!({
                "funded_asset_id": policy_asset.to_string(),
                "funded_amount_sat": amount_sat,
            }))?
        }
        HarnessCommand::IssueAndFundAsset { amount_sat } => {
            let session = session_ref(state)?;
            let signer_address = session.wallet.signer_receive_address()?;
            let asset_id =
                nodes::issue_and_fund_asset(&session.node.test_env, &signer_address, amount_sat)?;

            to_json_value(serde_json::json!({
                "asset_id": asset_id.to_string(),
                "funded_amount_sat": amount_sat,
            }))?
        }
        HarnessCommand::MineBlocks { blocks } => {
            let session = session_ref(state)?;
            nodes::mine_blocks(&session.node.test_env, blocks)?;
            to_json_value(serde_json::json!({ "mined_blocks": blocks }))?
        }
        HarnessCommand::ProcessTxCreate { request } => {
            let session = session_mut(state)?;
            to_json_value(session.wallet.process_tx_create(&request).await?)?
        }
        HarnessCommand::SingleMempoolTxid { label } => {
            let session = session_ref(state)?;
            let txid = nodes::single_mempool_txid(&session.node.test_env, &label)?;
            to_json_value(serde_json::json!({ "txid": txid.to_string() }))?
        }
        HarnessCommand::ExtractIssuanceInfo {
            tx_hex,
            issuance_entropy,
        } => {
            let session = session_ref(state)?;
            to_json_value(
                session
                    .wallet
                    .extract_issuance_info(&tx_hex, issuance_entropy)?,
            )?
        }
        HarnessCommand::Shutdown => {
            state.session = None;
            nodes::shutdown_node_context()?;
            return Ok(CommandOutcome {
                result: to_json_value(serde_json::json!({ "shutdown": true }))?,
                shutdown: true,
            });
        }
    };

    Ok(CommandOutcome {
        result,
        shutdown: false,
    })
}
