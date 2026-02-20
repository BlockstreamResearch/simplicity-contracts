#![allow(clippy::missing_errors_doc)]

use std::convert::TryFrom;
use std::future::Future;

use crate::modules::store::Store;
use crate::modules::utils::execute_request;

use anyhow::{Context, anyhow};
use clap::Subcommand;
use contracts::option_offer::{OptionOfferArguments, OptionOfferRuntime, get_option_offer_address};
use simplicityhl::elements::{AssetId, OutPoint, Script, Txid};
use wallet_abi::Encodable;
use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::TxCreateRequest;
use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

/// Option-offer contract utilities.
#[derive(Subcommand, Debug)]
pub enum OptionOffer {
    /// Create, store, and fund a new option-offer contract in one command.
    Create {
        /// Collateral asset id.
        #[arg(long = "collateral-asset-id")]
        collateral_asset_id: AssetId,
        /// Premium asset id.
        #[arg(long = "premium-asset-id")]
        premium_asset_id: AssetId,
        /// Settlement asset id.
        #[arg(long = "settlement-asset-id")]
        settlement_asset_id: AssetId,
        /// Expected collateral amount user will deposit.
        #[arg(long = "expected-to-deposit-collateral")]
        expected_to_deposit_collateral: u64,
        /// Expected premium amount user will deposit.
        #[arg(long = "expected-to-deposit-premium")]
        expected_to_deposit_premium: u64,
        /// Expected settlement amount user will get on exercise.
        #[arg(long = "expected-to-get-settlement")]
        expected_to_get_settlement: u64,
        /// Unix timestamp after which expiry path becomes valid.
        #[arg(long = "expiry-time")]
        expiry_time: u32,
        /// When set, broadcast the built transaction via Esplora and print txid.
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Import option-offer arguments into local store.
    Import {
        /// Option-offer taproot pubkey gen handle used as local store key.
        #[arg(long = "option-offer-taproot-pubkey-gen")]
        option_offer_taproot_pubkey_gen: String,
        /// Encoded option-offer arguments (hex).
        #[arg(long = "encoded-option-offer-arguments")]
        encoded_option_offer_arguments: String,
    },
    /// Export option-offer arguments from local store.
    Export {
        /// Option-offer taproot pubkey gen handle used as local store key.
        #[arg(long = "option-offer-taproot-pubkey-gen")]
        option_offer_taproot_pubkey_gen: String,
    },
    /// Exercise path: swap settlement asset for collateral and premium.
    Exercise {
        /// Option-offer taproot pubkey gen handle.
        #[arg(long = "option-offer-taproot-pubkey-gen")]
        option_offer_taproot_pubkey_gen: String,
        /// Creation txid containing covenant outputs (collateral at vout=0, premium at vout=1).
        #[arg(long = "creation-txid")]
        creation_tx_id: Txid,
        /// Collateral amount to receive from covenant.
        #[arg(long = "collateral-amount")]
        collateral_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid.
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Withdraw settlement from covenant after exercise.
    Withdraw {
        /// Option-offer taproot pubkey gen handle.
        #[arg(long = "option-offer-taproot-pubkey-gen")]
        option_offer_taproot_pubkey_gen: String,
        /// Exercise txid that produced settlement output in covenant.
        #[arg(long = "exercise-txid")]
        exercise_tx_id: Txid,
        /// When set, broadcast the built transaction via Esplora and print txid.
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Expiry path: reclaim collateral and premium after expiry time.
    Expiry {
        /// Option-offer taproot pubkey gen handle.
        #[arg(long = "option-offer-taproot-pubkey-gen")]
        option_offer_taproot_pubkey_gen: String,
        /// Creation txid containing covenant outputs (collateral at vout=0, premium at vout=1).
        #[arg(long = "creation-txid")]
        creation_tx_id: Txid,
        /// When set, broadcast the built transaction via Esplora and print txid.
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateOutput {
    vout: u32,
    script_pubkey: Script,
    asset_id: Option<AssetId>,
    value_sat: Option<u64>,
}

struct OptionOfferContext {
    runtime: OptionOfferRuntime,
}

impl OptionOfferContext {
    const fn new(runtime: OptionOfferRuntime) -> Self {
        Self { runtime }
    }

    fn load(runtime: WalletRuntimeConfig, taproot_pubkey_gen: &str) -> anyhow::Result<Self> {
        let store = Store::load().context("failed to open local store")?;
        let args = store
            .get_arguments::<OptionOfferArguments>(taproot_pubkey_gen)
            .with_context(|| {
                format!("failed to load option-offer arguments for key '{taproot_pubkey_gen}'")
            })?;

        let tap = TaprootPubkeyGen::build_from_str(
            taproot_pubkey_gen,
            &args,
            runtime.network,
            &get_option_offer_address,
        )
        .with_context(|| format!("invalid option-offer taproot handle '{taproot_pubkey_gen}'"))?;

        let signer_pubkey = runtime.signer_x_only_public_key()?.serialize();
        if signer_pubkey != args.user_pubkey() {
            return Err(anyhow!(
                "signer x-only pubkey mismatch: signer={}, args.user_pubkey={}",
                hex::encode(signer_pubkey),
                hex::encode(args.user_pubkey())
            ));
        }

        Ok(Self::new(OptionOfferRuntime::new(runtime, args, tap)))
    }

    const fn runtime_mut(&mut self) -> &mut WalletRuntimeConfig {
        self.runtime.runtime_mut()
    }

    fn taproot_pubkey_gen(&self) -> String {
        self.runtime.tap().to_string()
    }

    fn build_deposit_request(
        &self,
        collateral_deposit_amount: u64,
        broadcast: bool,
    ) -> TxCreateRequest {
        let mut request = self
            .runtime
            .build_deposit_request(collateral_deposit_amount);
        request.broadcast = broadcast;
        request
    }

    async fn build_exercise_request(
        &self,
        creation_tx_id: Txid,
        collateral_amount: u64,
        broadcast: bool,
    ) -> anyhow::Result<TxCreateRequest> {
        let mut request = self
            .runtime
            .build_exercise_request(creation_tx_id, collateral_amount)
            .await?;
        request.broadcast = broadcast;
        Ok(request)
    }

    async fn build_withdraw_request(
        &self,
        exercise_tx_id: Txid,
        broadcast: bool,
    ) -> anyhow::Result<TxCreateRequest> {
        let tx = {
            let inner_esplora = self.runtime.runtime().esplora.lock().await;
            inner_esplora.get_transaction(exercise_tx_id).await?
        };

        let covenant_script = self.runtime.tap().address.script_pubkey();
        let settlement_asset_id = self.runtime.args().get_settlement_asset_id();

        let outputs = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, tx_out)| tx_out.script_pubkey.eq(&covenant_script))
            .map(
                |(vout, tx_out)| -> anyhow::Result<Option<CandidateOutput>> {
                    if tx_out.asset.is_confidential() {
                        return Ok(None);
                    }

                    let asset_id = tx_out.asset.explicit().ok_or_else(|| {
                        anyhow!(
                            "exercise transaction output at vout={vout} has non-explicit asset id"
                        )
                    })?;

                    if asset_id != settlement_asset_id {
                        return Ok(None);
                    }

                    Ok(Some(CandidateOutput {
                        vout: u32::try_from(vout).context("exercise transaction vout overflow")?,
                        script_pubkey: tx_out.script_pubkey.clone(),
                        asset_id: Some(asset_id),
                        value_sat: tx_out.value.explicit(),
                    }))
                },
            )
            .collect::<anyhow::Result<Vec<_>>>()?;

        let outputs: Vec<_> = outputs.into_iter().flatten().collect();

        let (settlement_vout, settlement_amount) =
            select_settlement_output_for_withdraw(&outputs, &covenant_script, settlement_asset_id)?;

        let mut request = self.runtime.build_withdraw_request_for_outpoint(
            OutPoint::new(exercise_tx_id, settlement_vout),
            settlement_amount,
        )?;
        request.broadcast = broadcast;

        Ok(request)
    }

    async fn build_expiry_request(
        &self,
        creation_tx_id: Txid,
        broadcast: bool,
    ) -> anyhow::Result<TxCreateRequest> {
        let collateral_outpoint = OutPoint::new(creation_tx_id, 0);
        let collateral_tx_out = self
            .runtime
            .runtime()
            .fetch_tx_out(&collateral_outpoint)
            .await?;
        ensure_explicit_asset(
            Option::from(&collateral_tx_out.asset.explicit()),
            self.runtime.args().get_collateral_asset_id(),
            "covenant collateral output",
        )?;
        let collateral_amount = explicit_amount(
            collateral_tx_out.value.explicit(),
            "covenant collateral output",
        )?;

        let premium_outpoint = OutPoint::new(creation_tx_id, 1);
        let premium_tx_out = self
            .runtime
            .runtime()
            .fetch_tx_out(&premium_outpoint)
            .await?;
        ensure_explicit_asset(
            Option::from(&premium_tx_out.asset.explicit()),
            self.runtime.args().get_premium_asset_id(),
            "covenant premium output",
        )?;
        let premium_amount =
            explicit_amount(premium_tx_out.value.explicit(), "covenant premium output")?;

        let mut request =
            self.runtime
                .build_expiry_request(creation_tx_id, collateral_amount, premium_amount)?;
        request.broadcast = broadcast;

        Ok(request)
    }
}

impl OptionOffer {
    #[allow(clippy::too_many_lines)]
    pub async fn handle(&self, runtime: WalletRuntimeConfig) -> anyhow::Result<()> {
        match self {
            Self::Create {
                collateral_asset_id,
                premium_asset_id,
                settlement_asset_id,
                expected_to_deposit_collateral,
                expected_to_deposit_premium,
                expected_to_get_settlement,
                expiry_time,
                broadcast,
            } => {
                let (collateral_per_contract, premium_per_collateral) =
                    derive_contract_terms_from_expected_amounts(
                        *expected_to_deposit_collateral,
                        *expected_to_deposit_premium,
                        *expected_to_get_settlement,
                    )?;

                let user_pubkey = runtime.signer_x_only_public_key()?.serialize();
                let args = OptionOfferArguments::new(
                    *collateral_asset_id,
                    *premium_asset_id,
                    *settlement_asset_id,
                    collateral_per_contract,
                    premium_per_collateral,
                    *expiry_time,
                    user_pubkey,
                );

                let tap = TaprootPubkeyGen::from(&args, runtime.network, &get_option_offer_address)
                    .context("failed to derive option-offer taproot handle")?;
                let taproot_pubkey_gen = tap.to_string();
                let encoded = args.encode()?;

                let store = Store::load().context("failed to open local store")?;
                if store.store.get(&taproot_pubkey_gen)?.is_some() {
                    return Err(anyhow!(
                        "option-offer key already exists in store: {taproot_pubkey_gen}"
                    ));
                }

                let mut context =
                    OptionOfferContext::new(OptionOfferRuntime::new(runtime, args, tap));
                let request =
                    context.build_deposit_request(*expected_to_deposit_collateral, *broadcast);
                execute_then_store_option_offer(&store, &taproot_pubkey_gen, &encoded, || async {
                    let _ = execute_request(context.runtime_mut(), request).await?;
                    Ok(())
                })
                .await?;

                println!(
                    "Option-offer taproot pubkey gen: {}",
                    context.taproot_pubkey_gen()
                );
                println!("Option-offer address: {}", context.runtime.tap().address);
                println!("Encoded option-offer arguments: {}", hex::encode(encoded));
                println!("Derived collateral-per-contract: {collateral_per_contract}");
                println!("Derived premium-per-collateral: {premium_per_collateral}");
                println!("Expiry-time: {expiry_time}");

                Ok(())
            }
            Self::Import {
                option_offer_taproot_pubkey_gen,
                encoded_option_offer_arguments,
            } => Store::load()?.import_arguments::<OptionOfferArguments>(
                option_offer_taproot_pubkey_gen,
                encoded_option_offer_arguments,
                runtime.network,
                &get_option_offer_address,
            ),
            Self::Export {
                option_offer_taproot_pubkey_gen,
            } => {
                println!(
                    "{}",
                    Store::load()?.export_arguments(option_offer_taproot_pubkey_gen)?
                );
                Ok(())
            }
            Self::Exercise {
                option_offer_taproot_pubkey_gen,
                creation_tx_id,
                collateral_amount,
                broadcast,
            } => {
                let mut context =
                    OptionOfferContext::load(runtime, option_offer_taproot_pubkey_gen)?;
                let request = context
                    .build_exercise_request(*creation_tx_id, *collateral_amount, *broadcast)
                    .await?;
                let _ = execute_request(context.runtime_mut(), request).await?;
                Ok(())
            }
            Self::Withdraw {
                option_offer_taproot_pubkey_gen,
                exercise_tx_id,
                broadcast,
            } => {
                let mut context =
                    OptionOfferContext::load(runtime, option_offer_taproot_pubkey_gen)?;
                let request = context
                    .build_withdraw_request(*exercise_tx_id, *broadcast)
                    .await?;
                let _ = execute_request(context.runtime_mut(), request).await?;
                Ok(())
            }
            Self::Expiry {
                option_offer_taproot_pubkey_gen,
                creation_tx_id,
                broadcast,
            } => {
                let mut context =
                    OptionOfferContext::load(runtime, option_offer_taproot_pubkey_gen)?;
                let request = context
                    .build_expiry_request(*creation_tx_id, *broadcast)
                    .await?;
                let _ = execute_request(context.runtime_mut(), request).await?;
                Ok(())
            }
        }
    }
}

fn checked_div_exact_u64(numerator: u64, denominator: u64, label: &str) -> anyhow::Result<u64> {
    if denominator == 0 {
        return Err(anyhow!("{label} denominator must be > 0"));
    }
    if !numerator.is_multiple_of(denominator) {
        return Err(anyhow!(
            "{label} must divide exactly: numerator={numerator}, denominator={denominator}"
        ));
    }
    Ok(numerator / denominator)
}

async fn execute_then_store_option_offer<Exec, ExecFuture>(
    store: &Store,
    taproot_pubkey_gen: &str,
    encoded: &[u8],
    execute: Exec,
) -> anyhow::Result<()>
where
    Exec: FnOnce() -> ExecFuture,
    ExecFuture: Future<Output = anyhow::Result<()>>,
{
    execute().await?;

    store
        .store
        .insert(taproot_pubkey_gen, encoded)
        .with_context(|| {
            format!(
                "transaction succeeded but failed to persist option-offer arguments; \
taproot key: {taproot_pubkey_gen}; encoded args (hex): {}. \
You can recover by re-importing this value with `option-offer import`.",
                hex::encode(encoded)
            )
        })?;

    Ok(())
}

fn derive_contract_terms_from_expected_amounts(
    expected_to_deposit_collateral: u64,
    expected_to_deposit_premium: u64,
    expected_to_get_settlement: u64,
) -> anyhow::Result<(u64, u64)> {
    if expected_to_deposit_collateral == 0 {
        return Err(anyhow!("expected-to-deposit-collateral must be > 0"));
    }

    let premium_per_collateral = checked_div_exact_u64(
        expected_to_deposit_premium,
        expected_to_deposit_collateral,
        "expected-to-deposit-premium / expected-to-deposit-collateral",
    )?;
    let collateral_per_contract = checked_div_exact_u64(
        expected_to_get_settlement,
        expected_to_deposit_collateral,
        "expected-to-get-settlement / expected-to-deposit-collateral",
    )?;

    Ok((collateral_per_contract, premium_per_collateral))
}

fn ensure_explicit_asset(
    actual: Option<&AssetId>,
    expected: AssetId,
    context_label: &str,
) -> anyhow::Result<()> {
    match actual {
        Some(asset_id) if *asset_id == expected => Ok(()),
        Some(asset_id) => Err(anyhow!(
            "{context_label} has wrong asset id: expected {expected}, got {asset_id}"
        )),
        None => Err(anyhow!("{context_label} must have explicit asset id")),
    }
}

fn explicit_amount(value: Option<u64>, context_label: &str) -> anyhow::Result<u64> {
    value.ok_or_else(|| anyhow!("{context_label} must have explicit value"))
}

fn select_settlement_output_for_withdraw(
    outputs: &[CandidateOutput],
    covenant_script: &Script,
    settlement_asset_id: AssetId,
) -> anyhow::Result<(u32, u64)> {
    let Some(selected) = outputs
        .iter()
        .rfind(|output| output.script_pubkey == *covenant_script)
    else {
        return Err(anyhow!("exercise transaction has no covenant outputs"));
    };

    ensure_explicit_asset(
        Option::from(&selected.asset_id),
        settlement_asset_id,
        "selected covenant settlement output",
    )?;
    let amount = explicit_amount(selected.value_sat, "selected covenant settlement output")?;

    Ok((selected.vout, amount))
}
