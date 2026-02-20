//! Output resolution for transaction construction.
//!
//! This module balances the final output set through a deterministic, equation-first flow:
//! 1. Materialize requested outputs exactly as declared in `RuntimeParams`.
//! 2. Normalize or append the fee output to match the target policy-asset fee.
//! 3. Aggregate per-asset supply from resolved inputs plus issuance/reissuance minting.
//! 4. Aggregate per-asset demand from all outputs currently present in the PSET.
//! 5. Compute deficits and residuals per asset.
//! 6. Fail if any deficit remains; otherwise append one change output per residual asset.
//! 7. Assign output blinder indices and assert exact per-asset conservation.
//!
//! # Assumptions
//!
//! Input resolution is expected to be fee-aware (implicit fee demand injected on policy asset).
//! This module still enforces exact conservation independently and hard-fails on any deficit.
//!
//! # Complexity
//!
//! Let:
//! - `I` = number of inputs in the PSET
//! - `O` = number of outputs after fee/change materialization
//! - `A` = number of distinct assets across supply and demand
//!
//! Time complexity is `O(I + O + A)` and auxiliary space complexity is `O(A)`.

use crate::runtime::input_resolution::{
    add_balance, derive_issuance_entropy, issuance_token_from_entropy_for_unblinded_issuance,
};
use crate::runtime::{WalletRuntimeConfig, get_finalizer_spec_key};
use crate::{
    AssetVariant, BlinderVariant, FinalizerSpec, InputIssuance, InputIssuanceKind, LockVariant,
    RuntimeParams, WalletAbiError,
};

use std::collections::{BTreeMap, BTreeSet};

use lwk_wollet::bitcoin::PublicKey;
use lwk_wollet::elements::pset::{Output, PartiallySignedTransaction};
use lwk_wollet::elements::{Address, AssetId, OutPoint, Script};

/// Aggregated amounts keyed by asset id.
type AssetBalances = BTreeMap<AssetId, u64>;

/// Result of one supply-vs-demand comparison pass.
#[derive(Debug, Default)]
struct BalanceDelta {
    /// Positive entries where `demand > supply`.
    deficit_by_asset: AssetBalances,
    /// Positive entries where `supply > demand`.
    residual_by_asset: AssetBalances,
}

/// Validate one output-linked input index and return it as `usize`.
fn validate_output_input_index(
    output_id: &str,
    input_index: u32,
    input_count: usize,
) -> Result<usize, WalletAbiError> {
    let idx = usize::try_from(input_index).map_err(|_| {
        WalletAbiError::InvalidRequest(format!(
            "output '{output_id}' input_index overflow: {input_index}"
        ))
    })?;

    if idx >= input_count {
        return Err(WalletAbiError::InvalidRequest(format!(
            "output '{output_id}' references missing input_index {input_index}"
        )));
    }

    Ok(idx)
}

/// Return indices of inputs finalized by the wallet signer.
///
/// These indices are later used as valid `blinder_index` anchors for blinded outputs.
fn wallet_input_indices(pst: &PartiallySignedTransaction) -> Result<Vec<u32>, WalletAbiError> {
    let mut indices = Vec::new();

    for (index, input) in pst.inputs().iter().enumerate() {
        let finalizer = FinalizerSpec::decode(
            input
                .proprietary
                .get(&get_finalizer_spec_key())
                .ok_or_else(|| {
                    WalletAbiError::InvalidRequest(format!(
                        "missing finalizer metadata for input index {index}"
                    ))
                })?,
        )?;

        if matches!(finalizer, FinalizerSpec::Wallet) {
            let index_u32 = u32::try_from(index).map_err(|_| {
                WalletAbiError::InvalidRequest(format!(
                    "wallet input index overflow while balancing outputs: {index}"
                ))
            })?;
            indices.push(index_u32);
        }
    }

    Ok(indices)
}

/// Aggregate issuance/reissuance minting supply from declared inputs.
///
/// For each declared input with issuance metadata:
/// - Add `asset_amount_sat` to the derived issuance asset id.
/// - Add `token_amount_sat` to the derived reissuance token id (if non-zero).
fn aggregate_issuance_supply(
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<AssetBalances, WalletAbiError> {
    let mut balances = AssetBalances::new();

    for (input_index, input) in params.inputs.iter().enumerate() {
        let Some(issuance) = input.issuance.as_ref() else {
            continue;
        };

        let pset_input = pst.inputs().get(input_index).ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "input '{}' at index {input_index} missing from PSET while aggregating issuance supply",
                input.id
            ))
        })?;

        let outpoint = OutPoint::new(pset_input.previous_txid, pset_input.previous_output_index);
        let entropy = derive_issuance_entropy(outpoint, issuance);
        let issuance_asset = AssetId::from_entropy(entropy);
        add_balance(&mut balances, issuance_asset, issuance.asset_amount_sat)?;

        if issuance.token_amount_sat > 0 {
            let token_asset = issuance_token_from_entropy_for_unblinded_issuance(entropy);
            add_balance(&mut balances, token_asset, issuance.token_amount_sat)?;
        }
    }

    Ok(balances)
}

/// Aggregate total per-asset input supply.
///
/// Supply is the sum of:
/// - Base amounts from all PSET inputs.
/// - Minted issuance/reissuance amounts derived from declared input metadata.
///
/// Overflow is rejected via checked arithmetic.
fn aggregate_input_supply(
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<AssetBalances, WalletAbiError> {
    let mut balances = AssetBalances::new();

    for (input_index, input) in pst.inputs().iter().enumerate() {
        let asset = input.asset.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "input index {input_index} missing explicit asset while aggregating supply"
            ))
        })?;
        let amount_sat = input.amount.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "input index {input_index} missing explicit amount while aggregating supply"
            ))
        })?;
        add_balance(&mut balances, asset, amount_sat)?;
    }

    let issuance_supply = aggregate_issuance_supply(pst, params)?;
    for (asset_id, amount_sat) in issuance_supply {
        add_balance(&mut balances, asset_id, amount_sat)?;
    }

    Ok(balances)
}

/// Aggregate total per-asset output demand from current PSET outputs.
///
/// Fee output (policy asset, empty script) is treated as ordinary demand and is not
/// special-cased in this aggregation.
fn aggregate_output_demand(
    pst: &PartiallySignedTransaction,
) -> Result<AssetBalances, WalletAbiError> {
    let mut balances = AssetBalances::new();

    for (output_index, output) in pst.outputs().iter().enumerate() {
        let asset = output.asset.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "output index {output_index} missing explicit asset while aggregating demand"
            ))
        })?;
        let amount_sat = output.amount.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "output index {output_index} missing explicit amount while aggregating demand"
            ))
        })?;
        add_balance(&mut balances, asset, amount_sat)?;
    }

    Ok(balances)
}

/// Compute per-asset deficits and residuals from supply/demand maps.
///
/// Definitions:
/// - deficit: `max(demand - supply, 0)`
/// - residual: `max(supply - demand, 0)`
///
/// Returns `Funding` error if any deficit is present, including deterministic asset-ordered
/// deficit details and the applied fee target context.
fn compute_balance_delta(
    supply_by_asset: &AssetBalances,
    demand_by_asset: &AssetBalances,
    fee_target_sat: u64,
) -> Result<BalanceDelta, WalletAbiError> {
    let mut delta = BalanceDelta::default();
    let mut all_assets = BTreeSet::new();

    all_assets.extend(supply_by_asset.keys().copied());
    all_assets.extend(demand_by_asset.keys().copied());

    for asset_id in all_assets {
        let supply_sat = supply_by_asset.get(&asset_id).copied().unwrap_or(0);
        let demand_sat = demand_by_asset.get(&asset_id).copied().unwrap_or(0);

        if demand_sat > supply_sat {
            delta
                .deficit_by_asset
                .insert(asset_id, demand_sat - supply_sat);
            continue;
        }

        if supply_sat > demand_sat {
            delta
                .residual_by_asset
                .insert(asset_id, supply_sat - demand_sat);
        }
    }

    if !delta.deficit_by_asset.is_empty() {
        let details = delta
            .deficit_by_asset
            .iter()
            .map(|(asset_id, missing_sat)| format!("{asset_id}:{missing_sat}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(WalletAbiError::Funding(format!(
            "asset deficits after applying fee target {fee_target_sat}: {details}"
        )));
    }

    Ok(delta)
}

/// Resolve the issuance context required for one issuance-derived output asset.
///
/// The returned tuple is `(issuance_metadata, prevout)`.
fn resolve_issuance_asset_context(
    output_id: &str,
    input_index: u32,
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<(InputIssuance, OutPoint), WalletAbiError> {
    let idx = validate_output_input_index(output_id, input_index, params.inputs.len())?;
    let input = params.inputs.get(idx).ok_or_else(|| {
        WalletAbiError::InvalidRequest(format!(
            "output '{output_id}' references missing input_index {input_index}"
        ))
    })?;
    let issuance = input.issuance.as_ref().ok_or_else(|| {
        WalletAbiError::InvalidRequest(format!(
            "output '{output_id}' references input {} but input '{}' has no issuance metadata",
            input_index, input.id
        ))
    })?;

    let pset_input = pst.inputs().get(idx).ok_or_else(|| {
        WalletAbiError::InvalidRequest(format!(
            "resolved PSET input index {input_index} missing while materializing output '{output_id}'"
        ))
    })?;
    let outpoint = OutPoint {
        txid: pset_input.previous_txid,
        vout: pset_input.previous_output_index,
    };
    Ok((issuance.clone(), outpoint))
}

/// Resolve one output `AssetVariant` into a concrete `AssetId`.
///
/// Issuance-linked variants validate issuance-kind compatibility against the referenced input.
fn resolve_output_asset(
    output_id: &str,
    variant: &AssetVariant,
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<AssetId, WalletAbiError> {
    match variant {
        AssetVariant::AssetId { asset_id } => Ok(*asset_id),
        AssetVariant::NewIssuanceAsset { input_index } => {
            let (issuance, outpoint) =
                resolve_issuance_asset_context(output_id, *input_index, pst, params)?;
            if issuance.kind != InputIssuanceKind::New {
                return Err(WalletAbiError::InvalidRequest(format!(
                    "output '{output_id}' new_issuance_asset references non-new issuance input index {input_index}"
                )));
            }
            Ok(AssetId::from_entropy(derive_issuance_entropy(
                outpoint, &issuance,
            )))
        }
        AssetVariant::NewIssuanceToken { input_index } => {
            let (issuance, outpoint) =
                resolve_issuance_asset_context(output_id, *input_index, pst, params)?;
            if issuance.kind != InputIssuanceKind::New {
                return Err(WalletAbiError::InvalidRequest(format!(
                    "output '{output_id}' new_issuance_token references non-new issuance input index {input_index}"
                )));
            }
            Ok(issuance_token_from_entropy_for_unblinded_issuance(
                derive_issuance_entropy(outpoint, &issuance),
            ))
        }
        AssetVariant::ReIssuanceAsset { input_index } => {
            let (issuance, outpoint) =
                resolve_issuance_asset_context(output_id, *input_index, pst, params)?;
            if issuance.kind != InputIssuanceKind::Reissue {
                return Err(WalletAbiError::InvalidRequest(format!(
                    "output '{output_id}' re_issuance_asset references non-reissue input index {input_index}"
                )));
            }
            Ok(AssetId::from_entropy(derive_issuance_entropy(
                outpoint, &issuance,
            )))
        }
    }
}

/// Resolve output locking script from request lock variant.
///
/// - `Script` uses caller-provided script directly.
/// - `Finalizer::Wallet` uses signer receive script.
/// - `Finalizer::Simf` uses internal taproot script from finalizer metadata.
fn resolve_output_lock_script(
    lock: &LockVariant,
    pst: &PartiallySignedTransaction,
    network: lwk_common::Network,
) -> Result<Script, WalletAbiError> {
    match lock {
        LockVariant::Script { script } => Ok(script.clone()),
        LockVariant::Finalizer { finalizer } => finalizer.try_resolve_script_pubkey(pst, network),
    }
}

/// Mutate or append fee output so it matches the requested fee target.
///
/// If `fee_output_index` is `Some(i)`, validates and overwrites that output as explicit fee.
/// Otherwise appends a new explicit fee output.
fn apply_fee_target(
    pst: &mut PartiallySignedTransaction,
    fee_output_index: Option<usize>,
    fee_target_sat: u64,
    policy_asset: AssetId,
) -> Result<(), WalletAbiError> {
    if let Some(index) = fee_output_index {
        let fee_output = pst.outputs_mut().get_mut(index).ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "fee output index {index} missing while applying fee target"
            ))
        })?;

        let fee_asset = fee_output.asset.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "fee output at index {index} is missing explicit asset metadata"
            ))
        })?;
        if fee_asset != policy_asset {
            return Err(WalletAbiError::InvalidRequest(format!(
                "fee output must use policy asset {policy_asset}, found {fee_asset}"
            )));
        }

        fee_output.script_pubkey = Script::new();
        fee_output.amount = Some(fee_target_sat);
        fee_output.asset = Some(policy_asset);
        fee_output.blinding_key = None;
        fee_output.blinder_index = None;

        return Ok(());
    }

    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_target_sat,
        policy_asset,
        None,
    ));

    Ok(())
}

/// Materialize all user-requested outputs into the PSET in declared order.
///
/// Returns the index of the output whose id is `"fee"` if present, and fails on duplicates.
fn materialize_requested_outputs(
    pst: &mut PartiallySignedTransaction,
    params: &RuntimeParams,
    signer_address: &Address,
    network: lwk_common::Network,
) -> Result<Option<usize>, WalletAbiError> {
    let mut fee_output_index = None;

    for output in &params.outputs {
        let asset_id = resolve_output_asset(&output.id, &output.asset, pst, params)?;
        let script = resolve_output_lock_script(&output.lock, pst, network)?;

        let blinding_key: Option<PublicKey> = match output.blinder {
            BlinderVariant::Wallet => Some(
                signer_address
                    .blinding_pubkey
                    .ok_or_else(|| {
                        WalletAbiError::InvalidSignerConfig(
                            "signer receive address missing blinding pubkey for wallet output blinder"
                                .to_string(),
                        )
                    })?
                    .into(),
            ),
            BlinderVariant::Provided { pubkey } => Some(pubkey.into()),
            BlinderVariant::Explicit => None,
        };

        pst.add_output(Output::new_explicit(
            script,
            output.amount_sat,
            asset_id,
            blinding_key,
        ));

        if output.id == "fee" {
            let inserted_index = pst.outputs().len() - 1;
            if fee_output_index.replace(inserted_index).is_some() {
                return Err(WalletAbiError::InvalidRequest(
                    "duplicate output id 'fee' in params.outputs".to_string(),
                ));
            }
        }
    }

    Ok(fee_output_index)
}

/// Append one blinded change output per positive residual asset.
///
/// Change outputs are deterministic because `residual_by_asset` is a `BTreeMap` and therefore
/// iterated in ascending `AssetId` order.
fn append_global_change_outputs(
    pst: &mut PartiallySignedTransaction,
    signer_address: &Address,
    residual_by_asset: &AssetBalances,
) -> Result<(), WalletAbiError> {
    let change_blinding_key = signer_address.blinding_pubkey.ok_or_else(|| {
        WalletAbiError::InvalidSignerConfig(
            "signer receive address missing blinding pubkey for change output".to_string(),
        )
    })?;

    for (asset_id, residual_sat) in residual_by_asset {
        if *residual_sat == 0 {
            continue;
        }

        pst.add_output(Output::new_explicit(
            signer_address.script_pubkey(),
            *residual_sat,
            *asset_id,
            Some(change_blinding_key.into()),
        ));
    }

    Ok(())
}

/// Apply output `blinder_index` values using the first wallet-finalized input as source.
///
/// Unblinded outputs get `None`; blinded outputs require at least one wallet-finalized input.
fn apply_output_blinder_indices(
    pst: &mut PartiallySignedTransaction,
    wallet_input_indices: &[u32],
) -> Result<(), WalletAbiError> {
    let wallet_blinder_index = wallet_input_indices.first().copied();
    for (output_index, output) in pst.outputs_mut().iter_mut().enumerate() {
        if output.blinding_key.is_none() {
            output.blinder_index = None;
            continue;
        }

        output.blinder_index = Some(wallet_blinder_index.ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "blinded output at index {output_index} requires at least one wallet-finalized input"
            ))
        })?);
    }

    Ok(())
}

/// Final safety check asserting exact per-asset conservation after change materialization.
///
/// This enforces `supply[a] == demand[a]` for every asset `a`.
///
/// ```rust,ignore
/// assert_exact_asset_conservation(&pst, &params)?;
/// ```
fn assert_exact_asset_conservation(
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<(), WalletAbiError> {
    let supply_by_asset = aggregate_input_supply(pst, params)?;
    let demand_by_asset = aggregate_output_demand(pst)?;
    let mut all_assets = BTreeSet::new();
    let mut mismatches = Vec::new();

    all_assets.extend(supply_by_asset.keys().copied());
    all_assets.extend(demand_by_asset.keys().copied());

    for asset_id in all_assets {
        let supply_sat = supply_by_asset.get(&asset_id).copied().unwrap_or(0);
        let demand_sat = demand_by_asset.get(&asset_id).copied().unwrap_or(0);
        if supply_sat != demand_sat {
            mismatches.push(format!(
                "{asset_id}:supply={supply_sat},demand={demand_sat}"
            ));
        }
    }

    if mismatches.is_empty() {
        return Ok(());
    }

    Err(WalletAbiError::InvalidRequest(format!(
        "asset conservation violated after balancing: {}",
        mismatches.join("; ")
    )))
}

impl WalletRuntimeConfig {
    /// Materialize and balance final outputs for an already input-resolved PSET.
    ///
    /// Pipeline:
    /// 1. Materialize outputs from params in order.
    /// 2. Apply fee target.
    /// 3. Build supply/demand equations.
    /// 4. Fail on deficits; otherwise append residual change.
    /// 5. Assign blinder indices and assert exact conservation.
    ///
    /// Safety:
    /// - This stage intentionally keeps hard deficit failure even when input selection is
    ///   fee-aware; it is the final conservation gate before signing.
    ///
    /// # Complexity
    ///
    /// With `I` inputs, `O` outputs and `A` distinct assets, runtime is `O(I + O + A)` and
    /// additional space is `O(A)`.
    pub(super) fn balance_out(
        &self,
        mut pst: PartiallySignedTransaction,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let signer_address = self.signer_receive_address()?;
        let wallet_input_indices = wallet_input_indices(&pst)?;
        let fee_output_index =
            materialize_requested_outputs(&mut pst, params, &signer_address, self.network)?;

        apply_fee_target(
            &mut pst,
            fee_output_index,
            fee_target_sat,
            *self.network.policy_asset(),
        )?;

        let supply_by_asset = aggregate_input_supply(&pst, params)?;
        let demand_by_asset = aggregate_output_demand(&pst)?;
        let delta = compute_balance_delta(&supply_by_asset, &demand_by_asset, fee_target_sat)?;

        append_global_change_outputs(&mut pst, &signer_address, &delta.residual_by_asset)?;
        apply_output_blinder_indices(&mut pst, &wallet_input_indices)?;
        assert_exact_asset_conservation(&pst, params)?;

        Ok(pst)
    }
}
