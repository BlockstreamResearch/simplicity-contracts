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
//!
//! # Doc tests
//!
//! The delta split keeps positive deficits and positive residuals in separate maps:
//!
//! ```rust,ignore
//! use std::collections::BTreeMap;
//! use lwk_wollet::elements::AssetId;
//!
//! let lbtc = AssetId::from_slice(&[1u8; 32]).unwrap();
//! let usdt = AssetId::from_slice(&[2u8; 32]).unwrap();
//!
//! let residual_supply = BTreeMap::from([(lbtc, 15_u64)]);
//! let residual_demand = BTreeMap::from([(lbtc, 10_u64)]);
//! let delta = compute_balance_delta(&residual_supply, &residual_demand, 0).unwrap();
//! assert_eq!(delta.residual_by_asset.get(&lbtc), Some(&5));
//!
//! let deficit_supply = BTreeMap::from([(usdt, 4_u64)]);
//! let deficit_demand = BTreeMap::from([(usdt, 9_u64)]);
//! let err = compute_balance_delta(&deficit_supply, &deficit_demand, 25).unwrap_err();
//! assert!(format!("{err}").contains("fee target 25"));
//! ```
//!
//! Conservation holds when residuals are materialized through output-stage helpers:
//!
//! ```rust,ignore
//! let supply_by_asset = aggregate_input_supply(&pst, &params)?;
//! let demand_by_asset = aggregate_output_demand(&pst)?;
//! let delta = compute_balance_delta(&supply_by_asset, &demand_by_asset, fee_target_sat)?;
//! append_global_change_outputs(&mut pst, &signer_address, &delta.residual_by_asset)?;
//! assert_exact_asset_conservation(&pst, &params)?;
//! ```
//!
//! Formal references:
//! - Elements transaction fee output semantics:
//!   <https://docs.rs/elements/latest/src/elements/transaction.rs.html>
//! - Elements issued-assets conservation context:
//!   <https://elementsproject.org/features/issued-assets/investigation>
//!
use crate::runtime::input_resolution::{add_balance, derive_issuance_entropy};
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
///
/// ```rust,ignore
/// assert!(validate_output_input_index("out0", 0, 1).is_ok());
/// assert!(validate_output_input_index("out0", 1, 1).is_err());
/// ```
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
///
/// ```rust,ignore
/// // The returned order follows PSET input order.
/// let wallet_indices = wallet_input_indices(&pst)?;
/// assert!(wallet_indices.windows(2).all(|w| w[0] < w[1]));
/// ```
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
///
/// ```rust,ignore
/// // Minted issuance supply is included even if no output currently spends it.
/// let issuance_supply = aggregate_issuance_supply(&pst, &params)?;
/// assert!(issuance_supply.values().all(|x| *x >= 0));
/// ```
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
            let is_confidential = pset_input
                .witness_utxo
                .as_ref()
                .is_some_and(|utxo| utxo.asset.is_confidential());
            let token_asset = AssetId::reissuance_token_from_entropy(entropy, is_confidential);
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
///
/// ```rust,ignore
/// let supply = aggregate_input_supply(&pst, &params)?;
/// assert!(supply.len() >= 1);
/// ```
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
///
/// ```rust,ignore
/// let demand = aggregate_output_demand(&pst)?;
/// assert!(demand.values().all(|x| *x > 0));
/// ```
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
///
/// ```rust,ignore
/// let delta = compute_balance_delta(&supply, &demand, fee_target_sat)?;
/// assert!(delta.deficit_by_asset.is_empty());
/// ```
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
/// The returned tuple is `(issuance_metadata, prevout, is_confidential_prevout)`.
fn resolve_issuance_asset_context(
    output_id: &str,
    input_index: u32,
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<(InputIssuance, OutPoint, bool), WalletAbiError> {
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
    let is_confidential = pset_input
        .witness_utxo
        .as_ref()
        .is_some_and(|utxo| utxo.asset.is_confidential());

    Ok((issuance.clone(), outpoint, is_confidential))
}

/// Resolve one output `AssetVariant` into a concrete `AssetId`.
///
/// Issuance-linked variants validate issuance-kind compatibility against the referenced input.
///
/// ```rust,ignore
/// let asset_id = resolve_output_asset("out0", &output.asset, &pst, &params)?;
/// ```
fn resolve_output_asset(
    output_id: &str,
    variant: &AssetVariant,
    pst: &PartiallySignedTransaction,
    params: &RuntimeParams,
) -> Result<AssetId, WalletAbiError> {
    match variant {
        AssetVariant::AssetId { asset_id } => Ok(*asset_id),
        AssetVariant::NewIssuanceAsset { input_index } => {
            let (issuance, outpoint, _) =
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
            let (issuance, outpoint, is_confidential) =
                resolve_issuance_asset_context(output_id, *input_index, pst, params)?;
            if issuance.kind != InputIssuanceKind::New {
                return Err(WalletAbiError::InvalidRequest(format!(
                    "output '{output_id}' new_issuance_token references non-new issuance input index {input_index}"
                )));
            }
            Ok(AssetId::reissuance_token_from_entropy(
                derive_issuance_entropy(outpoint, &issuance),
                is_confidential,
            ))
        }
        AssetVariant::ReIssuanceAsset { input_index } => {
            let (issuance, outpoint, _) =
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
fn resolve_output_lock_script(lock: &LockVariant, signer_address: &Address) -> Script {
    match lock {
        LockVariant::Script { script } => script.clone(),
        LockVariant::Finalizer { finalizer } => match finalizer.as_ref() {
            FinalizerSpec::Wallet => signer_address.script_pubkey(),
            FinalizerSpec::Simf { internal_key, .. } => internal_key.address.script_pubkey(),
        },
    }
}

/// Mutate or append fee output so it matches the requested fee target.
///
/// If `fee_output_index` is `Some(i)`, validates and overwrites that output as explicit fee.
/// Otherwise appends a new explicit fee output.
///
/// ```rust,ignore
/// apply_fee_target(&mut pst, None, 500, policy_asset)?;
/// ```
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
///
/// ```rust,ignore
/// let fee_index = materialize_requested_outputs(&mut pst, &params, &signer_address)?;
/// ```
fn materialize_requested_outputs(
    pst: &mut PartiallySignedTransaction,
    params: &RuntimeParams,
    signer_address: &Address,
) -> Result<Option<usize>, WalletAbiError> {
    let mut fee_output_index = None;

    for output in &params.outputs {
        let asset_id = resolve_output_asset(&output.id, &output.asset, pst, params)?;
        let script = resolve_output_lock_script(&output.lock, signer_address);

        let blinding_key: Option<PublicKey> = match output.blinder {
            BlinderVariant::Wallet => Some(
                signer_address
                    .blinding_pubkey
                    .expect("CT descriptor always has blinder")
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
///
/// ```rust,ignore
/// append_global_change_outputs(&mut pst, &signer_address, &delta.residual_by_asset)?;
/// ```
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
///
/// ```rust,ignore
/// let wallet_indices = wallet_input_indices(&pst)?;
/// apply_output_blinder_indices(&mut pst, &wallet_indices)?;
/// ```
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
        let fee_output_index = materialize_requested_outputs(&mut pst, params, &signer_address)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_pubkey_gen::TaprootPubkeyGen;
    use crate::{
        BlinderVariant, InputSchema, LockVariant, Network, OutputSchema, ProgramError, UTXOSource,
        WalletSourceFilter,
    };

    use std::str::FromStr;

    use lwk_wollet::bitcoin::PublicKey as BitcoinPublicKey;
    use lwk_wollet::elements::Txid;
    use lwk_wollet::elements::address::AddressParams;
    use lwk_wollet::elements::hashes::Hash;
    use lwk_wollet::elements::pset::Input;
    use lwk_wollet::elements::secp256k1_zkp;
    use simplicityhl::elements::Address as SimplicityAddress;
    use simplicityhl::elements::schnorr::{Keypair, XOnlyPublicKey};
    use simplicityhl::elements::secp256k1_zkp::{SECP256K1, SecretKey};
    use simplicityhl::simplicity::bitcoin::PublicKey as SimplicityPublicKey;
    use simplicityhl::simplicity::bitcoin::key::Parity;

    fn test_asset(tag: u8) -> AssetId {
        AssetId::from_slice(&[tag; 32]).expect("asset id from fixed bytes")
    }

    fn test_outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint::new(
            Txid::from_slice(&[tag; 32]).expect("txid from fixed bytes"),
            vout,
        )
    }

    fn test_signer_address() -> Address {
        let spend_pk = BitcoinPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("valid spend key");
        let blinder = secp256k1_zkp::PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85a8554c0a6af1c70f6f82f0e2f7f3b7a",
        )
        .expect("valid blinder key");

        Address::p2wpkh(&spend_pk, Some(blinder), &AddressParams::ELEMENTS)
    }

    fn wallet_finalizer_input(outpoint: OutPoint, asset: AssetId, amount_sat: u64) -> Input {
        let mut input = Input::from_prevout(outpoint);
        input.amount = Some(amount_sat);
        input.asset = Some(asset);
        input
            .proprietary
            .insert(get_finalizer_spec_key(), FinalizerSpec::Wallet.encode());
        input
    }

    struct TaprootTestArgs;

    fn p2pk_address_for_key(
        xonly: &XOnlyPublicKey,
        _args: &TaprootTestArgs,
        network: Network,
    ) -> Result<SimplicityAddress, ProgramError> {
        crate::get_p2pk_address(xonly, network)
    }

    fn simf_finalizer_for_tests() -> FinalizerSpec {
        let args = TaprootTestArgs;
        let secret = SecretKey::from_slice(&[0x12; 32]).expect("secret key");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        let xonly = keypair.x_only_public_key().0;
        let pubkey: SimplicityPublicKey = xonly.public_key(Parity::Even).into();
        let address =
            p2pk_address_for_key(&xonly, &args, Network::TestnetLiquid).expect("taproot address");
        let encoded = format!(
            "ext-{}:{}:{}",
            hex::encode(xonly.serialize()),
            pubkey,
            address
        );
        let taproot = TaprootPubkeyGen::build_from_str(
            &encoded,
            &args,
            Network::TestnetLiquid,
            &p2pk_address_for_key,
        )
        .expect("taproot pubkey generator");

        FinalizerSpec::Simf {
            source_simf: "tests.simf".to_string(),
            internal_key: Box::new(taproot),
            arguments: Vec::new(),
            witness: Vec::new(),
        }
    }

    fn explicit_output_schema(id: &str, asset_id: AssetId, amount_sat: u64) -> OutputSchema {
        OutputSchema {
            id: id.to_string(),
            amount_sat,
            lock: LockVariant::Script {
                script: Script::new(),
            },
            asset: AssetVariant::AssetId { asset_id },
            blinder: BlinderVariant::Explicit,
        }
    }

    fn params_with_inputs(inputs_len: usize) -> RuntimeParams {
        RuntimeParams {
            inputs: (0..inputs_len)
                .map(|idx| InputSchema {
                    id: format!("input-{idx}"),
                    utxo_source: UTXOSource::Wallet {
                        filter: WalletSourceFilter::default(),
                    },
                    ..InputSchema::new(format!("input-{idx}"))
                })
                .collect(),
            outputs: Vec::new(),
            fee_rate_sat_vb: None,
            locktime: None,
        }
    }

    #[test]
    fn exact_balance_has_no_deficit_or_residual() {
        let asset_id = test_asset(1);
        let supply = AssetBalances::from([(asset_id, 100)]);
        let demand = AssetBalances::from([(asset_id, 100)]);

        let delta = compute_balance_delta(&supply, &demand, 0).expect("balanced equation");

        assert!(delta.deficit_by_asset.is_empty());
        assert!(delta.residual_by_asset.is_empty());
    }

    #[test]
    fn fee_deficit_returns_funding_error_with_policy_asset_details() {
        let policy_asset = test_asset(2);
        let supply = AssetBalances::from([(policy_asset, 50)]);
        let demand = AssetBalances::from([(policy_asset, 65)]);

        let err = compute_balance_delta(&supply, &demand, 25).expect_err("deficit expected");
        match err {
            WalletAbiError::Funding(message) => {
                assert!(message.contains("fee target 25"));
                assert!(message.contains(&policy_asset.to_string()));
                assert!(message.contains(":15"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn global_residual_includes_non_wallet_surplus_and_blinds_change() {
        let policy_asset = test_asset(3);
        let non_wallet_asset = test_asset(4);
        let mut pst = PartiallySignedTransaction::new_v2();

        let wallet_input = wallet_finalizer_input(test_outpoint(1, 0), policy_asset, 10);
        pst.add_input(wallet_input);

        let mut non_wallet_input = Input::from_prevout(test_outpoint(2, 0));
        non_wallet_input.amount = Some(30);
        non_wallet_input.asset = Some(non_wallet_asset);
        non_wallet_input.proprietary.insert(
            get_finalizer_spec_key(),
            simf_finalizer_for_tests().encode(),
        );
        pst.add_input(non_wallet_input);

        pst.add_output(Output::new_explicit(Script::new(), 10, policy_asset, None));

        let params = params_with_inputs(2);
        let supply = aggregate_input_supply(&pst, &params).expect("input supply");
        let demand = aggregate_output_demand(&pst).expect("output demand");
        let delta = compute_balance_delta(&supply, &demand, 0).expect("no deficit");
        assert_eq!(delta.residual_by_asset.get(&non_wallet_asset), Some(&30));

        let signer = test_signer_address();
        append_global_change_outputs(&mut pst, &signer, &delta.residual_by_asset)
            .expect("append change");
        let wallet_indices = wallet_input_indices(&pst).expect("wallet indices");
        assert_eq!(wallet_indices, vec![0]);
        apply_output_blinder_indices(&mut pst, &wallet_indices).expect("blinder indices");

        let change_output = pst
            .outputs()
            .iter()
            .find(|output| output.asset == Some(non_wallet_asset))
            .expect("change output for non-wallet asset");
        assert_eq!(change_output.amount, Some(30));
        assert!(change_output.blinding_key.is_some());
        assert_eq!(change_output.blinder_index, Some(0));
    }

    #[test]
    fn issuance_surplus_becomes_change_in_deterministic_asset_order() {
        let base_asset = test_asset(5);
        let issuance = InputIssuance {
            kind: InputIssuanceKind::New,
            asset_amount_sat: 40,
            token_amount_sat: 15,
            entropy: [9; 32],
        };
        let outpoint = test_outpoint(3, 1);

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(wallet_finalizer_input(outpoint, base_asset, 10));
        pst.add_output(Output::new_explicit(Script::new(), 10, base_asset, None));

        let mut input_schema = InputSchema::new("input-0");
        input_schema.issuance = Some(issuance.clone());
        let params = RuntimeParams {
            inputs: vec![input_schema],
            outputs: Vec::new(),
            fee_rate_sat_vb: None,
            locktime: None,
        };

        let supply = aggregate_input_supply(&pst, &params).expect("input supply");
        let demand = aggregate_output_demand(&pst).expect("output demand");
        let delta = compute_balance_delta(&supply, &demand, 0).expect("no deficit");

        let entropy = derive_issuance_entropy(outpoint, &issuance);
        let issuance_asset = AssetId::from_entropy(entropy);
        let issuance_token = AssetId::reissuance_token_from_entropy(entropy, false);
        assert_eq!(delta.residual_by_asset.get(&issuance_asset), Some(&40));
        assert_eq!(delta.residual_by_asset.get(&issuance_token), Some(&15));

        let signer = test_signer_address();
        append_global_change_outputs(&mut pst, &signer, &delta.residual_by_asset)
            .expect("append change");

        let expected_assets: Vec<AssetId> = delta.residual_by_asset.keys().copied().collect();
        let change_assets: Vec<AssetId> = pst
            .outputs()
            .iter()
            .skip(1)
            .map(|output| output.asset.expect("explicit change asset"))
            .collect();
        assert_eq!(change_assets, expected_assets);
    }

    #[test]
    fn duplicate_fee_output_id_is_rejected() {
        let policy_asset = test_asset(6);
        let params = RuntimeParams {
            inputs: Vec::new(),
            outputs: vec![
                explicit_output_schema("fee", policy_asset, 1),
                explicit_output_schema("fee", policy_asset, 2),
            ],
            fee_rate_sat_vb: None,
            locktime: None,
        };
        let mut pst = PartiallySignedTransaction::new_v2();
        let signer = test_signer_address();

        let err = materialize_requested_outputs(&mut pst, &params, &signer)
            .expect_err("duplicate fee id");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("duplicate output id 'fee'"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn missing_fee_output_adds_explicit_policy_fee_output() {
        let policy_asset = test_asset(7);
        let mut pst = PartiallySignedTransaction::new_v2();

        apply_fee_target(&mut pst, None, 777, policy_asset).expect("fee output appended");

        assert_eq!(pst.outputs().len(), 1);
        let fee_output = &pst.outputs()[0];
        assert_eq!(fee_output.script_pubkey, Script::new());
        assert_eq!(fee_output.amount, Some(777));
        assert_eq!(fee_output.asset, Some(policy_asset));
        assert!(fee_output.blinding_key.is_none());
        assert!(fee_output.blinder_index.is_none());
    }

    #[test]
    fn blinded_outputs_require_wallet_finalized_input_index() {
        let policy_asset = test_asset(8);
        let blinded_key = BitcoinPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("valid blinded output key");
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_output(Output::new_explicit(
            Script::new(),
            5,
            policy_asset,
            Some(blinded_key),
        ));

        let err = apply_output_blinder_indices(&mut pst, &[]).expect_err("wallet input required");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("requires at least one wallet-finalized input"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn aggregate_input_supply_detects_overflow() {
        let overflow_asset = test_asset(9);
        let mut pst = PartiallySignedTransaction::new_v2();

        let mut input_a = Input::from_prevout(test_outpoint(10, 0));
        input_a.asset = Some(overflow_asset);
        input_a.amount = Some(u64::MAX);
        pst.add_input(input_a);

        let mut input_b = Input::from_prevout(test_outpoint(11, 0));
        input_b.asset = Some(overflow_asset);
        input_b.amount = Some(1);
        pst.add_input(input_b);

        let params = params_with_inputs(2);
        let err = aggregate_input_supply(&pst, &params).expect_err("overflow should fail");

        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("overflow"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn final_asset_conservation_check_passes_for_balanced_pset() {
        let asset_id = test_asset(12);
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(wallet_finalizer_input(test_outpoint(12, 0), asset_id, 100));
        pst.add_output(Output::new_explicit(Script::new(), 100, asset_id, None));

        let params = params_with_inputs(1);
        assert_exact_asset_conservation(&pst, &params).expect("exact conservation");
    }
}
