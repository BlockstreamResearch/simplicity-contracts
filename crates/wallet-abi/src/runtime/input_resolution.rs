//! Input resolution for transaction construction.
//!
//! This module balances the input/output equation in four phases:
//! 1. Build demand from all requested outputs (including fee outputs).
//! 2. Resolve declared inputs in order.
//! 3. Materialize deferred issuance-linked output demand when referenced inputs are known.
//! 4. Add auxiliary wallet inputs until every positive asset deficit is closed.
//!
//! # Complexity
//!
//! Let:
//! - `O` = number of outputs
//! - `I` = number of declared inputs
//! - `U` = wallet UTXO count in snapshot
//! - `A` = number of distinct demanded assets
//! - `K` = number of auxiliary inputs added
//!
//! Worst-case time is `O((I + K) * U * A + O + I)`, dominated by repeated scored UTXO
//! selection scans. Space is `O(U + A + O)` for used-outpoint tracking and equation state.
//!
//! # Doc tests
//!
//! The deficit map keeps only positive `(demand - supply)` entries:
//!
//! ```rust,ignore
//! use std::collections::BTreeMap;
//!
//! let demand = BTreeMap::from([("L-BTC", 8), ("USDT", 12)]);
//! let supply = BTreeMap::from([("L-BTC", 3), ("USDT", 12)]);
//! let d = current_deficits(&demand, &supply);
//! assert_eq!(d.get("L-BTC"), Some(&5));
//! assert!(!d.contains_key("USDT"));
//! ```
//!
//! Candidate ranking is lexicographic and deterministic:
//!
//! ```rust
//! #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
//! struct Score(u64, u64, u64, String, u32);
//!
//! let a = Score(10, 2, 1, "00aa".to_string(), 0);
//! let b = Score(10, 2, 1, "00aa".to_string(), 1);
//! assert!(a < b);
//! ```
//!

use crate::runtime::params::RuntimeParamsEnvelope;
use crate::runtime::WalletRuntimeConfig;
use crate::{
    AmountFilter, AssetFilter, AssetVariant, InputBlinder, InputIssuance, InputIssuanceKind,
    InputSchema, LockFilter, UTXOSource, WalletAbiError, WalletSourceFilter,
};

use std::collections::{BTreeMap, HashMap, HashSet};

use lwk_wollet::elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use lwk_wollet::elements::hashes::Hash;
use lwk_wollet::elements::pset::{Input, PartiallySignedTransaction};
use lwk_wollet::elements::{secp256k1_zkp, AssetId, ContractHash, OutPoint, TxOut, TxOutSecrets};
use lwk_wollet::{WalletTxOut, EC};

type CandidateScore = (u64, u64, u64, String, u32);

type Midstate = lwk_wollet::elements::hashes::sha256::Midstate;

#[derive(Clone, Copy)]
enum DeferredDemandKind {
    NewIssuanceAsset,
    NewIssuanceToken,
    ReIssuanceAsset,
}

#[derive(Default)]
struct ResolutionState {
    used_outpoints: HashSet<OutPoint>,
    demand_by_asset: BTreeMap<AssetId, u64>,
    supply_by_asset: BTreeMap<AssetId, u64>,
    deferred_demands: HashMap<u32, Vec<(DeferredDemandKind, u64)>>,
}

struct ResolvedInputMaterial {
    outpoint: OutPoint,
    tx_out: TxOut,
    secrets: TxOutSecrets,
    is_confidential: bool,
}

/// Add `amount_sat` to one asset bucket with overflow protection.
///
/// ```rust,ignore
/// use std::collections::BTreeMap;
///
/// let mut balances = BTreeMap::new();
/// add_balance(&mut balances, "L-BTC", 10).unwrap();
/// add_balance(&mut balances, "L-BTC", 2).unwrap();
/// assert_eq!(balances.get("L-BTC"), Some(&12));
/// ```
fn add_balance(
    map: &mut BTreeMap<AssetId, u64>,
    asset_id: AssetId,
    amount_sat: u64,
) -> Result<(), WalletAbiError> {
    let entry = map.entry(asset_id).or_insert(0);
    *entry = entry.checked_add(amount_sat).ok_or_else(|| {
        WalletAbiError::InvalidRequest(format!(
            "asset amount overflow while aggregating balances for {asset_id}"
        ))
    })?;
    Ok(())
}

/// Compute positive deficits `(demand - supply)` per asset.
///
/// ```rust,ignore
/// use std::collections::BTreeMap;
///
/// let demand = BTreeMap::from([("L-BTC", 9), ("USDT", 5)]);
/// let supply = BTreeMap::from([("L-BTC", 4), ("USDT", 5)]);
/// let d = current_deficits(&demand, &supply);
/// assert_eq!(d, BTreeMap::from([("L-BTC", 5)]));
/// ```
fn current_deficits(
    demand_by_asset: &BTreeMap<AssetId, u64>,
    supply_by_asset: &BTreeMap<AssetId, u64>,
) -> BTreeMap<AssetId, u64> {
    // Deficits are kept only for assets where demand is still strictly above supply.
    let mut deficits = BTreeMap::new();
    for (asset_id, demand_sat) in demand_by_asset {
        let supplied = supply_by_asset.get(asset_id).copied().unwrap_or(0);
        if *demand_sat > supplied {
            deficits.insert(*asset_id, demand_sat - supplied);
        }
    }
    deficits
}

/// Reserve an outpoint and fail if it was already used.
///
/// ```rust,ignore
/// use std::collections::HashSet;
///
/// let mut used = HashSet::new();
/// assert!(reserve(&mut used, (1, 0)).is_ok());
/// assert!(reserve(&mut used, (1, 0)).is_err());
/// ```
fn reserve_outpoint(
    used_outpoints: &mut HashSet<OutPoint>,
    input_id: &str,
    outpoint: OutPoint,
) -> Result<(), WalletAbiError> {
    if used_outpoints.insert(outpoint) {
        return Ok(());
    }

    Err(WalletAbiError::InvalidRequest(format!(
        "duplicate input outpoint resolved for '{}': {}:{}",
        input_id, outpoint.txid, outpoint.vout
    )))
}

/// Validate that an output reference points to an existing declared input index.
///
/// ```rust,ignore
///
/// assert!(validate(0, 1).is_ok());
/// assert!(validate(1, 1).is_err());
/// ```
fn validate_output_input_index(
    output_id: &str,
    input_index: u32,
    input_count: usize,
) -> Result<(), WalletAbiError> {
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

    Ok(())
}

/// Compute issuance entropy from input outpoint and issuance kind.
///
/// ```rust,ignore
///
/// let base = [7u8; 32];
/// assert_eq!(derive(3, InputIssuanceKind::Reissue(base)), base);
/// assert_ne!(derive(3, InputIssuanceKind::New(base)), base);
/// ```
fn derive_issuance_entropy(outpoint: OutPoint, issuance: &InputIssuance) -> Midstate {
    match issuance.kind {
        InputIssuanceKind::New => AssetId::generate_asset_entropy(
            outpoint,
            ContractHash::from_byte_array(issuance.entropy),
        ),
        InputIssuanceKind::Reissue => Midstate::from_byte_array(issuance.entropy),
    }
}

/// Resolve a deferred issuance-linked output demand into a concrete asset id.
fn demand_asset_from_deferred(
    kind: DeferredDemandKind,
    issuance: &InputIssuance,
    material: &ResolvedInputMaterial,
    input_id: &str,
) -> Result<AssetId, WalletAbiError> {
    match (kind, &issuance.kind) {
        (DeferredDemandKind::NewIssuanceAsset, InputIssuanceKind::New) => Ok(
            AssetId::from_entropy(derive_issuance_entropy(material.outpoint, issuance)),
        ),
        (DeferredDemandKind::NewIssuanceToken, InputIssuanceKind::New) => {
            Ok(AssetId::reissuance_token_from_entropy(
                derive_issuance_entropy(material.outpoint, issuance),
                material.is_confidential,
            ))
        }
        (DeferredDemandKind::ReIssuanceAsset, InputIssuanceKind::Reissue) => Ok(
            AssetId::from_entropy(derive_issuance_entropy(material.outpoint, issuance)),
        ),
        (DeferredDemandKind::NewIssuanceAsset, InputIssuanceKind::Reissue) => {
            Err(WalletAbiError::InvalidRequest(format!(
                "output asset variant new_issuance_asset references reissue input '{input_id}'"
            )))
        }
        (DeferredDemandKind::NewIssuanceToken, InputIssuanceKind::Reissue) => {
            Err(WalletAbiError::InvalidRequest(format!(
                "output asset variant new_issuance_token references reissue input '{input_id}'"
            )))
        }
        (DeferredDemandKind::ReIssuanceAsset, InputIssuanceKind::New) => {
            Err(WalletAbiError::InvalidRequest(format!(
                "output asset variant re_issuance_asset references new issuance input '{input_id}'"
            )))
        }
    }
}

/// Populate issuance-related PSET input fields from request metadata.
fn apply_issuance_to_pset_input(
    pset_input: &mut Input,
    issuance: &InputIssuance,
    secrets: &TxOutSecrets,
) -> Result<(), WalletAbiError> {
    pset_input.issuance_value_amount = if issuance.asset_amount_sat == 0 {
        None
    } else {
        Some(issuance.asset_amount_sat)
    };
    pset_input.issuance_asset_entropy = Some(issuance.entropy);
    pset_input.issuance_inflation_keys = if issuance.token_amount_sat == 0 {
        None
    } else {
        Some(issuance.token_amount_sat)
    };

    if let InputIssuanceKind::Reissue = issuance.kind {
        // TODO: investigate the purpose of this field, and make it functionally correct.
        let mut nonce = secrets.asset_bf.into_inner();
        if nonce == secp256k1_zkp::ZERO_TWEAK {
            let mut one = [0u8; 32];
            one[0] = 1;
            nonce = secp256k1_zkp::Tweak::from_slice(&one).expect("tweak from [0,..,1] is correct")
        }
        pset_input.issuance_blinding_nonce = Some(nonce);
    }

    pset_input.blinded_issuance = Some(0x00);

    Ok(())
}

/// Check whether a wallet UTXO candidate satisfies source filters and is unused.
fn matches_wallet_filter(
    candidate: &WalletTxOut,
    filter: &WalletSourceFilter,
    used_outpoints: &HashSet<OutPoint>,
) -> bool {
    if used_outpoints.contains(&candidate.outpoint) {
        return false;
    }

    let asset_ok = match filter.asset {
        AssetFilter::None => true,
        AssetFilter::Exact { asset_id } => candidate.unblinded.asset == asset_id,
    };
    if !asset_ok {
        return false;
    }

    let amount_ok = match filter.amount {
        AmountFilter::None => true,
        AmountFilter::Exact { satoshi } => candidate.unblinded.value == satoshi,
        AmountFilter::Min { satoshi } => candidate.unblinded.value >= satoshi,
    };
    if !amount_ok {
        return false;
    }

    match &filter.lock {
        LockFilter::None => true,
        LockFilter::Script { script } => candidate.script_pubkey == *script,
    }
}

/// Score one candidate by simulating its supply contribution.
///
/// Lower score tuple is better.
fn score_candidate(
    candidate: &WalletTxOut,
    demand_by_asset: &BTreeMap<AssetId, u64>,
    supply_by_asset: &BTreeMap<AssetId, u64>,
) -> Result<CandidateScore, WalletAbiError> {
    // Simulate adding this candidate to the current supply map, then compute a
    // deterministic lexicographic score that favors candidates which reduce deficits fastest.
    let mut simulated_supply = supply_by_asset.clone();
    let current_supply = simulated_supply
        .get(&candidate.unblinded.asset)
        .copied()
        .unwrap_or(0);
    let updated_supply = current_supply
        .checked_add(candidate.unblinded.value)
        .ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "asset amount overflow while scoring candidate {}:{}",
                candidate.outpoint.txid, candidate.outpoint.vout
            ))
        })?;
    simulated_supply.insert(candidate.unblinded.asset, updated_supply);

    let mut total_remaining_deficit = 0u64;
    for (asset_id, demand_sat) in demand_by_asset {
        let supplied = simulated_supply.get(asset_id).copied().unwrap_or(0);
        let remaining = demand_sat.saturating_sub(supplied);
        total_remaining_deficit =
            total_remaining_deficit
                .checked_add(remaining)
                .ok_or_else(|| {
                    WalletAbiError::InvalidRequest(
                        "deficit overflow while scoring wallet candidates".to_string(),
                    )
                })?;
    }

    let candidate_demand = demand_by_asset
        .get(&candidate.unblinded.asset)
        .copied()
        .unwrap_or(0);
    let candidate_before_supply = supply_by_asset
        .get(&candidate.unblinded.asset)
        .copied()
        .unwrap_or(0);
    let candidate_after_supply = simulated_supply
        .get(&candidate.unblinded.asset)
        .copied()
        .unwrap_or(0);

    let remaining_candidate_deficit = candidate_demand.saturating_sub(candidate_after_supply);
    let needed_before = candidate_demand.saturating_sub(candidate_before_supply);
    let overshoot_or_undershoot = candidate.unblinded.value.abs_diff(needed_before);

    Ok((
        total_remaining_deficit,
        remaining_candidate_deficit,
        overshoot_or_undershoot,
        candidate.outpoint.txid.to_string(),
        candidate.outpoint.vout,
    ))
}

impl WalletRuntimeConfig {
    /// Build demand from output specs and store issuance-linked entries as deferred.
    fn resolve_output_demands(
        &self,
        params: &RuntimeParamsEnvelope,
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Convert output-level asset requirements into equation demand.
        // Issuance-derived outputs are deferred until their referenced input is resolved.
        for output in &params.outputs {
            match &output.asset {
                AssetVariant::AssetId { asset_id } => {
                    add_balance(&mut state.demand_by_asset, *asset_id, output.amount_sat)?;
                }
                AssetVariant::NewIssuanceAsset { input_index } => {
                    validate_output_input_index(&output.id, *input_index, params.inputs.len())?;
                    state
                        .deferred_demands
                        .entry(*input_index)
                        .or_default()
                        .push((DeferredDemandKind::NewIssuanceAsset, output.amount_sat));
                }
                AssetVariant::NewIssuanceToken { input_index } => {
                    validate_output_input_index(&output.id, *input_index, params.inputs.len())?;
                    state
                        .deferred_demands
                        .entry(*input_index)
                        .or_default()
                        .push((DeferredDemandKind::NewIssuanceToken, output.amount_sat));
                }
                AssetVariant::ReIssuanceAsset { input_index } => {
                    validate_output_input_index(&output.id, *input_index, params.inputs.len())?;
                    state
                        .deferred_demands
                        .entry(*input_index)
                        .or_default()
                        .push((DeferredDemandKind::ReIssuanceAsset, output.amount_sat));
                }
            }
        }

        Ok(())
    }

    /// Resolve input material from a provided outpoint and optional blinder hints.
    fn resolve_provided_input_material(
        &self,
        input: &InputSchema,
        outpoint: OutPoint,
        state: &mut ResolutionState,
    ) -> Result<ResolvedInputMaterial, WalletAbiError> {
        reserve_outpoint(&mut state.used_outpoints, &input.id, outpoint)?;

        let tx_out = self.fetch_tx_out(&outpoint)?;

        let (secrets, is_confidential) = match &input.blinder {
            InputBlinder::Wallet => {
                let (_, unblinded) = self.unblind_with_wallet(tx_out.clone())?;

                (unblinded, true)
            }
            InputBlinder::Provided { secret_key } => {
                let unblinded = tx_out.unblind(&EC, *secret_key).map_err(|error| {
                    WalletAbiError::InvalidRequest(format!(
                        "unable to unblind input '{}' with provided blinder: {error}",
                        input.id
                    ))
                })?;

                (unblinded, true)
            }
            InputBlinder::Explicit => {
                let (Asset::Explicit(asset), Value::Explicit(value)) = (tx_out.asset, tx_out.value)
                else {
                    return Err(WalletAbiError::InvalidRequest(format!(
                        "marked input '{}' as explicit when the confidential was provided",
                        input.id
                    )));
                };

                (
                    TxOutSecrets {
                        asset,
                        asset_bf: AssetBlindingFactor::zero(),
                        value,
                        value_bf: ValueBlindingFactor::zero(),
                    },
                    false,
                )
            }
        };

        Ok(ResolvedInputMaterial {
            outpoint,
            tx_out,
            secrets,
            is_confidential,
        })
    }

    /// Resolve input material from wallet snapshot using deficit-aware selection.
    fn resolve_wallet_input_material(
        &self,
        input: &InputSchema,
        filter: &WalletSourceFilter,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
    ) -> Result<ResolvedInputMaterial, WalletAbiError> {
        let selected = self
            .filter_tx_out(
                wallet_snapshot,
                filter,
                &state.used_outpoints,
                &state.demand_by_asset,
                &state.supply_by_asset,
            )?
            .ok_or_else(|| {
                WalletAbiError::Funding(format!(
                    "no wallet UTXO matched contract input '{}' filter",
                    input.id
                ))
            })?;

        reserve_outpoint(&mut state.used_outpoints, &input.id, selected.outpoint)?;

        let tx_out = self.fetch_tx_out(&selected.outpoint)?;
        let is_confidential = tx_out.asset.is_confidential();

        Ok(ResolvedInputMaterial {
            outpoint: selected.outpoint,
            tx_out,
            secrets: selected.unblinded,
            is_confidential,
        })
    }

    /// Resolve one declared input from either provided or wallet source.
    fn resolve_declared_input_material(
        &self,
        input: &InputSchema,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
    ) -> Result<ResolvedInputMaterial, WalletAbiError> {
        match &input.utxo_source {
            UTXOSource::Wallet { filter } => {
                self.resolve_wallet_input_material(input, filter, wallet_snapshot, state)
            }
            UTXOSource::Provided { outpoint } => {
                self.resolve_provided_input_material(input, *outpoint, state)
            }
        }
    }

    /// Append a resolved input to the PSET and attach sequence, prevout and witness UTXO.
    fn add_resolved_input_to_pset(
        &self,
        pst: &mut PartiallySignedTransaction,
        input: &InputSchema,
        material: &ResolvedInputMaterial,
    ) -> Result<(), WalletAbiError> {
        let mut pset_input = Input::from_prevout(material.outpoint);
        pset_input.sequence = Some(input.sequence);
        pset_input.witness_utxo = Some(material.tx_out.clone());

        if let Some(issuance) = input.issuance.as_ref() {
            apply_issuance_to_pset_input(&mut pset_input, issuance, &material.secrets)?;
        }

        pst.add_input(pset_input);

        Ok(())
    }

    /// Apply the resolved input contribution to equation supply (base + issuance minting).
    fn apply_input_supply(
        &self,
        input: &InputSchema,
        material: &ResolvedInputMaterial,
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        add_balance(
            &mut state.supply_by_asset,
            material.secrets.asset,
            material.secrets.value,
        )?;

        if let Some(issuance) = input.issuance.as_ref() {
            let issuance_entropy = derive_issuance_entropy(material.outpoint, issuance);
            let issuance_asset = AssetId::from_entropy(issuance_entropy);
            add_balance(
                &mut state.supply_by_asset,
                issuance_asset,
                issuance.asset_amount_sat,
            )?;

            if issuance.token_amount_sat > 0 {
                let token_asset = AssetId::reissuance_token_from_entropy(
                    issuance_entropy,
                    material.is_confidential,
                );
                add_balance(
                    &mut state.supply_by_asset,
                    token_asset,
                    issuance.token_amount_sat,
                )?;
            }
        }

        Ok(())
    }

    /// Convert deferred issuance-linked demand into concrete asset demand for one input index.
    fn activate_deferred_demands_for_input(
        &self,
        input_index: usize,
        input: &InputSchema,
        material: &ResolvedInputMaterial,
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Deferred demands become concrete once the referenced input is known,
        // because issuance-derived asset ids depend on that input outpoint/entropy.
        let Some(entries) = state.deferred_demands.remove(&(input_index as u32)) else {
            return Ok(());
        };

        let issuance = input.issuance.as_ref().ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "output asset references input {} but input '{}' has no issuance metadata",
                input_index, input.id
            ))
        })?;

        for (kind, amount_sat) in entries {
            let demand_asset = demand_asset_from_deferred(kind, issuance, material, &input.id)?;
            add_balance(&mut state.demand_by_asset, demand_asset, amount_sat)?;
        }

        Ok(())
    }

    /// Resolve all declared inputs in order and mutate both PSET and equation state.
    fn resolve_declared_inputs(
        &self,
        pst: &mut PartiallySignedTransaction,
        params: &RuntimeParamsEnvelope,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Main declared-input pass:
        // resolve source -> append PSET input -> increase supply -> unlock deferred demands.
        for (input_index, input) in params.inputs.iter().enumerate() {
            let material = self.resolve_declared_input_material(input, wallet_snapshot, state)?;

            self.add_resolved_input_to_pset(pst, input, &material)?;
            self.apply_input_supply(input, &material, state)?;
            self.activate_deferred_demands_for_input(input_index, input, &material, state)?;
        }

        Ok(())
    }

    /// Pick the currently largest positive deficit asset (tie-break by asset id ordering).
    fn pick_largest_deficit_asset(state: &ResolutionState) -> Option<(AssetId, u64)> {
        current_deficits(&state.demand_by_asset, &state.supply_by_asset)
            .iter()
            .fold(
                None,
                |best: Option<(AssetId, u64)>, (asset, missing)| match best {
                    None => Some((*asset, *missing)),
                    Some((best_asset, best_missing)) => {
                        if *missing > best_missing
                            || (*missing == best_missing && *asset < best_asset)
                        {
                            Some((*asset, *missing))
                        } else {
                            Some((best_asset, best_missing))
                        }
                    }
                },
            )
    }

    /// Add one auxiliary wallet input targeting a specific missing asset amount.
    fn add_auxiliary_input_for_asset(
        &self,
        pst: &mut PartiallySignedTransaction,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
        target_asset: AssetId,
        target_missing: u64,
    ) -> Result<(), WalletAbiError> {
        // Auxiliary funding pass for one deficit asset.
        // We re-use the same scored wallet selector with a relaxed asset-only filter.
        let aux_filter = WalletSourceFilter {
            asset: AssetFilter::Exact {
                asset_id: target_asset,
            },
            amount: AmountFilter::None,
            lock: LockFilter::None,
        };

        let selected = self
            .filter_tx_out(
                wallet_snapshot,
                &aux_filter,
                &state.used_outpoints,
                &state.demand_by_asset,
                &state.supply_by_asset,
            )?
            .ok_or_else(|| {
                WalletAbiError::Funding(
                    "unable to cover remaining deficits with wallet utxos".to_string(),
                )
            })?;

        if !state.used_outpoints.insert(selected.outpoint) {
            return Err(WalletAbiError::InvalidRequest(format!(
                "duplicate auxiliary outpoint resolved: {}:{}",
                selected.outpoint.txid, selected.outpoint.vout
            )));
        }

        let tx_out = self.fetch_tx_out(&selected.outpoint)?;
        let mut pset_input = Input::from_prevout(selected.outpoint);
        pset_input.witness_utxo = Some(tx_out);
        pst.add_input(pset_input);

        add_balance(
            &mut state.supply_by_asset,
            selected.unblinded.asset,
            selected.unblinded.value,
        )?;

        let remaining_target = state
            .demand_by_asset
            .get(&target_asset)
            .copied()
            .unwrap_or(0)
            .saturating_sub(
                state
                    .supply_by_asset
                    .get(&target_asset)
                    .copied()
                    .unwrap_or(0),
            );

        if remaining_target >= target_missing {
            return Err(WalletAbiError::Funding(
                "unable to make progress while covering remaining deficits".to_string(),
            ));
        }

        Ok(())
    }

    /// Repeatedly add auxiliary wallet inputs until there is no remaining positive deficit.
    fn add_auxiliary_inputs_until_balanced(
        &self,
        pst: &mut PartiallySignedTransaction,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Keep injecting auxiliary inputs until the equation has no remaining positive deficits.
        while let Some((target_asset, target_missing)) = Self::pick_largest_deficit_asset(state) {
            self.add_auxiliary_input_for_asset(
                pst,
                wallet_snapshot,
                state,
                target_asset,
                target_missing,
            )?;
        }

        Ok(())
    }

    /// Resolve all inputs required to satisfy output demand, including issuance-derived demand.
    ///
    /// The algorithm first consumes declared inputs, then greedily appends auxiliary wallet
    /// inputs until the equation has no positive deficits.
    ///
    /// Fee nuance:
    /// - This resolver does not special-case fees.
    /// - Any fee output already present in `params.outputs` is treated like regular demand
    ///   (typically policy-asset demand) and must be funded by resolved inputs.
    ///
    /// Change nuance:
    /// - This resolver does not create or place change outputs.
    /// - It guarantees only `supply >= demand` per asset after resolution.
    /// - Any surplus created by UTXO granularity/overshoot is left for the output/change stage
    ///   to materialize as explicit change if for of separate UTXO.
    ///
    /// # Complexity
    ///
    /// Let `I` be declared inputs, `U` wallet UTXOs, `A` demanded assets, and `K` auxiliary
    /// inputs added. Worst-case time is `O((I + K) * U * A + I)` and space is `O(U + A + I)`.
    pub(super) fn resolve_inputs(
        &self,
        pst: PartiallySignedTransaction,
        params: &RuntimeParamsEnvelope,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        // Phase 1: initialize demand/supply state and load wallet snapshot once.
        // We keep all equation state in a dedicated struct so each phase mutates a single object.
        let mut pst = pst;
        let wallet_snapshot = self.wollet.utxos()?;
        let mut state = ResolutionState::default();

        // Phase 2: build output demand from AssetVariant.
        // AssetId contributes directly, while issuance-linked variants are deferred until their
        // referenced input is resolved and its issuance entropy is known.
        self.resolve_output_demands(params, &mut state)?;

        // Phase 3: resolve declared inputs in order.
        // Each input updates the PSET, contributes supply, and may unlock deferred output demand.
        self.resolve_declared_inputs(&mut pst, params, &wallet_snapshot, &mut state)?;

        // Safety check: all deferred output demands must have been activated by now.
        if !state.deferred_demands.is_empty() {
            return Err(WalletAbiError::InvalidRequest(
                "unresolved deferred output demands remain after input resolution".to_string(),
            ));
        }

        // Phase 4: if the declared inputs do not close the equation, add auxiliary wallet inputs
        // greedily by largest remaining deficit asset until fully balanced.
        self.add_auxiliary_inputs_until_balanced(&mut pst, &wallet_snapshot, &mut state)?;

        Ok(pst)
    }

    /// Return the best wallet UTXO candidate under a deterministic, deficit-aware score.
    ///
    /// Candidates must pass `WalletSourceFilter`, then are ranked lexicographically by:
    /// 1. total remaining deficit after simulated addition
    /// 2. remaining deficit on candidate asset
    /// 3. candidate overshoot/undershoot for that asset
    /// 4. `txid`, then `vout`
    ///
    /// # Complexity
    ///
    /// With `U` wallet UTXOs and `A` demanded assets, selection is `O(U * A)` time and `O(A)`
    /// temporary space per scored candidate simulation.
    fn filter_tx_out(
        &self,
        snapshot: &[WalletTxOut],
        filter: &WalletSourceFilter,
        used_outpoints: &HashSet<OutPoint>,
        demand_by_asset: &BTreeMap<AssetId, u64>,
        supply_by_asset: &BTreeMap<AssetId, u64>,
    ) -> Result<Option<WalletTxOut>, WalletAbiError> {
        // Candidate ranking is lexicographic and fully deterministic:
        // 1) total remaining deficit after adding candidate
        // 2) remaining deficit on candidate's asset
        // 3) candidate overshoot/undershoot for that asset
        // 4) txid + vout tie-break
        let mut best: Option<(WalletTxOut, CandidateScore)> = None;

        for candidate in snapshot
            .iter()
            .filter(|x| matches_wallet_filter(x, filter, used_outpoints))
        {
            let score = score_candidate(candidate, demand_by_asset, supply_by_asset)?;

            match &best {
                Some((_, best_score)) if score >= *best_score => {}
                _ => {
                    best = Some((candidate.clone(), score));
                }
            }
        }

        Ok(best.map(|(candidate, _)| candidate))
    }
}
