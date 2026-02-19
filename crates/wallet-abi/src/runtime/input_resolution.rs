//! Input resolution for transaction construction.
//!
//! This module balances the input/output equation in four phases:
//! 1. Build demand from all requested outputs and inject implicit fee demand on policy asset.
//! 2. Resolve declared inputs in order.
//! 3. Materialize deferred issuance-linked output demand when referenced inputs are known.
//! 4. Add auxiliary wallet inputs until every positive asset deficit is closed.
//!
//! # Algorithm
//!
//! Auxiliary funding for each asset deficit uses a deterministic stack:
//! 1. Bounded Branch-and-Bound (`BnB`) for exact subset match.
//! 2. Deterministic single-input fallback (largest UTXO above target).
//! 3. Deterministic largest-first accumulation fallback.
//!
//! This mirrors formal coin-selection framing (subset-sum / knapsack) while keeping runtime
//! bounded by an explicit node cap.
//!
//! # Determinism
//!
//! Candidate order and tie-breaks are stable:
//! - primary sort: amount descending
//! - tie-break 1: `txid` lexicographic ascending
//! - tie-break 2: `vout` ascending
//!
//! For multiple exact `BnB` matches with equal input count, the lexicographically smaller
//! outpoint list is selected.
//!
//! # Complexity
//!
//! Let:
//! - `O` = number of outputs
//! - `I` = number of declared inputs
//! - `U` = wallet UTXO count in snapshot
//! - `A` = number of distinct demanded assets
//! - `K` = number of auxiliary inputs added
//! - `N` = max candidate UTXOs for one deficit asset
//!
//! Worst-case time is:
//! - declared-input selection: `O(I * U * A)`
//! - auxiliary selection per deficit asset: bounded Branch-and-Bound search
//!   plus deterministic fallbacks, `O(MAX_BNB_NODES + N)`
//! - overall: `O(I * U * A + K * (MAX_BNB_NODES + N) + O + I)`
//!
//! Space is `O(U + A + O + N)` for used-outpoint tracking, equation state and
//! per-asset candidate working sets.
//!
//! # Failure modes
//!
//! - Duplicate `"fee"` output ids fail fast.
//! - Fee output with non-policy asset fails fast.
//! - Arithmetic overflow fails with `InvalidRequest`.
//! - Unclosable deficits fail with `Funding`.
//!
//! # Doc tests
//!
//! The deficit map keeps only positive `(demand - supply)` entries:
//!
//! ```rust,ignore
//! use std::collections::BTreeMap;
//! use lwk_wollet::elements::AssetId;
//!
//! let lbtc = AssetId::from_slice(&[1u8; 32]).unwrap();
//! let usdt = AssetId::from_slice(&[2u8; 32]).unwrap();
//! let demand = BTreeMap::from([(lbtc, 8_u64), (usdt, 12)]);
//! let supply = BTreeMap::from([(lbtc, 3_u64), (usdt, 12)]);
//! let d = current_deficits(&demand, &supply);
//! assert_eq!(d.get(&lbtc), Some(&5));
//! assert!(!d.contains_key(&usdt));
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
//! Formal references:
//! - Bitcoin Core coin selection (`BnB` / fallback context):
//!   <https://github.com/bitcoin/bitcoin/blob/master/src/wallet/coinselection.cpp>
//! - Murch, *An Evaluation of Coin Selection Strategies*:
//!   <http://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf>
//!

use crate::runtime::{WalletRuntimeConfig, get_finalizer_spec_key, get_secrets_spec_key};
use crate::{
    AmountFilter, AssetFilter, AssetVariant, FinalizerSpec, InputBlinder, InputIssuance,
    InputIssuanceKind, InputSchema, LockFilter, RuntimeParams, UTXOSource, WalletAbiError,
    WalletSourceFilter,
};

use lwk_common::Bip::Bip84;
use lwk_common::Signer;
use lwk_wollet::bitcoin::bip32::{ChildNumber, DerivationPath};
use lwk_wollet::elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use lwk_wollet::elements::hashes::Hash;
use lwk_wollet::elements::pset::{Input, PartiallySignedTransaction};
use lwk_wollet::elements::{AssetId, ContractHash, OutPoint, TxOut, TxOutSecrets, secp256k1_zkp};
use lwk_wollet::{Chain, EC, WalletTxOut};
use std::collections::{BTreeMap, HashMap, HashSet};

type CandidateScore = (u64, u64, u64, String, u32);

type Midstate = lwk_wollet::elements::hashes::sha256::Midstate;
/// Upper bound on DFS nodes visited by `BnB` before deterministic fallback is used.
const MAX_BNB_NODES: usize = 100_000;

/// Auxiliary `BnB` candidate projection used for deterministic subset search.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BnbCandidate {
    amount_sat: u64,
    txid_lex: String,
    vout: u32,
}

/// Selected auxiliary strategy used for one deficit asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BnbSelectionStatus {
    Exact,
    FallbackSingleLargestAboveTarget,
    FallbackLargestFirstAccumulation,
}

#[derive(Clone, Copy)]
struct WalletDerivationIndex {
    ext_int: Chain,
    wildcard_index: u32,
}

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
    wallet_derivation: Option<WalletDerivationIndex>,
}

/// Add `amount_sat` to one asset bucket with overflow protection.
///
/// ```rust,ignore
/// use std::collections::BTreeMap;
/// use lwk_wollet::elements::AssetId;
///
/// let asset = AssetId::from_slice(&[1u8; 32]).unwrap();
/// let mut balances = BTreeMap::new();
/// add_balance(&mut balances, asset, 10).unwrap();
/// add_balance(&mut balances, asset, 2).unwrap();
/// assert_eq!(balances.get(&asset), Some(&12));
/// ```
pub(super) fn add_balance(
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
/// use lwk_wollet::elements::AssetId;
///
/// let lbtc = AssetId::from_slice(&[1u8; 32]).unwrap();
/// let usdt = AssetId::from_slice(&[2u8; 32]).unwrap();
/// let demand = BTreeMap::from([(lbtc, 9_u64), (usdt, 5)]);
/// let supply = BTreeMap::from([(lbtc, 4_u64), (usdt, 5)]);
/// let d = current_deficits(&demand, &supply);
/// assert_eq!(d, BTreeMap::from([(lbtc, 5)]));
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
/// use lwk_wollet::elements::{OutPoint, Txid};
///
/// let mut used = HashSet::new();
/// let txid = Txid::from_slice(&[1u8; 32]).unwrap();
/// assert!(reserve_outpoint(&mut used, "input0", OutPoint::new(txid, 0)).is_ok());
/// assert!(reserve_outpoint(&mut used, "input0", OutPoint::new(txid, 0)).is_err());
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
/// assert!(validate_output_input_index("out0", 0, 1).is_ok());
/// assert!(validate_output_input_index("out0", 1, 1).is_err());
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
/// use lwk_wollet::elements::{OutPoint, Txid};
/// use lwk_wollet::elements::hashes::sha256::Midstate;
///
/// let entropy = [7u8; 32];
/// let outpoint = OutPoint::new(Txid::from_slice(&[3u8; 32]).unwrap(), 1);
/// let reissue = InputIssuance {
///     kind: InputIssuanceKind::Reissue,
///     asset_amount_sat: 0,
///     token_amount_sat: 0,
///     entropy,
/// };
/// let new_issuance = InputIssuance {
///     kind: InputIssuanceKind::New,
///     asset_amount_sat: 0,
///     token_amount_sat: 0,
///     entropy,
/// };
///
/// assert_eq!(
///     derive_issuance_entropy(outpoint, &reissue),
///     Midstate::from_byte_array(entropy)
/// );
/// assert_ne!(
///     derive_issuance_entropy(outpoint, &new_issuance),
///     Midstate::from_byte_array(entropy)
/// );
/// ```
pub(super) fn derive_issuance_entropy(outpoint: OutPoint, issuance: &InputIssuance) -> Midstate {
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
        (DeferredDemandKind::NewIssuanceAsset, InputIssuanceKind::New)
        | (DeferredDemandKind::ReIssuanceAsset, InputIssuanceKind::Reissue) => Ok(
            AssetId::from_entropy(derive_issuance_entropy(material.outpoint, issuance)),
        ),
        (DeferredDemandKind::NewIssuanceToken, InputIssuanceKind::New) => {
            Ok(AssetId::reissuance_token_from_entropy(
                derive_issuance_entropy(material.outpoint, issuance),
                material.is_confidential,
            ))
        }
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
) {
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

    if issuance.kind == InputIssuanceKind::Reissue {
        // TODO: investigate the purpose of this field, and make it functionally correct.
        let mut nonce = secrets.asset_bf.into_inner();
        if nonce == secp256k1_zkp::ZERO_TWEAK {
            let mut one = [0u8; 32];
            one[0] = 1;
            nonce = secp256k1_zkp::Tweak::from_slice(&one).expect("tweak from [0,..,1] is correct");
        }
        pset_input.issuance_blinding_nonce = Some(nonce);
    }

    pset_input.blinded_issuance = Some(0x00);
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

/// Sort candidates using the canonical deterministic order for `BnB` and fallbacks.
///
/// Order:
/// 1. amount descending
/// 2. txid lexicographic ascending
/// 3. vout ascending
///
/// ```rust,ignore
/// sort_bnb_candidates(&mut candidates);
/// ```
fn sort_bnb_candidates(candidates: &mut [BnbCandidate]) {
    candidates.sort_by(|a, b| {
        b.amount_sat
            .cmp(&a.amount_sat)
            .then_with(|| a.txid_lex.cmp(&b.txid_lex))
            .then_with(|| a.vout.cmp(&b.vout))
    });
}

/// Build a comparable outpoint-key for one candidate subset.
///
/// The key is sorted so subset order itself does not affect comparisons.
///
/// ```rust,ignore
/// let key = subset_lexicographic_key(&selected_indices, &candidates);
/// ```
fn subset_lexicographic_key(indices: &[usize], candidates: &[BnbCandidate]) -> Vec<(String, u32)> {
    let mut key = indices
        .iter()
        .map(|index| {
            let candidate = &candidates[*index];
            (candidate.txid_lex.clone(), candidate.vout)
        })
        .collect::<Vec<_>>();
    key.sort();
    key
}

/// Compare two exact-match subsets by deterministic tie-break rules.
///
/// Preference:
/// 1. fewer selected inputs
/// 2. lexicographically smaller outpoint key
fn is_better_exact_subset(
    proposed: &[usize],
    current_best: Option<&[usize]>,
    candidates: &[BnbCandidate],
) -> bool {
    let Some(current_best) = current_best else {
        return true;
    };

    if proposed.len() < current_best.len() {
        return true;
    }
    if proposed.len() > current_best.len() {
        return false;
    }

    subset_lexicographic_key(proposed, candidates)
        < subset_lexicographic_key(current_best, candidates)
}

fn build_bnb_suffix_sums(candidates: &[BnbCandidate]) -> Result<Vec<u64>, WalletAbiError> {
    let mut suffix_sum_sat = vec![0u64; candidates.len() + 1];
    for index in (0..candidates.len()).rev() {
        suffix_sum_sat[index] = suffix_sum_sat[index + 1]
            .checked_add(candidates[index].amount_sat)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "asset amount overflow while computing BnB suffix sums".to_string(),
                )
            })?;
    }

    Ok(suffix_sum_sat)
}

struct BnbSearch<'a> {
    target_sat: u64,
    candidates: &'a [BnbCandidate],
    suffix_sum_sat: &'a [u64],
    max_nodes: usize,
    nodes_visited: usize,
    node_limit_hit: bool,
    current: Vec<usize>,
    best: Option<Vec<usize>>,
}

impl<'a> BnbSearch<'a> {
    const fn new(
        target_sat: u64,
        candidates: &'a [BnbCandidate],
        suffix_sum_sat: &'a [u64],
        max_nodes: usize,
    ) -> Self {
        Self {
            target_sat,
            candidates,
            suffix_sum_sat,
            max_nodes,
            nodes_visited: 0,
            node_limit_hit: false,
            current: Vec::new(),
            best: None,
        }
    }

    const fn mark_node_visit(&mut self) -> bool {
        self.nodes_visited = self.nodes_visited.saturating_add(1);
        self.nodes_visited > self.max_nodes
    }

    fn record_exact_if_better(&mut self) {
        if is_better_exact_subset(&self.current, self.best.as_deref(), self.candidates) {
            self.best = Some(self.current.clone());
        }
    }

    fn can_reach_target(&self, index: usize, sum_sat: u64) -> Result<bool, WalletAbiError> {
        let max_possible = sum_sat
            .checked_add(self.suffix_sum_sat[index])
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "asset amount overflow while evaluating BnB pruning bounds".to_string(),
                )
            })?;

        Ok(max_possible >= self.target_sat)
    }

    fn search(&mut self, index: usize, sum_sat: u64) -> Result<(), WalletAbiError> {
        if self.node_limit_hit {
            return Ok(());
        }
        if self.mark_node_visit() {
            self.node_limit_hit = true;
            return Ok(());
        }

        if sum_sat == self.target_sat {
            self.record_exact_if_better();
            return Ok(());
        }
        if index >= self.candidates.len() || sum_sat > self.target_sat {
            return Ok(());
        }
        if !self.can_reach_target(index, sum_sat)? {
            return Ok(());
        }

        let included_sum = sum_sat
            .checked_add(self.candidates[index].amount_sat)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "asset amount overflow while evaluating BnB include branch".to_string(),
                )
            })?;
        if included_sum <= self.target_sat {
            self.current.push(index);
            self.search(index + 1, included_sum)?;
            self.current.pop();
        }

        self.search(index + 1, sum_sat)
    }
}

/// Bounded depth-first Branch-and-Bound search for an exact subset sum.
///
/// Returns:
/// - `Some(indices)` on exact match
/// - `None` if no exact match or node bound is reached
///
/// Pruning:
/// - stop include branch when `sum > target`
/// - stop branch when `sum + remaining < target`
///
/// ```rust,ignore
/// let maybe_exact = bnb_exact_subset_indices(&candidates, target_sat, MAX_BNB_NODES)?;
/// ```
fn bnb_exact_subset_indices(
    candidates: &[BnbCandidate],
    target_sat: u64,
    max_nodes: usize,
) -> Result<Option<Vec<usize>>, WalletAbiError> {
    if target_sat == 0 {
        return Ok(Some(Vec::new()));
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    let suffix_sum_sat = build_bnb_suffix_sums(candidates)?;
    let mut search = BnbSearch::new(target_sat, candidates, &suffix_sum_sat, max_nodes);
    search.search(0, 0)?;

    if search.node_limit_hit {
        return Ok(None);
    }

    Ok(search.best)
}

/// Deterministic fallback A: select one largest UTXO whose amount is `>= target`.
///
/// Candidates are expected to be pre-sorted with `sort_bnb_candidates`.
///
/// ```rust,ignore
/// let picked = select_single_largest_above_target(&candidates, target_sat);
/// ```
fn select_single_largest_above_target(
    candidates: &[BnbCandidate],
    target_sat: u64,
) -> Option<Vec<usize>> {
    candidates
        .iter()
        .position(|candidate| candidate.amount_sat >= target_sat)
        .map(|index| vec![index])
}

/// Deterministic fallback B: accumulate largest-first until the target is reached.
///
/// Candidates are expected to be pre-sorted with `sort_bnb_candidates`.
///
/// ```rust,ignore
/// let picked = select_largest_first_accumulation(&candidates, target_sat)?;
/// ```
fn select_largest_first_accumulation(
    candidates: &[BnbCandidate],
    target_sat: u64,
) -> Result<Option<Vec<usize>>, WalletAbiError> {
    let mut selected_indices = Vec::new();
    let mut sum_sat = 0u64;

    for (index, candidate) in candidates.iter().enumerate() {
        selected_indices.push(index);
        sum_sat = sum_sat.checked_add(candidate.amount_sat).ok_or_else(|| {
            WalletAbiError::InvalidRequest(
                "asset amount overflow while running fallback accumulation".to_string(),
            )
        })?;
        if sum_sat >= target_sat {
            return Ok(Some(selected_indices));
        }
    }

    Ok(None)
}

/// Sum selected candidate amounts with overflow checks.
///
/// ```rust,ignore
/// let total = sum_selected_amount(&candidates, &selected_indices)?;
/// ```
fn sum_selected_amount(
    candidates: &[BnbCandidate],
    selected_indices: &[usize],
) -> Result<u64, WalletAbiError> {
    selected_indices.iter().try_fold(0u64, |sum, index| {
        sum.checked_add(candidates[*index].amount_sat)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "asset amount overflow while summing selected auxiliary inputs".to_string(),
                )
            })
    })
}

impl WalletRuntimeConfig {
    /// Build demand from output specs and store issuance-linked entries as deferred.
    ///
    /// Rules:
    /// - Non-fee outputs contribute demand directly (or deferred for issuance-derived assets).
    /// - Exactly one implicit policy-asset demand entry is added for `fee_target_sat`.
    /// - `"fee"` output, if present, is validated only for uniqueness and policy-asset type.
    /// - Caller-provided fee output amount is ignored for demand accounting.
    fn resolve_output_demands(
        params: &RuntimeParams,
        fee_target_sat: u64,
        policy_asset: AssetId,
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Convert output-level asset requirements into equation demand.
        // Issuance-derived outputs are deferred until their referenced input is resolved.
        let mut fee_output_seen = false;
        for output in &params.outputs {
            if output.id == "fee" {
                if fee_output_seen {
                    return Err(WalletAbiError::InvalidRequest(
                        "duplicate output id 'fee' in params.outputs".to_string(),
                    ));
                }
                fee_output_seen = true;

                match output.asset {
                    AssetVariant::AssetId { asset_id } if asset_id == policy_asset => {}
                    AssetVariant::AssetId { asset_id } => {
                        return Err(WalletAbiError::InvalidRequest(format!(
                            "fee output must use policy asset {policy_asset}, found {asset_id}"
                        )));
                    }
                    _ => {
                        return Err(WalletAbiError::InvalidRequest(
                            "fee output must use explicit asset_id policy asset variant"
                                .to_string(),
                        ));
                    }
                }

                continue;
            }

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

        // Fee demand is always modeled from runtime target, independent of params fee amount.
        add_balance(&mut state.demand_by_asset, policy_asset, fee_target_sat)?;

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
            wallet_derivation: None,
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
        let selected = Self::filter_tx_out(
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
            wallet_derivation: Some(WalletDerivationIndex {
                ext_int: selected.ext_int,
                wildcard_index: selected.wildcard_index,
            }),
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

    fn signer_origin_for_wallet_utxo(
        &self,
        index: WalletDerivationIndex,
    ) -> Result<(lwk_wollet::elements::bitcoin::PublicKey, DerivationPath), WalletAbiError> {
        let ext_int = match index.ext_int {
            Chain::External => ChildNumber::from_normal_idx(0),
            Chain::Internal => ChildNumber::from_normal_idx(1),
        }
        .map_err(|error| {
            WalletAbiError::InvalidSignerConfig(format!(
                "invalid change index for descriptor derivation: {error}"
            ))
        })?;
        let wildcard = ChildNumber::from_normal_idx(index.wildcard_index).map_err(|error| {
            WalletAbiError::InvalidRequest(format!(
                "invalid wallet wildcard index {}: {error}",
                index.wildcard_index
            ))
        })?;

        let derivation_path = self
            .get_derivation_path(Bip84)
            .child(ext_int)
            .child(wildcard);
        let pubkey = self.signer.derive_xpub(&derivation_path)?.public_key.into();

        Ok((pubkey, derivation_path))
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
        pset_input.amount = Some(material.secrets.value);
        pset_input.asset = Some(material.secrets.asset);

        if let Some(issuance) = input.issuance.as_ref() {
            apply_issuance_to_pset_input(&mut pset_input, issuance, &material.secrets);
        }

        pset_input
            .proprietary
            .insert(get_finalizer_spec_key(), input.finalizer.encode());
        pset_input.proprietary.insert(
            get_secrets_spec_key(),
            serde_json::to_vec(&material.secrets)?,
        );
        if let Some(index) = material.wallet_derivation {
            let (pubkey, derivation_path) = self.signer_origin_for_wallet_utxo(index)?;
            pset_input
                .bip32_derivation
                .insert(pubkey, (self.signer.fingerprint(), derivation_path));
        }
        pst.add_input(pset_input);

        Ok(())
    }

    /// Apply the resolved input contribution to equation supply (base + issuance minting).
    fn apply_input_supply(
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
        input_index: usize,
        input: &InputSchema,
        material: &ResolvedInputMaterial,
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Deferred demands become concrete once the referenced input is known,
        // because issuance-derived asset ids depend on that input outpoint/entropy.
        let input_index_u32 = u32::try_from(input_index).map_err(|_| {
            WalletAbiError::InvalidRequest(format!(
                "input index overflow while activating deferred demands: {input_index}"
            ))
        })?;
        let Some(entries) = state.deferred_demands.remove(&input_index_u32) else {
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
        params: &RuntimeParams,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
    ) -> Result<(), WalletAbiError> {
        // Main declared-input pass:
        // resolve source -> append PSET input -> increase supply -> unlock deferred demands.
        for (input_index, input) in params.inputs.iter().enumerate() {
            let material = self.resolve_declared_input_material(input, wallet_snapshot, state)?;

            self.add_resolved_input_to_pset(pst, input, &material)?;
            Self::apply_input_supply(input, &material, state)?;
            Self::activate_deferred_demands_for_input(input_index, input, &material, state)?;
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

    /// Select deterministic auxiliary wallet inputs for one deficit asset.
    ///
    /// Strategy order:
    /// 1. exact `BnB`
    /// 2. single largest-above-target
    /// 3. largest-first accumulation
    fn select_auxiliary_inputs_for_asset(
        wallet_snapshot: &[WalletTxOut],
        used_outpoints: &HashSet<OutPoint>,
        target_asset: AssetId,
        target_missing: u64,
    ) -> Result<(Vec<WalletTxOut>, BnbSelectionStatus), WalletAbiError> {
        let mut wallet_candidates: Vec<WalletTxOut> = wallet_snapshot
            .iter()
            .filter(|candidate| {
                !used_outpoints.contains(&candidate.outpoint)
                    && candidate.unblinded.asset == target_asset
            })
            .cloned()
            .collect();
        if wallet_candidates.is_empty() {
            return Err(WalletAbiError::Funding(
                "unable to cover remaining deficits with wallet utxos".to_string(),
            ));
        }

        let mut bnb_candidates = wallet_candidates
            .iter()
            .map(|candidate| BnbCandidate {
                amount_sat: candidate.unblinded.value,
                txid_lex: candidate.outpoint.txid.to_string(),
                vout: candidate.outpoint.vout,
            })
            .collect::<Vec<_>>();
        sort_bnb_candidates(&mut bnb_candidates);
        wallet_candidates.sort_by(|a, b| {
            b.unblinded
                .value
                .cmp(&a.unblinded.value)
                .then_with(|| {
                    a.outpoint
                        .txid
                        .to_string()
                        .cmp(&b.outpoint.txid.to_string())
                })
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        });

        let (selected_indices, status) = if let Some(exact) =
            bnb_exact_subset_indices(&bnb_candidates, target_missing, MAX_BNB_NODES)?
        {
            (exact, BnbSelectionStatus::Exact)
        } else if let Some(single) =
            select_single_largest_above_target(&bnb_candidates, target_missing)
        {
            (single, BnbSelectionStatus::FallbackSingleLargestAboveTarget)
        } else if let Some(accumulated) =
            select_largest_first_accumulation(&bnb_candidates, target_missing)?
        {
            (
                accumulated,
                BnbSelectionStatus::FallbackLargestFirstAccumulation,
            )
        } else {
            return Err(WalletAbiError::Funding(
                "unable to cover remaining deficits with wallet utxos".to_string(),
            ));
        };

        let selected_total = sum_selected_amount(&bnb_candidates, &selected_indices)?;
        if selected_total < target_missing {
            return Err(WalletAbiError::Funding(
                "unable to cover remaining deficits with wallet utxos".to_string(),
            ));
        }

        let selected = selected_indices
            .iter()
            .map(|index| wallet_candidates[*index].clone())
            .collect::<Vec<_>>();

        Ok((selected, status))
    }

    fn add_auxiliary_wallet_input(
        &self,
        pst: &mut PartiallySignedTransaction,
        state: &mut ResolutionState,
        selected: &WalletTxOut,
    ) -> Result<(), WalletAbiError> {
        if !state.used_outpoints.insert(selected.outpoint) {
            return Err(WalletAbiError::InvalidRequest(format!(
                "duplicate auxiliary outpoint resolved: {}:{}",
                selected.outpoint.txid, selected.outpoint.vout
            )));
        }

        // TODO: use wollet cache here instead of fetching.
        let tx_out = self.fetch_tx_out(&selected.outpoint)?;
        let mut pset_input = Input::from_prevout(selected.outpoint);
        pset_input.witness_utxo = Some(tx_out);
        pset_input.amount = Some(selected.unblinded.value);
        pset_input.asset = Some(selected.unblinded.asset);
        pset_input
            .proprietary
            .insert(get_finalizer_spec_key(), FinalizerSpec::Wallet.encode());
        pset_input.proprietary.insert(
            get_secrets_spec_key(),
            serde_json::to_vec(&selected.unblinded)?,
        );
        let (pubkey, derivation_path) =
            self.signer_origin_for_wallet_utxo(WalletDerivationIndex {
                ext_int: selected.ext_int,
                wildcard_index: selected.wildcard_index,
            })?;
        pset_input
            .bip32_derivation
            .insert(pubkey, (self.signer.fingerprint(), derivation_path));
        pst.add_input(pset_input);

        add_balance(
            &mut state.supply_by_asset,
            selected.unblinded.asset,
            selected.unblinded.value,
        )?;

        Ok(())
    }

    /// Add one or more auxiliary wallet inputs targeting one missing asset amount.
    ///
    /// The selected inputs are appended in deterministic order and each contribution updates
    /// `supply_by_asset` immediately.
    fn add_auxiliary_input_for_asset(
        &self,
        pst: &mut PartiallySignedTransaction,
        wallet_snapshot: &[WalletTxOut],
        state: &mut ResolutionState,
        target_asset: AssetId,
        target_missing: u64,
    ) -> Result<(), WalletAbiError> {
        let (selected_inputs, _status) = Self::select_auxiliary_inputs_for_asset(
            wallet_snapshot,
            &state.used_outpoints,
            target_asset,
            target_missing,
        )?;

        for selected in &selected_inputs {
            self.add_auxiliary_wallet_input(pst, state, selected)?;
        }

        Ok(())
    }

    /// Repeatedly add auxiliary wallet inputs until there is no remaining positive deficit.
    ///
    /// Assets are processed by current largest deficit (asset-id tie-break).
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
    /// - Fee demand is injected implicitly as policy-asset demand equal to `fee_target_sat`.
    /// - Fee output amount in request params is ignored for funding demand purposes.
    /// - Fee output id validation (`"fee"`) is still enforced for duplicates and asset type.
    ///
    /// Change nuance:
    /// - This resolver does not create or place change outputs.
    /// - It guarantees only `supply >= demand` per asset after resolution.
    /// - Any surplus created by UTXO granularity/overshoot is left for the output stage
    ///   to materialize as explicit change.
    ///
    /// # Complexity
    ///
    /// Let `I` be declared inputs, `U` wallet UTXOs, `A` demanded assets, and `K` auxiliary
    /// inputs added. Declared-input selection is `O(I * U * A)`. Auxiliary per-asset funding
    /// is bounded by `MAX_BNB_NODES` search plus deterministic fallbacks.
    pub(super) fn resolve_inputs(
        &self,
        pst: PartiallySignedTransaction,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        // Phase 1: initialize demand/supply state and load wallet snapshot once.
        // We keep all equation state in a dedicated struct so each phase mutates a single object.
        let mut pst = pst;
        let wallet_snapshot = self.wollet.utxos()?;
        let mut state = ResolutionState::default();

        // Phase 2: build output demand from AssetVariant.
        // AssetId contributes directly, while issuance-linked variants are deferred until their
        // referenced input is resolved and its issuance entropy is known.
        Self::resolve_output_demands(
            params,
            fee_target_sat,
            *self.network.policy_asset(),
            &mut state,
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlinderVariant, LockVariant, OutputSchema};
    use lwk_wollet::elements::Script;

    fn test_asset(tag: u8) -> AssetId {
        AssetId::from_slice(&[tag; 32]).expect("asset id from fixed bytes")
    }

    fn make_output(id: &str, asset_id: AssetId, amount_sat: u64) -> OutputSchema {
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

    fn to_key(indices: &[usize], candidates: &[BnbCandidate]) -> Vec<(String, u32)> {
        let mut key = indices
            .iter()
            .map(|index| {
                let candidate = &candidates[*index];
                (candidate.txid_lex.clone(), candidate.vout)
            })
            .collect::<Vec<_>>();
        key.sort();
        key
    }

    #[test]
    fn resolve_output_demands_includes_implicit_fee_demand() {
        let policy_asset = test_asset(1);
        let mut state = ResolutionState::default();
        let params = RuntimeParams {
            inputs: Vec::new(),
            outputs: vec![make_output("out0", test_asset(2), 7)],
            fee_rate_sat_vb: None,
            locktime: None,
        };

        WalletRuntimeConfig::resolve_output_demands(&params, 13, policy_asset, &mut state)
            .expect("demand resolution");

        assert_eq!(state.demand_by_asset.get(&test_asset(2)), Some(&7));
        assert_eq!(state.demand_by_asset.get(&policy_asset), Some(&13));
    }

    #[test]
    fn resolve_output_demands_rejects_duplicate_fee_outputs() {
        let policy_asset = test_asset(3);
        let mut state = ResolutionState::default();
        let params = RuntimeParams {
            inputs: Vec::new(),
            outputs: vec![
                make_output("fee", policy_asset, 0),
                make_output("fee", policy_asset, 0),
            ],
            fee_rate_sat_vb: None,
            locktime: None,
        };

        let err = WalletRuntimeConfig::resolve_output_demands(&params, 1, policy_asset, &mut state)
            .expect_err("duplicate fee output should fail");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("duplicate output id 'fee'"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_output_demands_rejects_non_policy_fee_asset() {
        let policy_asset = test_asset(4);
        let mut state = ResolutionState::default();
        let params = RuntimeParams {
            inputs: Vec::new(),
            outputs: vec![make_output("fee", test_asset(5), 0)],
            fee_rate_sat_vb: None,
            locktime: None,
        };

        let err = WalletRuntimeConfig::resolve_output_demands(&params, 1, policy_asset, &mut state)
            .expect_err("non-policy fee asset should fail");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("fee output must use policy asset"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn bnb_finds_exact_match() {
        let mut candidates = vec![
            BnbCandidate {
                amount_sat: 8,
                txid_lex: "cc".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 6,
                txid_lex: "aa".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 4,
                txid_lex: "bb".to_string(),
                vout: 1,
            },
        ];
        sort_bnb_candidates(&mut candidates);

        let selected = bnb_exact_subset_indices(&candidates, 10, MAX_BNB_NODES)
            .expect("bnb exact")
            .expect("exact subset expected");

        assert_eq!(
            sum_selected_amount(&candidates, &selected).expect("sum"),
            10
        );
    }

    #[test]
    fn fallback_single_largest_above_target_is_deterministic() {
        let mut candidates = vec![
            BnbCandidate {
                amount_sat: 9,
                txid_lex: "bb".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 20,
                txid_lex: "aa".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 8,
                txid_lex: "cc".to_string(),
                vout: 0,
            },
        ];
        sort_bnb_candidates(&mut candidates);

        let selected =
            select_single_largest_above_target(&candidates, 10).expect("single-above-target");
        assert_eq!(selected, vec![0]);
        assert_eq!(
            sum_selected_amount(&candidates, &selected).expect("sum"),
            20
        );
    }

    #[test]
    fn fallback_largest_first_accumulation_reaches_target() {
        let mut candidates = vec![
            BnbCandidate {
                amount_sat: 9,
                txid_lex: "aa".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 8,
                txid_lex: "bb".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 4,
                txid_lex: "cc".to_string(),
                vout: 0,
            },
        ];
        sort_bnb_candidates(&mut candidates);

        let selected = select_largest_first_accumulation(&candidates, 15)
            .expect("fallback accumulation result")
            .expect("accumulation should reach target");
        assert_eq!(selected, vec![0, 1]);
        assert_eq!(
            sum_selected_amount(&candidates, &selected).expect("sum"),
            17
        );
    }

    #[test]
    fn bnb_tie_break_is_lexicographically_deterministic() {
        let mut candidates = vec![
            BnbCandidate {
                amount_sat: 6,
                txid_lex: "ab".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 6,
                txid_lex: "aa".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 4,
                txid_lex: "ba".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 4,
                txid_lex: "bb".to_string(),
                vout: 0,
            },
        ];
        sort_bnb_candidates(&mut candidates);

        let selected = bnb_exact_subset_indices(&candidates, 10, MAX_BNB_NODES)
            .expect("bnb exact")
            .expect("exact subset expected");
        assert_eq!(
            to_key(&selected, &candidates),
            vec![("aa".to_string(), 0), ("ba".to_string(), 0)]
        );
    }

    #[test]
    fn bnb_node_cap_forces_fallback() {
        let mut candidates = vec![
            BnbCandidate {
                amount_sat: 10,
                txid_lex: "aa".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 5,
                txid_lex: "bb".to_string(),
                vout: 0,
            },
            BnbCandidate {
                amount_sat: 5,
                txid_lex: "cc".to_string(),
                vout: 0,
            },
        ];
        sort_bnb_candidates(&mut candidates);

        let exact_limited =
            bnb_exact_subset_indices(&candidates, 10, 1).expect("limited bnb should not error");
        assert!(exact_limited.is_none());

        let selected =
            select_single_largest_above_target(&candidates, 10).expect("fallback single");
        assert_eq!(selected, vec![0]);
    }
}
