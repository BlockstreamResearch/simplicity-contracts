use crate::runtime::input_resolution::{add_balance, derive_issuance_entropy};
use crate::runtime::{WalletRuntimeConfig, get_finalizer_spec_key};
use crate::{
    AssetVariant, BlinderVariant, FinalizerSpec, InputIssuance, InputIssuanceKind, LockVariant,
    RuntimeParams, WalletAbiError,
};

use std::collections::BTreeMap;

use lwk_wollet::bitcoin::PublicKey;
use lwk_wollet::elements::pset::{Output, PartiallySignedTransaction};
use lwk_wollet::elements::{Address, AssetId, OutPoint, Script};

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
            indices.push(index as u32);
        }
    }

    Ok(indices)
}

fn wallet_supply_by_asset(
    pst: &PartiallySignedTransaction,
    wallet_input_indices: &[u32],
) -> Result<BTreeMap<AssetId, u64>, WalletAbiError> {
    let mut balances = BTreeMap::new();

    for input_index in wallet_input_indices {
        let input = pst.inputs().get(*input_index as usize).ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "wallet input index {input_index} is out of bounds while balancing outputs"
            ))
        })?;

        let asset = input.asset.expect("ensured by the inputs resolver");
        let amount_sat = input.amount.expect("ensured by the inputs resolver");

        add_balance(&mut balances, asset, amount_sat)?;
    }

    Ok(balances)
}

fn aggregate_output_balances(
    pst: &PartiallySignedTransaction,
) -> Result<BTreeMap<AssetId, u64>, WalletAbiError> {
    let mut balances = BTreeMap::new();

    for output in pst.outputs() {
        let asset = output.asset.expect("ensured by the this resolver");
        let amount_sat = output.amount.expect("ensured by the this resolver");

        add_balance(&mut balances, asset, amount_sat)?;
    }

    Ok(balances)
}

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

fn resolve_output_lock_script(
    lock: &LockVariant,
    signer_address: &Address,
) -> Result<Script, WalletAbiError> {
    match lock {
        LockVariant::Script { script } => Ok(script.clone()),
        LockVariant::Finalizer { finalizer } => match finalizer.as_ref() {
            FinalizerSpec::Wallet => Ok(signer_address.script_pubkey()),
            FinalizerSpec::Simf { internal_key, .. } => Ok(internal_key.address.script_pubkey()),
        },
    }
}

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

fn append_wallet_change_outputs(
    pst: &mut PartiallySignedTransaction,
    signer_address: &Address,
    wallet_supply_by_asset: &BTreeMap<AssetId, u64>,
    assigned_output_by_asset: &BTreeMap<AssetId, u64>,
) {
    let change_blinding_key = signer_address
        .blinding_pubkey
        .expect("CT descriptor always has blinder");
    for (asset_id, wallet_supply_sat) in wallet_supply_by_asset {
        let assigned = assigned_output_by_asset.get(asset_id).copied().unwrap_or(0);
        if *wallet_supply_sat <= assigned {
            continue;
        }

        pst.add_output(Output::new_explicit(
            signer_address.script_pubkey(),
            wallet_supply_sat - assigned,
            *asset_id,
            Some(change_blinding_key.into()),
        ));
    }
}

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

impl WalletRuntimeConfig {
    pub(super) fn balance_out(
        &self,
        mut pst: PartiallySignedTransaction,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let signer_address = self.signer_receive_address()?;
        let wallet_input_indices = wallet_input_indices(&pst)?;
        let wallet_supply = wallet_supply_by_asset(&pst, &wallet_input_indices)?;

        let mut fee_output_index = None;
        for output in &params.outputs {
            let asset_id = resolve_output_asset(&output.id, &output.asset, &pst, params)?;
            let script = resolve_output_lock_script(&output.lock, &signer_address)?;

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

        apply_fee_target(
            &mut pst,
            fee_output_index,
            fee_target_sat,
            *self.network.policy_asset(),
        )?;

        let assigned_output_by_asset = aggregate_output_balances(&pst)?;

        append_wallet_change_outputs(
            &mut pst,
            &signer_address,
            &wallet_supply,
            &assigned_output_by_asset,
        );
        apply_output_blinder_indices(&mut pst, &wallet_input_indices)?;

        Ok(pst)
    }
}
