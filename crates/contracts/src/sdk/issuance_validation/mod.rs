use std::collections::HashSet;

use simplicityhl::elements::confidential::Value as ConfidentialValue;
use simplicityhl::elements::secp256k1_zkp::{SECP256K1, SecretKey, ZERO_TWEAK};
use simplicityhl::elements::{AssetId, Script, Transaction};

/// Constraints for verifying an issuance transaction.
#[derive(Clone, Debug, Default)]
pub struct IssuanceTxConstraints {
    /// Per-issuance-input constraints.
    pub inputs: Vec<IssuanceInputConstraints>,

    /// If `false`, every issuance input in the transaction must be listed in [`Self::inputs`].
    pub allow_unconstrained_issuances: bool,
}

/// Per-input constraints for a new issuance.
#[derive(Clone, Debug)]
pub struct IssuanceInputConstraints {
    /// Index into `tx.input`.
    pub input_idx: usize,

    /// Destination, amount, and optional blinding key for the issued asset.
    ///
    /// The tuple is `(script, amount, blinding_key)`. When `blinding_key` is `Some`,
    /// confidential outputs are unblinded using it; if unblinding succeeds and the asset
    /// matches, the output is accounted for, otherwise it is skipped.
    pub issuance_destination: Option<(Script, u64, Option<SecretKey>)>,

    /// Destination, amount, and optional blinding key for the reissuance token.
    ///
    /// The tuple is `(script, amount, blinding_key)`. When `blinding_key` is `Some`,
    /// confidential outputs are unblinded using it; if unblinding succeeds and the asset
    /// matches, the output is accounted for, otherwise it is skipped.
    pub reissuance_destination: Option<(Script, u64, Option<SecretKey>)>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum IssuanceVerificationError {
    #[error("No asset issuances found in the transaction.")]
    NoIssuancesFound,

    #[error("Constraint input index {input_idx} is out of bounds (tx inputs: {inputs_len}).")]
    ConstraintInputOutOfBounds { input_idx: usize, inputs_len: usize },

    #[error("Constraint input index {input_idx} appears more than once.")]
    DuplicateConstraintInput { input_idx: usize },

    #[error("Constraint input index {input_idx} is not an issuance input.")]
    ConstraintInputNotAnIssuance { input_idx: usize },

    #[error("Issuance input at index {input_idx} is a reissuance (not a new issuance).")]
    ReissuanceInputFound { input_idx: usize },

    #[error("Issuance input at index {input_idx} is not listed in constraints.")]
    UnexpectedIssuanceInput { input_idx: usize },

    #[error("Issuance input at index {input_idx} has a confidential issued amount.")]
    ConfidentialIssuanceAmount { input_idx: usize },

    #[error("Issuance input at index {input_idx} has confidential inflation keys.")]
    ConfidentialInflationKeys { input_idx: usize },

    #[error(
        "Minted issued amount mismatch for input #{input_idx} (Asset ID: {asset_id}): expected {expected}, found {found}."
    )]
    MintedIssuanceAmountMismatch {
        input_idx: usize,
        asset_id: AssetId,
        expected: u64,
        found: u64,
    },

    #[error(
        "Minted inflation keys mismatch for input #{input_idx} (Reissuance Token ID: {asset_id}): expected {expected}, found {found}."
    )]
    MintedInflationKeysMismatch {
        input_idx: usize,
        asset_id: AssetId,
        expected: u64,
        found: u64,
    },

    #[error(
        "Output #{vout} has non-explicit value for constrained asset {asset_id} (cannot verify exact amounts)."
    )]
    OutputValueNotExplicitForConstrainedAsset { vout: usize, asset_id: AssetId },

    #[error("Constrained asset {asset_id} appears in an unexpected output #{vout}.")]
    AssetAppearsInUnexpectedOutput { vout: usize, asset_id: AssetId },

    #[error("Amount mismatch for asset {asset_id}: expected {expected}, found {found}.")]
    AmountMismatch {
        asset_id: AssetId,
        expected: u64,
        found: u64,
    },
}

/// Verifies that `tx` is a well-formed *new issuance* transaction and satisfies `constraints`.
///
/// ## What gets checked
///
/// - **New issuance inputs only**: every input with a non-null `asset_issuance` must be a *new*
///   issuance (`asset_blinding_nonce == ZERO_TWEAK`). Reissuances are rejected.
/// - **Coverage**: if `constraints.allow_unconstrained_issuances` is `false`, then every issuance
///   input in the transaction must be listed in `constraints.inputs`.
/// - **Minted amounts**: minted `asset_issuance.amount` and `asset_issuance.inflation_keys` must
///   be `Null` or `Explicit`; confidential issuance fields are rejected.
/// - **Destinations**: for each constrained input, both the issued asset and the reissuance token
///   must only appear in outputs spending to the provided `Script`, and the *sum of explicit
///   output values* must equal the constrained amount.
///
/// ## Confidentiality policy
///
/// - Each destination tuple carries an optional blinding key (the third element). When set,
///   confidential outputs are unblinded using the key. If unblinding succeeds and the asset
///   matches, the output is accounted for. If unblinding fails, the output is silently skipped.
/// - When no blinding key is provided for a destination, outputs whose **asset is confidential**
///   are ignored during verification (this verifier makes no claims about what may be hidden in
///   confidential-asset outputs).
/// - For constrained assets, any output with an **explicit matching asset** but a **non-explicit
///   value** fails verification (cannot check exact amounts).
///
/// ## `None` destination semantics
///
/// If `issuance_destination` or `reissuance_destination` is `None`, the corresponding minted amount
/// must be `0` and the asset must not appear in any *explicit* output (even with value `0`).
///
/// # Errors
///
/// Returns an [`IssuanceVerificationError`] if the transaction does not satisfy the constraints.
#[allow(clippy::too_many_lines)]
pub fn verify_issuance(
    tx: &Transaction,
    constraints: &IssuanceTxConstraints,
) -> Result<(), IssuanceVerificationError> {
    let issuance_input_indices: Vec<usize> = tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(i, inp)| (!inp.asset_issuance.is_null()).then_some(i))
        .collect();

    if issuance_input_indices.is_empty() {
        return Err(IssuanceVerificationError::NoIssuancesFound);
    }

    // All issuance inputs must be *new* issuances.
    for &input_idx in &issuance_input_indices {
        if tx.input[input_idx].asset_issuance.asset_blinding_nonce != ZERO_TWEAK {
            return Err(IssuanceVerificationError::ReissuanceInputFound { input_idx });
        }
    }

    // Validate constraint indices and build a set for coverage checks.
    let mut constrained_inputs = HashSet::<usize>::new();
    for issuance_input_constraint in &constraints.inputs {
        if issuance_input_constraint.input_idx >= tx.input.len() {
            return Err(IssuanceVerificationError::ConstraintInputOutOfBounds {
                input_idx: issuance_input_constraint.input_idx,
                inputs_len: tx.input.len(),
            });
        }

        if !constrained_inputs.insert(issuance_input_constraint.input_idx) {
            return Err(IssuanceVerificationError::DuplicateConstraintInput {
                input_idx: issuance_input_constraint.input_idx,
            });
        }

        if tx.input[issuance_input_constraint.input_idx]
            .asset_issuance
            .is_null()
        {
            return Err(IssuanceVerificationError::ConstraintInputNotAnIssuance {
                input_idx: issuance_input_constraint.input_idx,
            });
        }
    }

    if !constraints.allow_unconstrained_issuances {
        for &input_idx in &issuance_input_indices {
            if !constrained_inputs.contains(&input_idx) {
                return Err(IssuanceVerificationError::UnexpectedIssuanceInput { input_idx });
            }
        }
    }

    for constraint in &constraints.inputs {
        let inp = &tx.input[constraint.input_idx];
        let (issued_asset_id, reissuance_token_id) = inp.issuance_ids();

        let minted_issuance_amount =
            issuance_value_to_u64(&inp.asset_issuance.amount, constraint.input_idx)?;
        verify_constrained_asset(
            tx,
            issued_asset_id,
            minted_issuance_amount,
            Option::from(&constraint.issuance_destination),
            constraint.input_idx,
            MintedConstraintKind::IssuanceAmount,
        )?;

        let minted_inflation_keys =
            inflation_keys_to_u64(&inp.asset_issuance.inflation_keys, constraint.input_idx)?;
        verify_constrained_asset(
            tx,
            reissuance_token_id,
            minted_inflation_keys,
            Option::from(&constraint.reissuance_destination),
            constraint.input_idx,
            MintedConstraintKind::InflationKeys,
        )?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MintedConstraintKind {
    IssuanceAmount,
    InflationKeys,
}

fn issuance_value_to_u64(
    amount: &ConfidentialValue,
    input_idx: usize,
) -> Result<u64, IssuanceVerificationError> {
    if amount.is_null() {
        return Ok(0);
    }

    amount
        .explicit()
        .ok_or(IssuanceVerificationError::ConfidentialIssuanceAmount { input_idx })
}

fn inflation_keys_to_u64(
    amount: &ConfidentialValue,
    input_idx: usize,
) -> Result<u64, IssuanceVerificationError> {
    if amount.is_null() {
        return Ok(0);
    }

    amount
        .explicit()
        .ok_or(IssuanceVerificationError::ConfidentialInflationKeys { input_idx })
}

fn verify_constrained_asset(
    tx: &Transaction,
    asset_id: AssetId,
    minted_amount: u64,
    destination: Option<&(Script, u64, Option<SecretKey>)>,
    input_idx: usize,
    kind: MintedConstraintKind,
) -> Result<(), IssuanceVerificationError> {
    let (dest_script, expected_amount, blinder) = match destination {
        Some((s, amt, blinder)) => (Some(s), *amt, Option::from(blinder)),
        None => (None, 0, None),
    };

    if minted_amount != expected_amount {
        return Err(match kind {
            MintedConstraintKind::IssuanceAmount => {
                IssuanceVerificationError::MintedIssuanceAmountMismatch {
                    input_idx,
                    asset_id,
                    expected: expected_amount,
                    found: minted_amount,
                }
            }
            MintedConstraintKind::InflationKeys => {
                IssuanceVerificationError::MintedInflationKeysMismatch {
                    input_idx,
                    asset_id,
                    expected: expected_amount,
                    found: minted_amount,
                }
            }
        });
    }

    verify_asset_destination(tx, asset_id, expected_amount, dest_script, blinder)
}

fn verify_asset_destination(
    tx: &Transaction,
    asset_id: AssetId,
    expected_amount: u64,
    destination_script: Option<&Script>,
    blinding_key: Option<&SecretKey>,
) -> Result<(), IssuanceVerificationError> {
    let mut sum_to_destination = 0u64;

    for (vout, output) in tx.output.iter().enumerate() {
        let resolved = match output.asset.explicit() {
            Some(out_asset) if out_asset == asset_id => {
                let Some(value) = output.value.explicit() else {
                    return Err(
                        IssuanceVerificationError::OutputValueNotExplicitForConstrainedAsset {
                            vout,
                            asset_id,
                        },
                    );
                };
                Some(value)
            }
            _ => blinding_key
                .and_then(|key| output.unblind(SECP256K1, *key).ok())
                .filter(|secrets| secrets.asset == asset_id)
                .map(|secrets| secrets.value),
        };

        if let Some(value) = resolved {
            let Some(dest_script) = destination_script else {
                return Err(IssuanceVerificationError::AssetAppearsInUnexpectedOutput {
                    vout,
                    asset_id,
                });
            };

            if output.script_pubkey != *dest_script {
                return Err(IssuanceVerificationError::AssetAppearsInUnexpectedOutput {
                    vout,
                    asset_id,
                });
            }

            sum_to_destination = sum_to_destination.saturating_add(value);
        }
    }

    if sum_to_destination != expected_amount {
        return Err(IssuanceVerificationError::AmountMismatch {
            asset_id,
            expected: expected_amount,
            found: sum_to_destination,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::options::{OptionsArguments, get_options_address};
    use crate::sdk::taproot_pubkey_gen::TaprootPubkeyGen;
    use simplicityhl::elements::confidential::{Asset as ConfidentialAsset, Nonce, Value};
    use simplicityhl::elements::hashes::Hash;
    use simplicityhl::elements::pset::serialize::Deserialize;
    use simplicityhl::elements::secp256k1_zkp::{Generator, Secp256k1, Tweak, ZERO_TWEAK};
    use simplicityhl::elements::{
        AssetIssuance, LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut, TxOutWitness, Txid,
    };
    use simplicityhl_core::{Encodable, SimplicityNetwork};

    fn outpoint(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::all_zeros(),
            vout,
        }
    }

    fn new_issuance_input(vout: u32, contract_hash: [u8; 32], amount: u64, keys: u64) -> TxIn {
        TxIn {
            previous_output: outpoint(vout),
            sequence: Sequence::MAX,
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: ZERO_TWEAK,
                asset_entropy: contract_hash,
                amount: if amount == 0 {
                    Value::Null
                } else {
                    Value::Explicit(amount)
                },
                inflation_keys: if keys == 0 {
                    Value::Null
                } else {
                    Value::Explicit(keys)
                },
            },
            ..Default::default()
        }
    }

    fn reissuance_input(vout: u32, entropy: [u8; 32]) -> TxIn {
        TxIn {
            previous_output: outpoint(vout),
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: Tweak::from_inner([1u8; 32]).expect("valid tweak"),
                asset_entropy: entropy,
                amount: Value::Explicit(1),
                inflation_keys: Value::Null,
            },
            ..Default::default()
        }
    }

    fn tx_out_explicit(script: Script, asset_id: AssetId, value: u64) -> TxOut {
        TxOut {
            asset: ConfidentialAsset::Explicit(asset_id),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness::default(),
        }
    }

    fn tx_out_confidential_asset(script: Script) -> TxOut {
        // Create a valid confidential asset generator.
        let secp = Secp256k1::new();
        let generator = Generator::new_unblinded(&secp, AssetId::LIQUID_BTC.into_tag());
        TxOut {
            asset: ConfidentialAsset::Confidential(generator),
            value: Value::Explicit(1),
            nonce: Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness::default(),
        }
    }

    fn tx_with(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    #[test]
    fn verify_issuance_happy_path_sums_to_destinations() {
        let issue_script = Script::from(vec![0x51]);
        let token_script = Script::from(vec![0x52]);

        let inp0 = new_issuance_input(0, [7u8; 32], 50, 1);
        let (asset_id, token_id) = inp0.issuance_ids();

        let tx = tx_with(
            vec![inp0],
            vec![
                tx_out_explicit(issue_script.clone(), asset_id, 25),
                tx_out_explicit(issue_script.clone(), asset_id, 25),
                tx_out_explicit(token_script.clone(), token_id, 1),
                tx_out_confidential_asset(Script::from(vec![0x6a])),
            ],
        );

        let constraints = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: Some((issue_script, 50, None)),
                reissuance_destination: Some((token_script, 1, None)),
            }],
            ..Default::default()
        };

        assert_eq!(verify_issuance(&tx, &constraints), Ok(()));
    }

    #[test]
    fn verify_issuance_fails_on_wrong_script() {
        let issue_script = Script::from(vec![0x51]);
        let wrong_script = Script::from(vec![0x52]);
        let token_script = Script::from(vec![0x53]);

        let inp0 = new_issuance_input(0, [9u8; 32], 10, 1);
        let (asset_id, token_id) = inp0.issuance_ids();

        let tx = tx_with(
            vec![inp0],
            vec![
                tx_out_explicit(wrong_script, asset_id, 10),
                tx_out_explicit(token_script.clone(), token_id, 1),
            ],
        );

        let constraints = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: Some((issue_script, 10, None)),
                reissuance_destination: Some((token_script, 1, None)),
            }],
            ..Default::default()
        };

        assert!(matches!(
            verify_issuance(&tx, &constraints),
            Err(IssuanceVerificationError::AssetAppearsInUnexpectedOutput { .. })
        ));
    }

    #[test]
    fn verify_issuance_fails_on_amount_mismatch() {
        let issue_script = Script::from(vec![0x51]);
        let token_script = Script::from(vec![0x52]);

        let inp0 = new_issuance_input(0, [11u8; 32], 10, 1);
        let (asset_id, token_id) = inp0.issuance_ids();

        let tx = tx_with(
            vec![inp0],
            vec![
                tx_out_explicit(issue_script.clone(), asset_id, 9),
                tx_out_explicit(token_script.clone(), token_id, 1),
            ],
        );

        let constraints = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: Some((issue_script, 10, None)),
                reissuance_destination: Some((token_script, 1, None)),
            }],
            ..Default::default()
        };

        assert!(matches!(
            verify_issuance(&tx, &constraints),
            Err(IssuanceVerificationError::AmountMismatch { .. })
        ));
    }

    #[test]
    fn verify_issuance_none_destination_requires_zero_and_no_appearances() {
        let token_script = Script::from(vec![0x52]);

        let inp0 = new_issuance_input(0, [13u8; 32], 0, 1);
        let (asset_id, token_id) = inp0.issuance_ids();

        let tx = tx_with(
            vec![inp0],
            vec![
                // Value 0 still counts as an appearance.
                tx_out_explicit(Script::from(vec![0x51]), asset_id, 0),
                tx_out_explicit(token_script.clone(), token_id, 1),
            ],
        );

        let constraints = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: None,
                reissuance_destination: Some((token_script, 1, None)),
            }],
            ..Default::default()
        };

        assert!(matches!(
            verify_issuance(&tx, &constraints),
            Err(IssuanceVerificationError::AssetAppearsInUnexpectedOutput { .. })
        ));
    }

    #[test]
    fn verify_issuance_fails_if_any_issuance_input_is_reissuance() {
        let tx = tx_with(vec![reissuance_input(0, [0u8; 32])], vec![]);
        let constraints = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: None,
                reissuance_destination: None,
            }],
            ..Default::default()
        };

        assert_eq!(
            verify_issuance(&tx, &constraints),
            Err(IssuanceVerificationError::ReissuanceInputFound { input_idx: 0 })
        );
    }

    #[test]
    fn verify_issuance_coverage_policy_allows_extra_issuance_when_enabled() {
        let issue_script = Script::from(vec![0x51]);
        let token_script = Script::from(vec![0x52]);

        let inp0 = new_issuance_input(0, [21u8; 32], 10, 1);
        let (asset_id, token_id) = inp0.issuance_ids();

        let inp1 = new_issuance_input(1, [22u8; 32], 1, 1);

        let tx = tx_with(
            vec![inp0, inp1],
            vec![
                tx_out_explicit(issue_script.clone(), asset_id, 10),
                tx_out_explicit(token_script.clone(), token_id, 1),
            ],
        );

        let constraints_strict = IssuanceTxConstraints {
            inputs: vec![IssuanceInputConstraints {
                input_idx: 0,
                issuance_destination: Some((issue_script, 10, None)),
                reissuance_destination: Some((token_script, 1, None)),
            }],
            ..Default::default()
        };

        assert_eq!(
            verify_issuance(&tx, &constraints_strict),
            Err(IssuanceVerificationError::UnexpectedIssuanceInput { input_idx: 1 })
        );

        let constraints_allow = IssuanceTxConstraints {
            allow_unconstrained_issuances: true,
            ..constraints_strict
        };

        assert_eq!(verify_issuance(&tx, &constraints_allow), Ok(()));
    }

    #[test]
    fn test_verify_issuance_valid() -> Result<(), String> {
        let option_arguments_str = include_str!("./test_data/option_arguments.hex");
        let option_arguments =
            OptionsArguments::decode(&hex::decode(option_arguments_str).expect("Invalid hex"))
                .unwrap();

        let taproot_str = include_str!("./test_data/taproot.hex");
        let taproot_gen = TaprootPubkeyGen::build_from_str(
            taproot_str,
            &option_arguments,
            SimplicityNetwork::LiquidTestnet,
            &get_options_address,
        )
        .unwrap();

        let tx_hex = include_str!("./test_data/transaction.hex");
        let tx_bytes = hex::decode(tx_hex.trim()).unwrap();
        let tx: Transaction = Deserialize::deserialize(&tx_bytes[..]).unwrap();

        let constraints = IssuanceTxConstraints {
            inputs: vec![
                IssuanceInputConstraints {
                    input_idx: 0,
                    issuance_destination: None,
                    reissuance_destination: Some((taproot_gen.address.script_pubkey(), 1, None)),
                },
                IssuanceInputConstraints {
                    input_idx: 1,
                    issuance_destination: None,
                    reissuance_destination: Some((taproot_gen.address.script_pubkey(), 1, None)),
                },
            ],
            ..Default::default()
        };

        verify_issuance(&tx, &constraints).map_err(|e| format!("Verification failed: {e:?}"))?;

        Ok(())
    }
}
