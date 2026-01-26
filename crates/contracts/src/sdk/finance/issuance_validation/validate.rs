use simplicityhl::elements::{AssetId, Script, Transaction};

use thiserror::Error;

pub trait IssuanceSpec {
    fn get_primary_issuance_id(&self) -> AssetId;
    fn get_secondary_issuance_id(&self) -> AssetId;
    fn get_controlling_reissuance_id(&self) -> AssetId;
}

#[derive(Error, Debug)]
pub enum IssuanceVerificationError {
    #[error("Invalid issuance count: expected exactly 2 inputs with issuances, found {found}")]
    InvalidIssuanceCount { found: usize },

    #[error(
        "Primary Generator input is missing or invalid. Check Asset ID, ensure Amount is Null and Inflation Keys are Explicit."
    )]
    InvalidPrimaryGeneratorInput,

    #[error(
        "Secondary Generator input is missing or invalid. Check Asset ID, ensure Amount is Null and Inflation Keys are Explicit."
    )]
    InvalidSecondaryGeneratorInput,

    #[error(
        "Security Breach: Controlling reissuance token explicitly sent to external wallet at output #{0}"
    )]
    ControllingReissuanceExplicitLeak(usize),

    #[error(
        "Potential Security Breach: Unknown confidential outputs detected outside the covenant"
    )]
    ConfidentialOutputLeak,

    #[error("Failure: Controlling reissuance token not found in covenant")]
    ControllingReissuanceMissingFromCovenant,
}

/// Verifies the issuance against the provided transaction.
///
/// # Errors
///
/// Returns an [`IssuanceVerificationError`] if the transaction or script validation fails.
pub fn verify_issuance(
    tx: &Transaction,
    def: &impl IssuanceSpec,
    expected_covenant_script: &Script,
) -> Result<(), IssuanceVerificationError> {
    verify_issuances_input(tx, def)?;
    verify_reissuance_output(tx, def, expected_covenant_script)?;

    Ok(())
}

fn verify_issuances_input(
    tx: &Transaction,
    def: &impl IssuanceSpec,
) -> Result<(), IssuanceVerificationError> {
    let issuances: Vec<_> = tx
        .input
        .iter()
        .filter(|i| !i.asset_issuance.is_null())
        .collect();

    if issuances.len() != 2 {
        return Err(IssuanceVerificationError::InvalidIssuanceCount {
            found: issuances.len(),
        });
    }

    let primary_asset = def.get_primary_issuance_id();
    let secondary_asset = def.get_secondary_issuance_id();

    let valid_primary_issuance = issuances.iter().any(|i| {
        let issued_id = i.issuance_ids().0;
        issued_id == primary_asset
            && i.asset_issuance.amount.is_null()
            && i.asset_issuance.inflation_keys.is_explicit()
    });

    let valid_secondary_issuance = issuances.iter().any(|i| {
        let issued_id = i.issuance_ids().0;
        issued_id == secondary_asset
            && i.asset_issuance.amount.is_null()
            && i.asset_issuance.inflation_keys.is_explicit()
    });

    if !valid_primary_issuance {
        return Err(IssuanceVerificationError::InvalidPrimaryGeneratorInput);
    }
    if !valid_secondary_issuance {
        return Err(IssuanceVerificationError::InvalidSecondaryGeneratorInput);
    }

    Ok(())
}

fn verify_reissuance_output(
    tx: &Transaction,
    def: &impl IssuanceSpec,
    covenant_script: &Script,
) -> Result<(), IssuanceVerificationError> {
    let controlling_reissuance = def.get_controlling_reissuance_id();

    let mut potential_leak = false;

    for (i, output) in tx.output.iter().enumerate() {
        // Skip outputs going to the Covenant (These are safe)
        if output.script_pubkey == *covenant_script {
            continue;
        }

        if let Some(asset_id) = output.asset.explicit() {
            if asset_id == controlling_reissuance {
                return Err(IssuanceVerificationError::ControllingReissuanceExplicitLeak(i));
            }
        } else {
            println!("Output #{i} is Confidential and goes to an external address.");
            potential_leak = true;
        }
    }

    if potential_leak {
        return Err(IssuanceVerificationError::ConfidentialOutputLeak);
    }

    let secured = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == *covenant_script)
        .any(|o| o.asset.explicit() == Some(controlling_reissuance) || o.asset.is_confidential());

    if !secured {
        return Err(IssuanceVerificationError::ControllingReissuanceMissingFromCovenant);
    }

    Ok(())
}
