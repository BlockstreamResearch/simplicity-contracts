use std::collections::HashMap;

use simplicityhl::parse::ParseFromStr;
use simplicityhl::simplicity::bitcoin;
use simplicityhl::{ResolvedType, WitnessValues, str::WitnessName, types::TypeConstructible};

#[derive(Debug, Default, Copy, Clone)]
pub enum MergeBranch {
    // Left(Left(())) => merge 2 tokens
    #[default]
    Two,
    // Left(Right(())) => merge 3 tokens
    Three,
    // Right(()) => merge 4 tokens
    Four,
}

impl MergeBranch {
    fn to_str(self) -> &'static str {
        match self {
            MergeBranch::Two => "Left(Left(()))",
            MergeBranch::Three => "Left(Right(()))",
            MergeBranch::Four => "Right(())",
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum TokenBranch {
    // Left(()) in SIMF
    #[default]
    Maker,
    // Right(()) in SIMF
    Taker,
}

impl TokenBranch {
    fn to_str(self) -> &'static str {
        match self {
            TokenBranch::Maker => "Left(())",
            TokenBranch::Taker => "Right(())",
        }
    }
}

#[derive(Debug)]
pub enum DcdBranch<'a> {
    // Left(Left(Left((u64, u64, u64, u64))))
    MakerFunding {
        principal_collateral_amount: u64,
        principal_asset_amount: u64,
        interest_collateral_amount: u64,
        interest_asset_amount: u64,
    },
    // Left(Left(Right((u64, u64, bool))))
    TakerFunding {
        collateral_amount_to_deposit: u64,
        filler_token_amount_to_get: u64,
        is_change_needed: bool,
    },
    // Left(Right((u64, Signature, u32, u64, u64, bool)))
    Settlement {
        price_at_current_block_height: u64,
        oracle_sig: &'a bitcoin::secp256k1::schnorr::Signature,
        index_to_spend: u32,
        amount_to_burn: u64,
        amount_to_get: u64,
        is_change_needed: bool,
    },
    // Right(Left((bool, u32, u64, u64)))
    TakerEarlyTermination {
        is_change_needed: bool,
        index_to_spend: u32,
        filler_token_amount_to_return: u64,
        collateral_amount_to_get: u64,
    },
    // Right(Right((bool, u32, u64, u64)))
    MakerTermination {
        is_change_needed: bool,
        index_to_spend: u32,
        grantor_token_amount_to_burn: u64,
        amount_to_get: u64,
    },
    // Right(Right(())) with MERGE_BRANCH controlling merge routine
    Merge,
}

/// Build witness values for DCD program execution.
///
/// # Panics
/// Panics if type parsing fails (should never happen with valid constants).
#[must_use]
pub fn build_dcd_witness(
    token_branch: TokenBranch,
    branch: &DcdBranch,
    merge_branch: MergeBranch,
) -> WitnessValues {
    // Types
    let maker_funding = ResolvedType::parse_from_str("(u64, u64, u64, u64)").unwrap();
    let taker_funding = ResolvedType::parse_from_str("(u64, u64, bool)").unwrap();
    let settlement = ResolvedType::parse_from_str("(u64, Signature, u32, u64, u64, bool)").unwrap();
    let taker_termination = ResolvedType::parse_from_str("(bool, u32, u64, u64)").unwrap();
    let maker_termination = ResolvedType::parse_from_str("(bool, u32, u64, u64)").unwrap();

    let funding_either = ResolvedType::either(maker_funding, taker_funding);
    let left_type = ResolvedType::either(funding_either, settlement);
    let termination_or_maker = ResolvedType::either(taker_termination, maker_termination);
    let right_type = ResolvedType::either(
        termination_or_maker,
        ResolvedType::parse_from_str("()").unwrap(),
    );
    let path_type = ResolvedType::either(left_type, right_type);

    // Merge branch type: Either<Either<(), ()>, ()>
    let merge_choice = ResolvedType::either(
        ResolvedType::parse_from_str("()").unwrap(),
        ResolvedType::parse_from_str("()").unwrap(),
    );
    let merge_type =
        ResolvedType::either(merge_choice, ResolvedType::parse_from_str("()").unwrap());

    // Values
    let branch_str = match branch {
        DcdBranch::MakerFunding {
            principal_collateral_amount,
            principal_asset_amount,
            interest_collateral_amount,
            interest_asset_amount,
        } => {
            format!(
                "Left(Left(Left(({principal_collateral_amount}, {principal_asset_amount}, {interest_collateral_amount}, {interest_asset_amount}))))"
            )
        }
        DcdBranch::TakerFunding {
            collateral_amount_to_deposit,
            filler_token_amount_to_get,
            is_change_needed,
        } => {
            format!(
                "Left(Left(Right(({collateral_amount_to_deposit}, {filler_token_amount_to_get}, {is_change_needed}))))"
            )
        }
        DcdBranch::Settlement {
            price_at_current_block_height,
            oracle_sig,
            index_to_spend,
            amount_to_burn,
            amount_to_get,
            is_change_needed,
        } => {
            let sig_hex = hex::encode(oracle_sig.serialize());
            format!(
                "Left(Right(({price_at_current_block_height}, 0x{sig_hex}, {index_to_spend}, {amount_to_burn}, {amount_to_get}, {is_change_needed})))"
            )
        }
        DcdBranch::TakerEarlyTermination {
            is_change_needed,
            index_to_spend,
            filler_token_amount_to_return,
            collateral_amount_to_get,
        } => {
            format!(
                "Right(Left(Left(({is_change_needed}, {index_to_spend}, {filler_token_amount_to_return}, {collateral_amount_to_get}))))"
            )
        }
        DcdBranch::MakerTermination {
            is_change_needed,
            index_to_spend,
            grantor_token_amount_to_burn,
            amount_to_get,
        } => {
            format!(
                "Right(Left(Right(({is_change_needed}, {index_to_spend}, {grantor_token_amount_to_burn}, {amount_to_get}))))"
            )
        }
        DcdBranch::Merge => "Right(Right(()))".to_string(),
    };

    simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("TOKEN_BRANCH"),
            simplicityhl::Value::parse_from_str(
                token_branch.to_str(),
                &ResolvedType::either(
                    ResolvedType::parse_from_str("()").unwrap(),
                    ResolvedType::parse_from_str("()").unwrap(),
                ),
            )
            .unwrap(),
        ),
        (
            WitnessName::from_str_unchecked("PATH"),
            simplicityhl::Value::parse_from_str(&branch_str, &path_type).unwrap(),
        ),
        (
            WitnessName::from_str_unchecked("MERGE_BRANCH"),
            simplicityhl::Value::parse_from_str(merge_branch.to_str(), &merge_type).unwrap(),
        ),
    ]))
}
