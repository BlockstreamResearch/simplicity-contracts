use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, WitnessValues, parse::ParseFromStr, str::WitnessName, types::TypeConstructible,
};

#[derive(Debug, Default)]
pub enum TokenBranch {
    #[default]
    OptionToken,
    GrantorToken,
}

impl TokenBranch {
    fn to_str(&self) -> &str {
        match self {
            TokenBranch::OptionToken => "Left(())",
            TokenBranch::GrantorToken => "Right(())",
        }
    }
}

#[derive(Debug)]
pub enum OptionBranch {
    Funding {
        expected_asset_amount: u64,
    },
    Exercise {
        amount_to_burn: u64,
        collateral_amount_to_get: u64,
        asset_amount: u64,
    },
    Expiry {
        grantor_token_amount_to_burn: u64,
        collateral_amount_to_withdraw: u64,
    },
    Cancellation {
        amount_to_burn: u64,
        collateral_amount_to_withdraw: u64,
    },
}

pub fn build_option_witness(token_branch: TokenBranch, branch: OptionBranch) -> WitnessValues {
    let single = ResolvedType::parse_from_str("u64").unwrap();
    let triple = ResolvedType::parse_from_str("(u64, u64, u64)").unwrap();
    let pair = ResolvedType::parse_from_str("(u64, u64)").unwrap();

    let left_type = ResolvedType::either(single.clone(), triple.clone());
    let right_type = ResolvedType::either(pair.clone(), pair.clone());
    let path_type = ResolvedType::either(left_type, right_type);

    let branch_str = match branch {
        OptionBranch::Funding {
            expected_asset_amount,
        } => {
            format!("Left(Left({expected_asset_amount}))")
        }
        OptionBranch::Exercise {
            amount_to_burn,
            collateral_amount_to_get: collateral_amount,
            asset_amount,
        } => {
            format!("Left(Right(({amount_to_burn}, {collateral_amount}, {asset_amount})))")
        }
        OptionBranch::Expiry {
            grantor_token_amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => {
            format!("Right(Left(({grantor_token_amount_to_burn}, {collateral_amount})))")
        }
        OptionBranch::Cancellation {
            amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => {
            format!("Right(Right(({amount_to_burn}, {collateral_amount})))")
        }
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
    ]))
}
