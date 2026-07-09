//! Collateral-for-settlement offer contract with three spending branches:
//! `Exercise`, `Withdraw`, and `Expiry`.

use crate::artifacts::option_offer::OptionOfferProgram;
use crate::artifacts::option_offer::derived_option_offer::{
    OptionOfferArguments, OptionOfferWitness,
};
use crate::programs::program::SimplexProgram;

use simplex::constants::DUMMY_SIGNATURE;
use simplex::either::{Left, Right};
use simplex::program::Program;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, secp256k1_zkp::XOnlyPublicKey};

#[derive(Debug, Clone, Copy)]
pub struct OptionOfferParameters {
    pub collateral_asset_id: AssetId,
    pub premium_asset_id: AssetId,
    pub settlement_asset_id: AssetId,
    pub collateral_per_contract: u64,
    pub premium_per_collateral: u64,
    pub expiry_time: u32,
    pub user_pubkey: XOnlyPublicKey,
    pub network: SimplicityNetwork,
}

impl From<OptionOfferParameters> for OptionOfferArguments {
    fn from(value: OptionOfferParameters) -> Self {
        Self {
            collateral_asset_id: value.collateral_asset_id.into_inner().0,
            premium_asset_id: value.premium_asset_id.into_inner().0,
            settlement_asset_id: value.settlement_asset_id.into_inner().0,
            collateral_per_contract: value.collateral_per_contract,
            premium_per_collateral: value.premium_per_collateral,
            expiry_time: value.expiry_time,
            user_pubkey: value.user_pubkey.serialize(),
        }
    }
}

pub struct OptionOffer {
    program: OptionOfferProgram,
    pub parameters: OptionOfferParameters,
}

#[derive(Debug, Clone, Copy)]
pub enum OptionOfferBranch {
    /// Exercise path: counterparty swaps settlement asset for collateral + premium
    Exercise {
        /// Amount of collateral the counterparty will receive (premium derived from ratio)
        collateral_amount: u64,
        /// Whether there's change (partial swap)
        is_change_needed: bool,
    },
    /// Withdraw path: user withdraws settlement asset
    Withdraw,
    /// Expiry path: user reclaims collateral + premium after expiry
    Expiry,
}

impl OptionOffer {
    #[must_use]
    pub fn new(parameters: OptionOfferParameters) -> Self {
        Self {
            program: OptionOfferProgram::new(OptionOfferArguments::from(parameters)),
            parameters,
        }
    }

    #[must_use]
    pub fn from_internal_key(
        internal_key: XOnlyPublicKey,
        parameters: OptionOfferParameters,
    ) -> Self {
        Self {
            program: OptionOfferProgram::new(OptionOfferArguments::from(parameters))
                .with_taproot_pubkey(internal_key),
            parameters,
        }
    }

    #[must_use]
    pub const fn calculate_per_params(
        collateral_amount_to_deposit: u64,
        expected_settlement: u64,
        expected_premium: u64,
    ) -> (Option<u64>, Option<u64>) {
        let collateral_per_contract = expected_settlement.checked_div(collateral_amount_to_deposit);
        let premium_per_collateral = expected_premium.checked_div(collateral_amount_to_deposit);

        (collateral_per_contract, premium_per_collateral)
    }

    #[must_use]
    pub const fn get_witness(option_offer_branch: OptionOfferBranch) -> OptionOfferWitness {
        let path = match option_offer_branch {
            OptionOfferBranch::Exercise {
                collateral_amount,
                is_change_needed,
            } => Left((collateral_amount, is_change_needed)),
            OptionOfferBranch::Withdraw => Right(Left(())),
            OptionOfferBranch::Expiry => Right(Right(())),
        };

        OptionOfferWitness {
            user_sighash_all: DUMMY_SIGNATURE,
            path,
        }
    }
}

impl SimplexProgram for OptionOffer {
    fn get_program(&self) -> &Program {
        self.program.as_ref()
    }

    fn get_network(&self) -> &SimplicityNetwork {
        &self.parameters.network
    }
}
