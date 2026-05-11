use simplex::either::{Left, Right};
use simplex::program::Program;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, secp256k1_zkp::XOnlyPublicKey};

use crate::artifacts::options::OptionsProgram;
use crate::artifacts::options::derived_options::{OptionsArguments, OptionsWitness};
use crate::programs::program::SimplexProgram;

#[derive(Debug, Clone, Copy)]
pub struct OptionsParameters {
    pub start_time: u32,
    pub expiry_time: u32,
    pub collateral_per_contract: u64,
    pub settlement_per_contract: u64,
    pub collateral_asset_id: AssetId,
    pub settlement_asset_id: AssetId,
    pub option_token_asset: AssetId,
    pub option_reissuance_token_asset: AssetId,
    pub grantor_token_asset: AssetId,
    pub grantor_reissuance_token_asset: AssetId,
    pub network: SimplicityNetwork,
}

impl From<OptionsParameters> for OptionsArguments {
    fn from(value: OptionsParameters) -> Self {
        Self {
            start_time: value.start_time,
            expiry_time: value.expiry_time,
            collateral_per_contract: value.collateral_per_contract,
            settlement_per_contract: value.settlement_per_contract,
            collateral_asset_id: value.collateral_asset_id.into_inner().0,
            settlement_asset_id: value.settlement_asset_id.into_inner().0,
            option_token_asset: value.option_token_asset.into_inner().0,
            option_reissuance_token_asset: value.option_reissuance_token_asset.into_inner().0,
            grantor_token_asset: value.grantor_token_asset.into_inner().0,
            grantor_reissuance_token_asset: value.grantor_reissuance_token_asset.into_inner().0,
        }
    }
}

pub struct Options {
    program: OptionsProgram,
    pub parameters: OptionsParameters,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OptionsFundingBlinders {
    pub input_option_abf: [u8; 32],
    pub input_option_vbf: [u8; 32],
    pub input_grantor_abf: [u8; 32],
    pub input_grantor_vbf: [u8; 32],
    pub output_option_abf: [u8; 32],
    pub output_option_vbf: [u8; 32],
    pub output_grantor_abf: [u8; 32],
    pub output_grantor_vbf: [u8; 32],
}

impl OptionsFundingBlinders {
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            input_option_abf: [0; 32],
            input_option_vbf: [0; 32],
            input_grantor_abf: [0; 32],
            input_grantor_vbf: [0; 32],
            output_option_abf: [0; 32],
            output_option_vbf: [0; 32],
            output_grantor_abf: [0; 32],
            output_grantor_vbf: [0; 32],
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum OptionsBranch {
    Fund {
        expected_settlement_amount: u64,
        blinders: OptionsFundingBlinders,
    },
    Exercise {
        is_change_needed: bool,
        amount_to_burn: u64,
        collateral_amount: u64,
        settlement_amount: u64,
    },
    Settlement {
        is_change_needed: bool,
        amount_to_burn: u64,
        settlement_amount: u64,
    },
    Expiry {
        is_change_needed: bool,
        amount_to_burn: u64,
        collateral_amount: u64,
    },
    Cancel {
        is_change_needed: bool,
        amount_to_burn: u64,
        collateral_amount: u64,
    },
}

impl Options {
    #[must_use]
    pub fn new(parameters: OptionsParameters) -> Self {
        Self {
            program: OptionsProgram::new(OptionsArguments::from(parameters)),
            parameters,
        }
    }

    #[must_use]
    pub fn from_internal_key(internal_key: XOnlyPublicKey, parameters: OptionsParameters) -> Self {
        Self {
            program: OptionsProgram::new(OptionsArguments::from(parameters))
                .with_pub_key(internal_key),
            parameters,
        }
    }

    #[must_use]
    pub const fn calculate_per_contract_params(
        total_collateral: u64,
        expected_settlement: u64,
        contract_count: u64,
    ) -> (Option<u64>, Option<u64>) {
        let collateral_per_contract = total_collateral.checked_div(contract_count);
        let settlement_per_contract = expected_settlement.checked_div(contract_count);

        (collateral_per_contract, settlement_per_contract)
    }

    #[must_use]
    pub const fn get_witness(branch: OptionsBranch) -> OptionsWitness {
        let path = match branch {
            OptionsBranch::Fund {
                expected_settlement_amount,
                blinders,
            } => Left(Left((
                expected_settlement_amount,
                blinders.input_option_abf,
                blinders.input_option_vbf,
                blinders.input_grantor_abf,
                blinders.input_grantor_vbf,
                blinders.output_option_abf,
                blinders.output_option_vbf,
                blinders.output_grantor_abf,
                blinders.output_grantor_vbf,
            ))),
            OptionsBranch::Exercise {
                is_change_needed,
                amount_to_burn,
                collateral_amount,
                settlement_amount,
            } => Left(Right(Left((
                is_change_needed,
                amount_to_burn,
                collateral_amount,
                settlement_amount,
            )))),
            OptionsBranch::Settlement {
                is_change_needed,
                amount_to_burn,
                settlement_amount,
            } => Left(Right(Right((
                is_change_needed,
                amount_to_burn,
                settlement_amount,
            )))),
            OptionsBranch::Expiry {
                is_change_needed,
                amount_to_burn,
                collateral_amount,
            } => Right(Left((is_change_needed, amount_to_burn, collateral_amount))),
            OptionsBranch::Cancel {
                is_change_needed,
                amount_to_burn,
                collateral_amount,
            } => Right(Right((is_change_needed, amount_to_burn, collateral_amount))),
        };

        OptionsWitness { path }
    }
}

impl SimplexProgram for Options {
    fn get_program(&self) -> &Program {
        self.program.as_ref()
    }

    fn get_network(&self) -> &SimplicityNetwork {
        &self.parameters.network
    }
}
