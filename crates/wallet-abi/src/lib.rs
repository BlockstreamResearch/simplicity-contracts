#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::default_trait_access,
        clippy::iter_on_single_items,
        clippy::needless_pass_by_value,
        clippy::too_many_lines
    )
)]

pub mod encoding;
pub mod error;
pub mod runtime;
pub mod schema;
pub mod scripts;
pub mod simplicity;
pub mod taproot_pubkey_gen;
pub mod tx_inclusion;

pub use encoding::Encodable;
pub use error::WalletAbiError;
pub use lwk_common::Network;
pub use lwk_simplicity::error::ProgramError;
pub use lwk_simplicity::runner::run_program;
pub use lwk_simplicity::signer::{finalize_transaction, get_and_verify_env, get_sighash_all};
pub use schema::runtime_params::*;
pub use scripts::{
    control_block, create_p2tr_address, get_new_asset_entropy, hash_script, load_program,
    simplicity_leaf_version, tap_data_hash,
};
pub use simplicity::p2pk::{P2PK_SOURCE, execute_p2pk_program, get_p2pk_address, get_p2pk_program};

pub use tx_inclusion::*;
