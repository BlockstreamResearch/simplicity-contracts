#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod encoding;
pub mod error;
pub mod issuance_validation;
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
