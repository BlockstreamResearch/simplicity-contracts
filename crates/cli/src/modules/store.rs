#![allow(dead_code)]

use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;
use wallet_abi::{Encodable, ProgramError};

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::elements::Address;

#[derive(Clone, Debug)]
pub struct Store {
    pub store: sled::Db,
}

impl Store {
    /// Load or create the local argument store.
    ///
    /// # Errors
    /// Returns error if the store database cannot be opened.
    pub fn load() -> anyhow::Result<Self> {
        Ok(Self {
            store: sled::open(".cache/store")?,
        })
    }

    /// Import and validate encoded arguments into the store.
    ///
    /// # Errors
    /// Returns error if hex decoding, validation, or storage fails.
    pub fn import_arguments<A>(
        &self,
        taproot_pubkey_gen: &str,
        encoded_data: &str,
        network: lwk_common::Network,
        get_address: &impl Fn(&XOnlyPublicKey, &A, lwk_common::Network) -> Result<Address, ProgramError>,
    ) -> anyhow::Result<()>
    where
        A: Encodable + wallet_abi::encoding::Decode<()>,
    {
        let decoded_data = hex::decode(encoded_data)?;

        let arguments = Encodable::decode(&decoded_data)?;
        let _ =
            TaprootPubkeyGen::build_from_str(taproot_pubkey_gen, &arguments, network, get_address)?;

        self.store.insert(taproot_pubkey_gen, decoded_data)?;

        Ok(())
    }

    /// Export stored arguments as hex-encoded string.
    ///
    /// # Errors
    /// Returns error if arguments are not found.
    pub fn export_arguments(&self, taproot_pubkey_gen: &str) -> anyhow::Result<String> {
        if let Some(value) = self.store.get(taproot_pubkey_gen)? {
            return Ok(hex::encode(value));
        }

        anyhow::bail!("Arguments not found");
    }

    /// Retrieve and decode arguments by name.
    ///
    /// # Errors
    /// Returns error if arguments are not found or decoding fails.
    pub fn get_arguments<A>(&self, arg_name: &str) -> anyhow::Result<A>
    where
        A: Encodable + wallet_abi::encoding::Decode<()>,
    {
        if let Some(value) = self.store.get(arg_name)? {
            return Encodable::decode(&value).map_err(anyhow::Error::msg);
        }

        anyhow::bail!("Arguments not found");
    }
}
