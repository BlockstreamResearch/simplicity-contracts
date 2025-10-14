use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::elements::{Address, AddressParams};
use simplicityhl_core::{Encodable, TaprootPubkeyGen};

#[derive(Clone, Debug)]
pub struct Store {
    pub store: sled::Db,
}

impl Store {
    pub fn load() -> anyhow::Result<Self> {
        Ok(Self {
            store: sled::open(".cache/store")?,
        })
    }

    pub fn import_arguments<A>(
        &self,
        taproot_pubkey_gen: &str,
        encoded_data: &str,
        params: &'static AddressParams,
        get_address: &impl Fn(&XOnlyPublicKey, &A, &'static AddressParams) -> anyhow::Result<Address>,
    ) -> anyhow::Result<()>
    where
        A: Encodable + simplicityhl_core::encoding::Decode<()>,
    {
        let decoded_data = hex::decode(encoded_data)?;

        let arguments = Encodable::decode(&decoded_data)?;
        let _ =
            TaprootPubkeyGen::build_from_str(taproot_pubkey_gen, &arguments, params, get_address)?;

        self.store.insert(taproot_pubkey_gen, decoded_data)?;

        Ok(())
    }

    pub fn export_arguments(&self, taproot_pubkey_gen: &str) -> anyhow::Result<String> {
        if let Some(value) = self.store.get(taproot_pubkey_gen)? {
            return Ok(hex::encode(value));
        }

        anyhow::bail!("Arguments not found");
    }

    pub fn get_arguments<A>(&self, taproot_pubkey_gen: &str) -> anyhow::Result<A>
    where
        A: Encodable + simplicityhl_core::encoding::Decode<()>,
    {
        if let Some(value) = self.store.get(taproot_pubkey_gen)? {
            return Encodable::decode(&value).map_err(anyhow::Error::msg);
        }

        anyhow::bail!("Arguments not found");
    }
}

#[cfg(test)]
mod tests {
    use contracts::OptionsArguments;
    use simplicityhl::simplicity::elements;
    use simplicityhl_core::{Encodable, LIQUID_TESTNET_TEST_ASSET_ID_STR};

    use super::*;

    fn load_mock() -> Store {
        Store {
            store: sled::Config::new()
                .temporary(true)
                .open()
                .expect("expected store"),
        }
    }

    fn get_mocked_data() -> anyhow::Result<(OptionsArguments, TaprootPubkeyGen)> {
        let args = OptionsArguments {
            start_time: 10,
            expiry_time: 50,
            contract_size: 100,
            asset_strike_price: 1000,
            grantor_token_strike_price: 1000,
            lbtc_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            reissuance_option_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            grantor_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            reissuance_grantor_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
        };

        let options_taproot_pubkey_gen = TaprootPubkeyGen::from(
            &args,
            &AddressParams::LIQUID_TESTNET,
            &contracts::get_options_address,
        )?;

        Ok((args, options_taproot_pubkey_gen))
    }

    #[test]
    fn test_sled_serialize_deserialize() -> anyhow::Result<()> {
        let store = load_mock();

        let (args, options_taproot_pubkey_gen) = get_mocked_data()?;

        store.import_arguments(
            &options_taproot_pubkey_gen.to_string(),
            &args.to_hex()?,
            &AddressParams::LIQUID_TESTNET,
            &contracts::get_options_address,
        )?;

        let retrieved =
            store.get_arguments::<OptionsArguments>(&options_taproot_pubkey_gen.to_string())?;

        assert_eq!(args, retrieved);

        Ok(())
    }

    #[test]
    fn test_sled_import_export_roundtrip() -> anyhow::Result<()> {
        let store = load_mock();

        let (args, options_taproot_pubkey_gen) = get_mocked_data()?;

        store.import_arguments(
            &options_taproot_pubkey_gen.to_string(),
            &args.to_hex()?,
            &AddressParams::LIQUID_TESTNET,
            &contracts::get_options_address,
        )?;

        let exported_hex = store.export_arguments(&options_taproot_pubkey_gen.to_string())?;

        assert_eq!(exported_hex, args.to_hex()?);

        Ok(())
    }

    #[test]
    fn test_sled_export_get_consistency() -> anyhow::Result<()> {
        let store = load_mock();

        let (args, options_taproot_pubkey_gen) = get_mocked_data()?;

        store.import_arguments(
            &options_taproot_pubkey_gen.to_string(),
            &args.to_hex()?,
            &AddressParams::LIQUID_TESTNET,
            &contracts::get_options_address,
        )?;

        let exported_hex = store.export_arguments(&options_taproot_pubkey_gen.to_string())?;
        let exported_bytes = hex::decode(&exported_hex)?;
        let decoded_from_export: OptionsArguments = Encodable::decode(&exported_bytes)?;

        let retrieved =
            store.get_arguments::<OptionsArguments>(&options_taproot_pubkey_gen.to_string())?;

        assert_eq!(decoded_from_export, retrieved);
        assert_eq!(retrieved, args);

        Ok(())
    }
}
