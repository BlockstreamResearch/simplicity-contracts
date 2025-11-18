use anyhow::{anyhow, Result};
use config::{Case, Config};

#[derive(Clone, Debug)]
pub struct Settings {
    pub seed_hex: String,
}

impl Settings {
    pub fn load() -> Result<Self> {
        match dotenvy::dotenv() {
            Ok(_) => {}
            Err(err) => anyhow::bail!("Could not load .env file: {:?}", err),
        }

        let cfg = Config::builder()
            .add_source(
                config::Environment::default()
                    .separator("__")
                    .convert_case(Case::ScreamingSnake),
            )
            .build()?;

        let seed_hex = cfg
            .get_string("SEED_HEX")
            .map_err(|_| anyhow!("SEED_HEX not set in environment or .env"))?;

        Ok(Self { seed_hex })
    }
}
