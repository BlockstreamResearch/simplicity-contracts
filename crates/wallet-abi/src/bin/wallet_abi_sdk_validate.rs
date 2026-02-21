use std::env;
use std::io::{self, Read};

use wallet_abi::schema::tx_create::TxCreateRequest;
use wallet_abi::{Network, WalletAbiError};

fn parse_runtime_network_from_cli(args: &[String]) -> Result<Option<Network>, WalletAbiError> {
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--runtime-network" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    WalletAbiError::InvalidRequest(
                        "missing value for '--runtime-network' argument".to_string(),
                    )
                })?;
                let parsed = value
                    .parse::<Network>()
                    .map_err(WalletAbiError::InvalidRequest)?;
                return Ok(Some(parsed));
            }
            "--help" | "-h" => {
                println!("Usage: wallet_abi_sdk_validate [--runtime-network <network>]\n");
                println!(
                    "Reads a TxCreateRequest JSON payload from stdin and validates ABI envelope fields."
                );
                println!("Networks: liquid | testnet-liquid | localtest-liquid");
                std::process::exit(0);
            }
            _ => {}
        }
        index += 1;
    }

    Ok(None)
}

fn parse_runtime_network_from_env() -> Result<Option<Network>, WalletAbiError> {
    let maybe_value = env::var("WALLET_ABI_RUNTIME_NETWORK").ok();

    maybe_value
        .map(|value| {
            value
                .parse::<Network>()
                .map_err(WalletAbiError::InvalidRequest)
        })
        .transpose()
}

fn run() -> Result<(), WalletAbiError> {
    let cli_args: Vec<String> = env::args().skip(1).collect();
    let cli_runtime_network = parse_runtime_network_from_cli(&cli_args)?;
    let env_runtime_network = parse_runtime_network_from_env()?;

    let mut stdin_payload = String::new();
    io::stdin().read_to_string(&mut stdin_payload)?;

    if stdin_payload.trim().is_empty() {
        return Err(WalletAbiError::InvalidRequest(
            "expected request JSON payload on stdin".to_string(),
        ));
    }

    let request: TxCreateRequest = serde_json::from_str(&stdin_payload).map_err(|error| {
        WalletAbiError::InvalidRequest(format!("invalid request JSON: {error}"))
    })?;

    let runtime_network = cli_runtime_network
        .or(env_runtime_network)
        .unwrap_or(request.network);

    request.validate_for_runtime(runtime_network)?;

    println!("ok");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
