use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::json;
use tempfile::tempdir;
use wallet_abi_qrgen::transport::{WalletAbiTransportResponseV1, encode_transport_response};

const TESTNET_ADDRESS: &str = "tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m";
const ENTROPY_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const REISSUE_TOKEN_ASSET_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn simple_transfer_writes_expected_artifacts() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "simple-transfer",
        "--to-address",
        TESTNET_ADDRESS,
        "--amount-sat",
        "1234",
        "--request-id",
        "req-cli-1",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .success()
        .stdout(contains("request_id: req-cli-1"))
        .stdout(contains("deep_link:"));

    assert_request_artifacts_exist(tmp.path(), "req-cli-1");

    let deep_link =
        fs::read_to_string(tmp.path().join("req-cli-1.deep_link.txt")).expect("deep link readable");
    assert!(deep_link.contains("#wa_v1="));
}

#[test]
fn split_transfer_writes_expected_artifacts() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "split-transfer",
        "--to-address",
        TESTNET_ADDRESS,
        "--split-parts",
        "3",
        "--part-amount-sat",
        "1000",
        "--request-id",
        "req-cli-split",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .success()
        .stdout(contains("request_id: req-cli-split"))
        .stdout(contains("deep_link:"));

    assert_request_artifacts_exist(tmp.path(), "req-cli-split");
}

#[test]
fn issue_asset_writes_expected_artifacts() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "issue-asset",
        "--to-address",
        TESTNET_ADDRESS,
        "--issue-amount-sat",
        "5000",
        "--token-amount-sat",
        "1",
        "--issuance-entropy-hex",
        ENTROPY_HEX,
        "--request-id",
        "req-cli-issue",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .success()
        .stdout(contains("request_id: req-cli-issue"))
        .stdout(contains("deep_link:"));

    assert_request_artifacts_exist(tmp.path(), "req-cli-issue");
}

#[test]
fn reissue_asset_writes_expected_artifacts() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "reissue-asset",
        "--to-address",
        TESTNET_ADDRESS,
        "--reissue-token-asset-id",
        REISSUE_TOKEN_ASSET_ID,
        "--reissue-amount-sat",
        "2000",
        "--asset-entropy-hex",
        ENTROPY_HEX,
        "--token-change-sat",
        "1",
        "--request-id",
        "req-cli-reissue",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .success()
        .stdout(contains("request_id: req-cli-reissue"))
        .stdout(contains("deep_link:"));

    assert_request_artifacts_exist(tmp.path(), "req-cli-reissue");
}

#[test]
fn same_device_https_requires_callback_url() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "simple-transfer",
        "--to-address",
        TESTNET_ADDRESS,
        "--amount-sat",
        "1000",
        "--request-id",
        "req-cli-2",
        "--callback-mode",
        "same_device_https",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .failure()
        .stderr(contains("callback_url is required"));
}

#[test]
fn qr_roundtrip_rejects_callback_url() {
    let tmp = tempdir().expect("tempdir");
    let out_dir = tmp.path().to_string_lossy().to_string();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args([
        "simple-transfer",
        "--to-address",
        TESTNET_ADDRESS,
        "--amount-sat",
        "1000",
        "--request-id",
        "req-cli-3",
        "--callback-mode",
        "qr_roundtrip",
        "--callback-url",
        "https://dapp.example/callback",
        "--out-dir",
        &out_dir,
    ]);

    cmd.assert()
        .failure()
        .stderr(contains("callback_url must be omitted for qr_roundtrip"));
}

#[test]
fn parse_payload_auto_decodes_raw_response_payload() {
    let envelope = WalletAbiTransportResponseV1 {
        v: 1,
        request_id: "req-resp-cli-1".to_string(),
        origin: "https://dapp.example".to_string(),
        processed_at_ms: 1_700_000_000_555,
        tx_create_response: Some(json!({
            "request_id": "req-resp-cli-1",
            "status": "ok"
        })),
        error: None,
    };
    let payload = encode_transport_response(&envelope).expect("payload");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args(["parse-payload", payload.as_str()]);

    cmd.assert()
        .success()
        .stdout(contains("kind: response"))
        .stdout(contains("request_id: req-resp-cli-1"));
}

#[test]
fn parse_payload_auto_extracts_response_from_callback_fragment() {
    let envelope = WalletAbiTransportResponseV1 {
        v: 1,
        request_id: "req-resp-cli-2".to_string(),
        origin: "https://dapp.example".to_string(),
        processed_at_ms: 1_700_000_000_666,
        tx_create_response: Some(json!({
            "request_id": "req-resp-cli-2",
            "status": "error"
        })),
        error: Some(
            wallet_abi_qrgen::transport::WalletAbiTransportResponseError {
                code: "transport_error".to_string(),
                message: "something went wrong".to_string(),
            },
        ),
    };
    let payload = encode_transport_response(&envelope).expect("payload");
    let callback = format!("https://dapp.example/walletabi/callback#wa_resp_v1={payload}");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args(["parse-payload", callback.as_str()]);

    cmd.assert()
        .success()
        .stdout(contains("kind: response"))
        .stdout(contains("request_id: req-resp-cli-2"));
}

#[test]
fn relay_connect_help_includes_nested_request_commands() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args(["relay-connect", "--help"]);

    cmd.assert()
        .success()
        .stdout(contains("simple-transfer"))
        .stdout(contains("split-transfer"))
        .stdout(contains("issue-asset"))
        .stdout(contains("reissue-asset"))
        .stdout(contains("option-offer"));
}

#[test]
fn relay_connect_option_offer_help_includes_all_branches() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args(["relay-connect", "option-offer", "--help"]);

    cmd.assert()
        .success()
        .stdout(contains("create"))
        .stdout(contains("exercise"))
        .stdout(contains("withdraw"))
        .stdout(contains("expiry"));
}

#[test]
fn option_offer_state_help_includes_import_and_export() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("wallet-abi-qrgen"));
    cmd.args(["option-offer-state", "--help"]);

    cmd.assert()
        .success()
        .stdout(contains("import"))
        .stdout(contains("export"));
}

fn assert_request_artifacts_exist(base: &std::path::Path, request_id: &str) {
    let tx_path = base.join(format!("{request_id}.tx_create_request.json"));
    let transport_path = base.join(format!("{request_id}.transport_request.json"));
    let deep_link_path = base.join(format!("{request_id}.deep_link.txt"));
    let qr_path = base.join(format!("{request_id}.qr.png"));

    assert!(tx_path.exists(), "missing tx request artifact");
    assert!(
        transport_path.exists(),
        "missing transport request artifact"
    );
    assert!(deep_link_path.exists(), "missing deep link artifact");
    assert!(qr_path.exists(), "missing png artifact");
}
