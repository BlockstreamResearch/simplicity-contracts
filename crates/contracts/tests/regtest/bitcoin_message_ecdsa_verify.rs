#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast};

use contracts::programs::bitcoin_message_ecdsa_verify::{
    BitcoinMessageEcdsaVerify, BitcoinMessageEcdsaVerifyWitness, Scalar,
};

use simplex::simplicityhl::elements::bitcoin::consensus::{Encodable, encode::VarInt};
use simplex::simplicityhl::elements::bitcoin::secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey,
};
use simplex::simplicityhl::elements::bitcoin::sign_message::BITCOIN_SIGNED_MSG_PREFIX;
use simplex::simplicityhl::elements::confidential::Value;
use simplex::simplicityhl::elements::hashes::{Hash, HashEngine, sha256d};
use simplex::simplicityhl::elements::hex::ToHex;
use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplex::simplicityhl::elements::{Script, Transaction, TxOut};
use simplex::simplicityhl::tracker::TrackerLogLevel;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, RequiredSignature, UTXO,
};

const GROUP_ORDER: Scalar = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const FIELD_PRIME: Scalar = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

struct PreparedCase {
    contract: BitcoinMessageEcdsaVerify,
    contract_utxo: UTXO,
    tx: Transaction,
    utxos: Vec<TxOut>,
    r: Scalar,
    s: Scalar,
}

#[simplex::test]
fn bitcoin_message_ecdsa_verify_manual_cases(context: simplex::TestContext) -> anyhow::Result<()> {
    let prepared = prepare_case(&context)?;
    let provider = context.get_default_provider();

    let finalized_tx = finalize_valid_signature(&prepared)?;
    assert_eq!(finalized_tx.input[0].witness.script_witness.len(), 4);
    let spend_receipt = provider.broadcast_transaction(&finalized_tx)?;
    spend_receipt.wait()?;
    let remaining_contract_utxos =
        provider.fetch_scripthash_utxos(&prepared.contract.get_script_pubkey())?;
    assert!(
        remaining_contract_utxos
            .iter()
            .all(|utxo| utxo.outpoint != prepared.contract_utxo.outpoint),
        "contract UTXO was not spent on regtest"
    );

    let mut tampered = prepared.tx.clone();
    tampered.output[0].value = Value::Explicit(2_000);
    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &tampered,
        |nonce_y| BitcoinMessageEcdsaVerify::get_witness(nonce_y, prepared.r, prepared.s),
    );

    let mut wrong_nonce_x = prepared.r;
    wrong_nonce_x[31] ^= 1;
    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| witness_with_nonce_x(nonce_y, wrong_nonce_x, prepared.r, prepared.s),
    );

    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| BitcoinMessageEcdsaVerify::get_witness(nonce_y, [0; 32], prepared.s),
    );

    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| BitcoinMessageEcdsaVerify::get_witness(nonce_y, prepared.r, [0; 32]),
    );

    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| BitcoinMessageEcdsaVerify::get_witness(nonce_y, GROUP_ORDER, prepared.s),
    );

    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| BitcoinMessageEcdsaVerify::get_witness(nonce_y, prepared.r, GROUP_ORDER),
    );

    assert_rejects_for_both_nonce_parities(
        &prepared.contract,
        &prepared.utxos,
        &prepared.tx,
        |nonce_y| witness_with_nonce_x(nonce_y, FIELD_PRIME, prepared.r, prepared.s),
    );

    Ok(())
}

fn prepare_case(context: &simplex::TestContext) -> anyhow::Result<PreparedCase> {
    let network = *context.get_network();
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[3; 32])?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let contract = BitcoinMessageEcdsaVerify::from_public_key(&public_key, network)?;
    let policy_asset = network.policy_asset();
    let contract_amount = 10_000;
    let spend_fee = 1_000;
    let funding_input_amount = 20_000;

    let funding_utxo = ensure_exact_signer_utxo(context, policy_asset, funding_input_amount)?;
    let mut funding = FinalTransaction::new();
    funding.add_input(
        PartialInput::new(funding_utxo),
        RequiredSignature::NativeEcdsa,
    );
    funding.add_output(PartialOutput::new(
        contract.get_script_pubkey(),
        contract_amount,
        policy_asset,
    ));
    let funding_txid = finalize_and_broadcast(context, &funding)?;
    let contract_utxo = provider
        .fetch_scripthash_utxos(&contract.get_script_pubkey())?
        .into_iter()
        .find(|utxo| utxo.outpoint.txid == funding_txid && utxo.outpoint.vout == 0)
        .ok_or_else(|| anyhow::anyhow!("missing funded bitcoin-message ECDSA contract UTXO"))?;

    let mut pst = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(contract_utxo.outpoint);
    input.witness_utxo = Some(contract_utxo.txout.clone());
    input.amount = Some(contract_amount);
    input.asset = Some(policy_asset);
    pst.add_input(input);
    pst.add_output(Output::new_explicit(
        signer.get_address().script_pubkey(),
        contract_amount - spend_fee,
        policy_asset,
        None,
    ));
    pst.add_output(Output::new_explicit(
        Script::new(),
        spend_fee,
        policy_asset,
        None,
    ));

    let tx = pst.extract_tx()?;
    let utxos = vec![contract_utxo.txout.clone()];
    let sighash_all = contract.sighash_all(&tx, &utxos, 0)?;
    let signed_message_hash = signed_msg_hash_bytes(sighash_all.to_hex().as_bytes());
    let message = Message::from_digest(signed_message_hash.to_byte_array());
    let signature = secp.sign_ecdsa(&message, &secret_key);
    secp.verify_ecdsa(&message, &signature, &public_key)?;

    let compact_signature = signature.serialize_compact();
    let r = compact_signature[..32].try_into()?;
    let s = compact_signature[32..].try_into()?;

    Ok(PreparedCase {
        contract,
        contract_utxo,
        tx,
        utxos,
        r,
        s,
    })
}

fn finalize_valid_signature(prepared: &PreparedCase) -> anyhow::Result<Transaction> {
    [false, true]
        .into_iter()
        .find_map(|nonce_y| {
            finalize_with_witness(
                &prepared.contract,
                &prepared.utxos,
                &prepared.tx,
                BitcoinMessageEcdsaVerify::get_witness(nonce_y, prepared.r, prepared.s),
            )
            .ok()
        })
        .ok_or_else(|| anyhow::anyhow!("valid ECDSA signature failed for both nonce parities"))
}

fn assert_rejects_for_both_nonce_parities(
    contract: &BitcoinMessageEcdsaVerify,
    utxos: &[TxOut],
    tx: &Transaction,
    witness: impl Fn(bool) -> BitcoinMessageEcdsaVerifyWitness,
) {
    for nonce_y in [false, true] {
        assert!(
            finalize_with_witness(contract, utxos, tx, witness(nonce_y)).is_err(),
            "invalid witness unexpectedly succeeded with nonce_y={nonce_y}"
        );
    }
}

fn finalize_with_witness(
    contract: &BitcoinMessageEcdsaVerify,
    utxos: &[TxOut],
    tx: &Transaction,
    witness: BitcoinMessageEcdsaVerifyWitness,
) -> anyhow::Result<Transaction> {
    Ok(contract.finalize_transaction(tx.clone(), utxos, 0, &witness, TrackerLogLevel::None)?)
}

const fn witness_with_nonce_x(
    nonce_y_is_odd: bool,
    nonce_x: Scalar,
    r: Scalar,
    s: Scalar,
) -> BitcoinMessageEcdsaVerifyWitness {
    BitcoinMessageEcdsaVerifyWitness {
        nonce_point: (nonce_y_is_odd, nonce_x),
        r,
        s,
    }
}

fn signed_msg_hash_bytes(message: &[u8]) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    VarInt::from(message.len())
        .consensus_encode(&mut engine)
        .unwrap();
    engine.input(message);
    sha256d::Hash::from_engine(engine)
}
