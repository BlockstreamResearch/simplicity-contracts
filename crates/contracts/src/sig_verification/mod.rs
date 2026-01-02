#![allow(clippy::unreadable_literal)]
//! Minimal reproduction for dual `bip_0340_verify` `ReachedPrunedBranch` bug.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use simplicityhl::num::U256;
    use simplicityhl::parse::ParseFromStr;
    use simplicityhl::str::WitnessName;
    use simplicityhl::types::TypeConstructible;
    use simplicityhl::value::ValueConstructible;
    use simplicityhl::{Arguments, ResolvedType, TemplateProgram, WitnessValues};

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::hashes::Hash;
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1::{self, Secp256k1};
    use simplicityhl::simplicity::elements::taproot::{ControlBlock, TaprootBuilder};
    use simplicityhl::simplicity::hashes::{HashEngine, sha256};
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
    use simplicityhl::simplicity::{BitMachine, leaf_version};

    /// `SimplicityHL` source that triggers the bug (4 asserts before dual `bip_0340_verify`)
    const SOURCE_FAILS: &str = r"
fn checksig_price_attestation(pk: Pubkey, timestamp: u32, price: u64, sig: Signature) {
    let hasher: Ctx8 = jet::sha_256_ctx_8_init();
    let hasher: Ctx8 = jet::sha_256_ctx_8_add_4(hasher, timestamp);
    let hasher: Ctx8 = jet::sha_256_ctx_8_add_8(hasher, price);
    let msg: u256 = jet::sha_256_ctx_8_finalize(hasher);
    jet::bip_0340_verify((pk, msg), sig);
}

fn settlement_positive_path(
    current_price: u64,
    new_price: u64,
    timestamp: u32,
    amount: u64,
    oracle_sig: Signature,
    secondary_sig: Signature
) {
    assert!(jet::eq_64(current_price, current_price));
    assert!(jet::eq_64(new_price, new_price));
    assert!(jet::eq_32(timestamp, timestamp));
    assert!(jet::eq_64(amount, amount));

    checksig_price_attestation(param::ORACLE_PK_1, timestamp, new_price, oracle_sig);
    checksig_price_attestation(param::ORACLE_PK_2, timestamp, new_price, secondary_sig);
}

fn main() {
    match witness::PATH {
        Left(settlement_params: Either<(u64, u64, u32, u64, Signature, Signature, bool), (u64, u64, u32, u64, Signature, Signature)>) => match settlement_params {
            Left(params: (u64, u64, u32, u64, Signature, Signature, bool)) => {
                let (current_price, new_price, timestamp, amount, oracle_sig, secondary_sig, is_change_needed): (u64, u64, u32, u64, Signature, Signature, bool) = params;
            },
            Right(params: (u64, u64, u32, u64, Signature, Signature)) => {
                let (current_price, new_price, timestamp, amount, oracle_sig, secondary_sig): (u64, u64, u32, u64, Signature, Signature) = params;
                settlement_positive_path(current_price, new_price, timestamp, amount, oracle_sig, secondary_sig)
            },
        },
        Right(close_params: Either<(u64, Signature, Signature), (u64, Signature)>) => match close_params {
            Left(params: (u64, Signature, Signature)) => {
                let (current_price, user_sig, oracle_sig): (u64, Signature, Signature) = params;
            },
            Right(params: (u64, Signature)) => {
                let (current_price, user_sig): (u64, Signature) = params;
            },
        },
    }
}
";

    /// `SimplicityHL` source that passes (3 asserts - first one commented out)
    const SOURCE_PASSES: &str = r"
fn checksig_price_attestation(pk: Pubkey, timestamp: u32, price: u64, sig: Signature) {
    let hasher: Ctx8 = jet::sha_256_ctx_8_init();
    let hasher: Ctx8 = jet::sha_256_ctx_8_add_4(hasher, timestamp);
    let hasher: Ctx8 = jet::sha_256_ctx_8_add_8(hasher, price);
    let msg: u256 = jet::sha_256_ctx_8_finalize(hasher);
    jet::bip_0340_verify((pk, msg), sig);
}

fn settlement_positive_path(
    current_price: u64,
    new_price: u64,
    timestamp: u32,
    amount: u64,
    oracle_sig: Signature,
    secondary_sig: Signature
) {
    // assert!(jet::eq_64(current_price, current_price));
    assert!(jet::eq_64(new_price, new_price));
    assert!(jet::eq_32(timestamp, timestamp));
    assert!(jet::eq_64(amount, amount));

    checksig_price_attestation(param::ORACLE_PK_1, timestamp, new_price, oracle_sig);
    checksig_price_attestation(param::ORACLE_PK_2, timestamp, new_price, secondary_sig);
}

fn main() {
    match witness::PATH {
        Left(settlement_params: Either<(u64, u64, u32, u64, Signature, Signature, bool), (u64, u64, u32, u64, Signature, Signature)>) => match settlement_params {
            Left(params: (u64, u64, u32, u64, Signature, Signature, bool)) => {
                let (current_price, new_price, timestamp, amount, oracle_sig, secondary_sig, is_change_needed): (u64, u64, u32, u64, Signature, Signature, bool) = params;
            },
            Right(params: (u64, u64, u32, u64, Signature, Signature)) => {
                let (current_price, new_price, timestamp, amount, oracle_sig, secondary_sig): (u64, u64, u32, u64, Signature, Signature) = params;
                settlement_positive_path(current_price, new_price, timestamp, amount, oracle_sig, secondary_sig)
            },
        },
        Right(close_params: Either<(u64, Signature, Signature), (u64, Signature)>) => match close_params {
            Left(params: (u64, Signature, Signature)) => {
                let (current_price, user_sig, oracle_sig): (u64, Signature, Signature) = params;
            },
            Right(params: (u64, Signature)) => {
                let (current_price, user_sig): (u64, Signature) = params;
            },
        },
    }
}
";

    fn unspendable_key() -> secp256k1::XOnlyPublicKey {
        secp256k1::XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .unwrap()
    }

    fn sign_price(kp: &Keypair, timestamp: u32, price: u64) -> [u8; 64] {
        let mut eng = sha256::Hash::engine();
        eng.input(&timestamp.to_be_bytes());
        eng.input(&price.to_be_bytes());
        let hash = sha256::Hash::from_engine(eng);
        kp.sign_schnorr(secp256k1::Message::from_digest(hash.to_byte_array()))
            .serialize()
    }

    fn run_dual_verify_test(source: &str) {
        let secp = Secp256k1::new();
        let kp1 = Keypair::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        );
        let kp2 = Keypair::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let pk1 = kp1.x_only_public_key().0.serialize();
        let pk2 = kp2.x_only_public_key().0.serialize();

        let args = Arguments::from(HashMap::from([
            (
                WitnessName::from_str_unchecked("ORACLE_PK_1"),
                simplicityhl::Value::u256(U256::from_byte_array(pk1)),
            ),
            (
                WitnessName::from_str_unchecked("ORACLE_PK_2"),
                simplicityhl::Value::u256(U256::from_byte_array(pk2)),
            ),
        ]));
        let program = TemplateProgram::new(source)
            .unwrap()
            .instantiate(args, true)
            .unwrap();
        let cmr = program.commit().cmr();

        let spend_info = TaprootBuilder::new()
            .add_leaf_with_ver(0, Script::from(cmr.as_ref().to_vec()), leaf_version())
            .unwrap()
            .finalize(secp256k1::SECP256K1, unspendable_key())
            .unwrap();

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(OutPoint::new(
            Txid::from_slice(&[0; 32]).unwrap(),
            0,
        )));
        pst.add_output(Output::new_explicit(
            Script::new(),
            0,
            AssetId::default(),
            None,
        ));

        let cb = spend_info
            .control_block(&(Script::from(cmr.as_ref().to_vec()), leaf_version()))
            .unwrap();
        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx().unwrap()),
            vec![ElementsUtxo {
                script_pubkey: Script::new_v1_p2tr_tweaked(spend_info.output_key()),
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&cb.serialize()).unwrap(),
            None,
            BlockHash::all_zeros(),
        );

        let timestamp = 1735689600u32;
        let new_price = 105_000u64;
        let sig1 = sign_price(&kp1, timestamp, new_price);
        let sig2 = sign_price(&kp2, timestamp, new_price);

        let path_type = ResolvedType::either(
            ResolvedType::either(
                ResolvedType::parse_from_str("(u64, u64, u32, u64, Signature, Signature, bool)")
                    .unwrap(),
                ResolvedType::parse_from_str("(u64, u64, u32, u64, Signature, Signature)").unwrap(),
            ),
            ResolvedType::either(
                ResolvedType::parse_from_str("(u64, Signature, Signature)").unwrap(),
                ResolvedType::parse_from_str("(u64, Signature)").unwrap(),
            ),
        );
        let witness_str = format!(
            "Left(Right((100000, {}, {}, 500, 0x{}, 0x{})))",
            new_price,
            timestamp,
            hex::encode(sig1),
            hex::encode(sig2)
        );
        let witness = WitnessValues::from(HashMap::from([(
            WitnessName::from_str_unchecked("PATH"),
            simplicityhl::Value::parse_from_str(&witness_str, &path_type).unwrap(),
        )]));

        // Execute via rust-simplicity directly
        let satisfied = program.satisfy(witness).unwrap();
        let pruned = satisfied.redeem().prune(&env).unwrap();
        let mut mac = BitMachine::for_program(&pruned).unwrap();

        match mac.exec(&pruned, &env) {
            Ok(_) => {}
            Err(e) => {
                let err = format!("{e:?}");
                assert!(
                    !err.contains("ReachedPrunedBranch"),
                    "BUG: Dual bip_0340_verify causes ReachedPrunedBranch: {err}"
                );
                panic!("Error: {err}");
            }
        }
    }

    /// Reproduces: dual `bip_0340_verify` causes `ReachedPrunedBranch`
    #[test]
    #[should_panic(expected = "ReachedPrunedBranch")]
    fn test_dual_verify_bug() {
        run_dual_verify_test(SOURCE_FAILS);
    }

    /// Same test but with one assert commented out - this passes
    #[test]
    fn test_dual_verify_passes() {
        run_dual_verify_test(SOURCE_PASSES);
    }
}
