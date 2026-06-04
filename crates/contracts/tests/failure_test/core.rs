use contracts::artifacts::failure_test::FailureTestProgram;
use contracts::artifacts::failure_test::derived_failure_test::{
    FailureTestArguments, FailureTestWitness,
};
use contracts::programs::program::SimplexProgram2;
use proptest::arbitrary::any;
use proptest::prelude::Strategy;
use proptest::prop_oneof;
use simplex::either::Either;
use simplex::program::{ProgramTrait, WitnessTrait};
use simplex::provider::{ProviderError, ProviderTrait, SimplicityNetwork};
use simplex::signer::Signer;
use simplex::simplicityhl::elements::hashes::Hash;
use simplex::simplicityhl::elements::{
    Address, AssetId, OutPoint, Script, Transaction, TxOut, Txid,
};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, TxReceipt, UTXO,
};
use std::collections::HashMap;
use std::fmt::Debug;

pub const DEFAULT_TEST_MNEMONIC: &str =
    "exist carry drive collect lend cereal occur much tiger just involve mean";
const DEFAULT_FAUCET: u64 = 1_000_000;
const DEFAULT_FEE: u64 = 1_000;
const DEFAULT_TARGET_BLOCKS: u32 = 6;

pub fn arb_either<L: 'static + Debug, R: 'static + Debug>(
    left: impl Strategy<Value = L> + 'static,
    right: impl Strategy<Value = R> + 'static,
) -> impl Strategy<Value = Either<L, R>> {
    prop_oneof![left.prop_map(Either::Left), right.prop_map(Either::Right),]
}

pub fn arb_u8() -> impl Strategy<Value = u8> {
    any::<u8>()
}

pub fn arb_2_bytes() -> impl Strategy<Value = [u8; 2]> {
    any::<[u8; 2]>()
}

pub fn arb_4_bytes() -> impl Strategy<Value = [u8; 4]> {
    any::<[u8; 4]>()
}

pub fn arb_8_bytes() -> impl Strategy<Value = [u8; 8]> {
    any::<[u8; 8]>()
}

pub fn arb_16_bytes() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

pub fn arb_32_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

pub fn arb_pubkey() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

pub fn arb_64_bytes() -> impl Strategy<Value = [u8; 64]> {
    any::<[u8; 64]>()
}

pub fn arb_asset_id() -> impl Strategy<Value = (AssetId)> {
    arb_32_bytes().prop_map(|x| AssetId::from_slice(&x).unwrap())
}

pub struct MockProvider {
    pub network: SimplicityNetwork,
}

impl MockProvider {
    pub fn new(network: SimplicityNetwork) -> Self {
        Self { network }
    }
}

impl ProviderTrait for MockProvider {
    fn get_network(&self) -> &SimplicityNetwork {
        &self.network
    }

    fn broadcast_transaction(&self, tx: &Transaction) -> Result<TxReceipt<'_>, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn wait(&self, txid: &Txid) -> Result<(), ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_tip_height(&self) -> Result<u32, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_tip_timestamp(&self) -> Result<u64, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_transaction(&self, txid: &Txid) -> Result<Transaction, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_address_utxos(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_scripthash_utxos(&self, script: &Script) -> Result<Vec<UTXO>, ProviderError> {
        unimplemented!("No network access needed for tests")
    }

    fn fetch_fee_estimates(&self) -> Result<HashMap<String, f64>, ProviderError> {
        Ok(HashMap::new())
    }
}

pub fn get_failure_program(
    network: &SimplicityNetwork,
    args: FailureTestArguments,
) -> (FailureTestProgram, Script) {
    let failure_program = FailureTestProgram::new(args);
    let failure_script = failure_program.get_script_pubkey(network);

    (failure_program, failure_script)
}

pub fn build_failure_tx(
    signer: &Signer,
    witness: &FailureTestWitness,
    args: &FailureTestArguments,
    network: &SimplicityNetwork,
    tx: Transaction,
) -> (Transaction, FailureTestProgram) {
    let mut ft = FinalTransaction::new();

    // input transaction
    ft.add_input(
        PartialInput::new(UTXO {
            outpoint: OutPoint::new(tx.txid(), 0),
            txout: tx.output[0].clone(),
            secrets: None,
        }),
        RequiredSignature::NativeEcdsa,
    );

    let (program, script) = get_failure_program(network, args.clone());

    ft.add_output(PartialOutput::new(
        script,
        tx.output[0].value.explicit().unwrap() - DEFAULT_FEE,
        network.policy_asset(),
    ));
    let (tx, sig) = signer.finalize_strict(&ft, DEFAULT_TARGET_BLOCKS).unwrap();

    (tx, program)
}

pub fn construct_executable_program(
    program: &FailureTestProgram,
    witness: &FailureTestWitness,
    tx: Transaction,
) -> FinalTransaction {
    let mut ft = FinalTransaction::new();

    let program_input: Box<dyn ProgramTrait> = Box::new(program.as_ref().clone());
    let witness_ref: Box<dyn WitnessTrait> = Box::new(witness.clone());

    ft.add_program_input(
        PartialInput::new(UTXO {
            outpoint: OutPoint::new(tx.txid(), 0),
            txout: tx.output[0].clone(),
            secrets: None,
        }),
        ProgramInput::new(program_input, witness_ref),
        RequiredSignature::None,
    );

    ft
}

pub fn construct_executable_program_2(
    witness: &FailureTestWitness,
    args: FailureTestArguments,
    network: &SimplicityNetwork,
) -> FinalTransaction {
    let mut ft = FinalTransaction::new();

    let (program, script) = get_failure_program(network, args);

    let program_input: Box<dyn ProgramTrait> = Box::new(program.as_ref().clone());
    let witness_ref: Box<dyn WitnessTrait> = Box::new(witness.clone());

    let txout = {
        let mut r = TxOut::new_fee(DEFAULT_FAUCET, network.policy_asset());
        r.script_pubkey = script;
        r
    };

    ft.add_program_input(
        PartialInput::new(UTXO {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            txout,
            secrets: None,
        }),
        ProgramInput::new(program_input, witness_ref),
        RequiredSignature::None,
    );

    ft
}

pub fn spawn_input_tx(signer: &Signer, network: &SimplicityNetwork) -> Transaction {
    let mut ft = FinalTransaction::new();
    ft.add_input(
        PartialInput::new(UTXO {
            outpoint: Default::default(),
            txout: TxOut::new_fee(DEFAULT_FAUCET, network.policy_asset()),
            secrets: None,
        }),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput {
        script_pubkey: signer.get_address().script_pubkey(),
        amount: DEFAULT_FAUCET - DEFAULT_FEE,
        asset: network.policy_asset(),
        blinding_key: None,
    });
    let (tx, _) = signer.finalize_strict(&ft, DEFAULT_TARGET_BLOCKS).unwrap();
    tx
}
