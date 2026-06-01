use crate::failure_test::core::{
    arb_32_bytes, build_failure_tx, construct_executable_program, spawn_input_tx,
    MockProvider, DEFAULT_TEST_MNEMONIC,
};
use contracts::artifacts::failure_test::derived_failure_test::*;
use proptest::prelude::{Just, ProptestConfig, Strategy};
use proptest::proptest;
use rand::random;
use simplex::program::core::ProgramTrait;
use simplex::program::WitnessTrait;
use simplex::provider::SimplicityNetwork;
use simplex::signer::Signer;
use simplex::simplicityhl::elements::hex::ToHex;

#[test]
fn proptesting_example_sim2() {
    let witness1 = FailureTestWitness {
        cmp_value: random(),
    };
    let args = FailureTestArguments {
        failure_value: random(),
    };
    let signer = Signer::new(
        DEFAULT_TEST_MNEMONIC,
        Box::new(MockProvider {
            network: SimplicityNetwork::default_regtest(),
        }),
    );
    let network = SimplicityNetwork::default_regtest();
    let funding_tx = spawn_input_tx(&signer, &network);
    let (testing_tx, program) = build_failure_tx(&signer, &witness1, &args, &network, funding_tx);

    let ft = construct_executable_program(&program, &witness1, testing_tx);
    let (testing_pst, _map) = ft.extract_pst();
    program
        .as_ref()
        .execute(&testing_pst, &witness1.build_witness(), 0, &network)
        .unwrap();
    assert!(
        program
            .as_ref()
            .execute(&testing_pst, &witness1.build_witness(), 0, &network)
            .is_ok(),
        "expected success mint path"
    );
}

fn arb_witness() -> impl Strategy<Value = FailureTestWitness> {
    arb_32_bytes().prop_map(|state| FailureTestWitness { cmp_value: state })
}

fn arb_arguments() -> impl Strategy<Value = FailureTestArguments> {
    arb_32_bytes().prop_map(|state| FailureTestArguments {
        failure_value: state,
    })
}

fn arb_program_params() -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
    (arb_arguments(), arb_witness())
}

fn arb_program_params_eq() -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
    (arb_arguments().prop_map(|x| {
        (
            FailureTestArguments {
                failure_value: x.failure_value,
            },
            FailureTestWitness {
                cmp_value: x.failure_value,
            },
        )
    }))
}

proptest! {
    #[test]
    fn proptesting_example_simplex_random((_arguments, witness1) in arb_program_params()) {
        // println!("{} - {}", witness1.cmp_value.to_hex(), _arguments.failure_value.to_hex());
        test_failure_program(_arguments, witness1).unwrap();
    }
}

proptest! {
    #[test]
    fn proptesting_example_eq((_arguments, witness1) in arb_program_params_eq()) {
        // println!("{} - {}", witness1.cmp_value.to_hex(), _arguments.failure_value.to_hex());
        test_failure_program(_arguments, witness1).unwrap();
    }
}

fn test_failure_program(args: FailureTestArguments, wit: FailureTestWitness) -> anyhow::Result<()>{
    let witness1 = FailureTestWitness {
        cmp_value: wit.cmp_value,
    };
    let args = FailureTestArguments {
        failure_value: args.failure_value,
    };
    let signer = Signer::new(
        DEFAULT_TEST_MNEMONIC,
        Box::new(MockProvider {
            network: SimplicityNetwork::default_regtest(),
        }),
    );
    let network = SimplicityNetwork::default_regtest();
    let funding_tx = spawn_input_tx(&signer, &network);
    let (testing_tx, program) = build_failure_tx(&signer, &witness1, &args, &network, funding_tx);

    let ft = construct_executable_program(&program, &witness1, testing_tx);
    let (testing_pst, _map) = ft.extract_pst();
    assert!(
        program
            .as_ref()
            .execute(&testing_pst, &witness1.build_witness(), 0, &network)
            .is_ok(),
        "expected success mint path"
    );
    Ok(())
}
