use crate::failure_test::core::{
    DEFAULT_TEST_MNEMONIC, MockProvider, arb_32_bytes, build_failure_tx,
    construct_executable_program, construct_executable_program_2, get_failure_program,
    spawn_input_tx,
};
use contracts::artifacts::failure_test::derived_failure_test::*;
use proptest::prelude::{Just, ProptestConfig, Strategy};
use proptest::proptest;
use rand::random;
use simplex::program::WitnessTrait;
use simplex::program::core::ProgramTrait;
use simplex::provider::SimplicityNetwork;
use simplex::signer::Signer;
use simplex::simplicityhl::elements::hex::ToHex;

#[test]
fn proptesting_example_1() {
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

#[test]
fn proptesting_example_2() {
    let witness1 = FailureTestWitness {
        cmp_value: random(),
    };
    let args = FailureTestArguments {
        failure_value: random(),
    };
    let network = SimplicityNetwork::default_regtest();

    let (program, _scr) = get_failure_program(&network, args.clone());
    let ft = construct_executable_program_2(&witness1, args, &network);
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

#[test]
fn proptesting_example_eq_2() {
    let mut config = ::proptest::test_runner::contextualize_config(
        (::proptest::test_runner::Config::default()).clone(),
    );
    config.test_name = ::core::option::Option::Some(::core::concat!(
        ::core::module_path!(),
        "::",
        ::core::stringify!(proptesting_example_eq)
    ));
    {
        config.source_file = Some(file!());
        let mut runner = ::proptest::test_runner::TestRunner::new(config);
        let names = "(_arguments,witness1)";
        match runner.run(
            &::proptest::strategy::Strategy::prop_map((arb_program_params_eq()), |values| {
                ::proptest::sugar::NamedArguments(names, values)
            }),
            |::proptest::sugar::NamedArguments(_, (_arguments, witness1))| {
                let (): () = {
                    // println!("{} - {}", witness1.cmp_value.to_hex(), _arguments.failure_value.to_hex());
                    test_failure_program(_arguments, witness1).unwrap();
                };
                ::core::result::Result::Ok(())
            },
        ) {
            ::core::result::Result::Ok(()) => (),
            ::core::result::Result::Err(e) => ::core::panic!("{}\n{}", e, runner),
        }
    }
}

fn test_failure_program(args: FailureTestArguments, wit: FailureTestWitness) -> anyhow::Result<()> {
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

#[test]
fn fuzz_testing() {
    let mut config = ::proptest::test_runner::contextualize_config(
        (::proptest::test_runner::Config::default()).clone(),
    );
    config.test_name = ::core::option::Option::Some(::core::concat!(
        ::core::module_path!(),
        "::",
        ::core::stringify!(proptesting_example_eq)
    ));
    {
        config.source_file = Some(file!());
        let mut runner = ::proptest::test_runner::TestRunner::new(config);
        let names = "(_arguments,witness1)";
        match runner.run(
            &::proptest::strategy::Strategy::prop_map((arb_program_params_eq()), |values| {
                ::proptest::sugar::NamedArguments(names, values)
            }),
            |::proptest::sugar::NamedArguments(_, (_arguments, witness1))| {
                let (): () = {
                    // println!("{} - {}", witness1.cmp_value.to_hex(), _arguments.failure_value.to_hex());
                    test_failure_program(_arguments, witness1).unwrap();
                };
                ::core::result::Result::Ok(())
            },
        ) {
            ::core::result::Result::Ok(()) => (),
            ::core::result::Result::Err(e) => ::core::panic!("{}\n{}", e, runner),
        }
    }
}

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};

struct AppState {
    max_users_allowed: u32,
    active_prefix: String,
}

// 1. Create a function that takes context and returns a Strategy
fn dynamic_fuzz_strategy(ctx: &AppState) -> impl Strategy<Value = (u32, String)> {
    let max = ctx.max_users_allowed;
    let prefix = ctx.active_prefix.clone();

    // 2. Build the strategy using the context
    // This generates a tuple of (0..max, "prefix_XXXX")
    (0..max, "[a-z]{4}")
        .prop_map(move |(id, random_str)| (id, format!("{}_{}", prefix, random_str)))
}

#[test]
fn proptest_orig() {
    let mut runner = TestRunner::new(Config::default());

    let current_state = AppState {
        max_users_allowed: 42,
        active_prefix: "testenv".to_string(),
    };

    // 3. Generate the strategy dynamically based on current state
    let strategy = dynamic_fuzz_strategy(&current_state);

    for _ in 0..10 {
        let tree = strategy.new_tree(&mut runner).unwrap();
        let (user_id, username) = tree.current();

        // Output will always respect the context bounds:
        // e.g., (12, "testenv_abcd")
        println!(
            "Generated context-aware data: ID: {}, Name: {}",
            user_id, username
        );
    }
}

fn main() {
    let mut runner = TestRunner::new(Config::default());
    let strategy = 0..1000u32;

    // 1. Generate the initial complex value AND its shrinking paths
    let mut value_tree = strategy.new_tree(&mut runner).unwrap();

    loop {
        // 2. Extract the current value from the tree
        let current_val = value_tree.current();

        // let did_test_pass = run_my_target(current_val);
        let did_test_pass = true;

        if did_test_pass {
            // If the test passed, try moving UP the tree to a more
            // complex value (only matters if we are currently shrinking)
            if !value_tree.complicate() {
                break; // We found the minimal failing input
            }
        } else {
            // If the test failed, try moving DOWN the tree to a
            // simpler value
            println!("Failed at {}, trying to shrink...", current_val);
            if !value_tree.simplify() {
                break; // We cannot shrink any further
            }
        }
    }
}
