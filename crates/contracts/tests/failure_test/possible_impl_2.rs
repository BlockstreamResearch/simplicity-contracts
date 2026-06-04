// use crate::failure_test::core::{
//     arb_32_bytes, MockProvider, DEFAULT_TEST_MNEMONIC, construct_executable_program_2,
//     get_failure_program,
// };
// use crate::failure_test::possible_interface::{FuzzContext, SimplexFuzzEngine};
// use contracts::artifacts::failure_test::derived_failure_test::*;
// use proptest::prelude::Strategy;
// use proptest::test_runner::Config;
// use simplex::program::WitnessTrait;
// use simplex::program::core::ProgramTrait;
// use simplex::provider::SimplicityNetwork;
// use simplex::signer::Signer;
//
// // ============================================================================
// // Proptest Strategies for FailureTest
// // ============================================================================
//
// /// Strategy generator for random (Arguments, Witness) pairs
// fn arb_failure_test_params() -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
//     (arb_32_bytes(), arb_32_bytes()).prop_map(|(arg_val, wit_val)| {
//         (
//             FailureTestArguments {
//                 failure_value: arg_val,
//             },
//             FailureTestWitness {
//                 cmp_value: wit_val,
//             },
//         )
//     })
// }
//
// /// Strategy for matching arguments and witness (for equality tests)
// fn arb_failure_test_params_eq() -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
//     arb_32_bytes().prop_map(|val| {
//         (
//             FailureTestArguments {
//                 failure_value: val,
//             },
//             FailureTestWitness { cmp_value: val },
//         )
//     })
// }
//
// // ============================================================================
// // Example 3: Simple fuzzing with default signer
// //
// // This example demonstrates:
// // - Using SimplexFuzzEngine with default configuration
// // - Setting default signer via DEFAULT_TEST_MNEMONIC
// // - Running fuzzing with matching arguments and witness
// // - Basic program execution and assertion
// // ============================================================================
//
// #[test]
// fn proptesting_example_3_basic() {
//     // Create engine with default proptest config
//     let engine = SimplexFuzzEngine::new(Config::default());
//
//     // Set up default signer for test execution
//     engine.with_default_signer();
//
//     // Run fuzzing with equal args/witness strategy
//     let result = engine.run_with_check(
//         arb_failure_test_params_eq(),
//         |context: &FuzzContext, args: &FailureTestArguments, witness: &FailureTestWitness| {
//             let network = context.get_network();
//
//             // Get program with generated arguments
//             let (program, _script) = get_failure_program(network, args.clone());
//
//             // Construct the executable transaction
//             let ft = construct_executable_program_2(witness, args.clone(), network);
//             let (testing_pst, _map) = ft.extract_pst();
//
//             // Execute and verify success
//             program
//                 .as_ref()
//                 .execute(
//                     &testing_pst,
//                     &witness.build_witness(),
//                     0,
//                     network,
//                 )
//                 .map_err(|e| anyhow::anyhow!("Execution failed: {:?}", e))?;
//
//             Ok(())
//         },
//     );
//
//     assert!(result.is_ok(), "Fuzz test failed");
// }
//
// // ============================================================================
// // Example 3b: Fuzzing with custom signer and verbose error handling
// //
// // This example demonstrates:
// // - Setting up a custom signer explicitly
// // - Accessing signer from FuzzContext during test
// // - Running with random (potentially mismatched) arguments/witness
// // - Graceful error handling for non-deterministic outcomes
// // ============================================================================
//
// #[test]
// fn proptesting_example_3b_custom_signer() {
//     // Create engine
//     let engine = SimplexFuzzEngine::new(Config::default());
//
//     // Setup custom signer explicitly
//     let signer = Signer::new(
//         DEFAULT_TEST_MNEMONIC,
//         Box::new(MockProvider {
//             network: SimplicityNetwork::default_regtest(),
//         }),
//     );
//     engine.with_signer(signer);
//
//     // Run with random (non-matching) arguments/witness - result may vary
//     let result = engine.run_with_check(
//         arb_failure_test_params(),
//         |context: &FuzzContext, args: &FailureTestArguments, witness: &FailureTestWitness| {
//             let network = context.get_network();
//
//             // Verify signer is available
//             let _signer = context
//                 .get_signer()
//                 .ok_or_else(|| anyhow::anyhow!("Signer not configured"))?;
//
//             // Get program with generated arguments
//             let (program, _script) = get_failure_program(network, args.clone());
//
//             // Construct the executable transaction
//             let ft = construct_executable_program_2(witness, args.clone(), network);
//             let (testing_pst, _map) = ft.extract_pst();
//
//             // For random values, execution may succeed or fail - we only ensure no panics
//             let _ = program
//                 .as_ref()
//                 .execute(
//                     &testing_pst,
//                     &witness.build_witness(),
//                     0,
//                     network,
//                 );
//
//             Ok(())
//         },
//     );
//
//     assert!(result.is_ok(), "Fuzz test framework failed");
// }
//
// // ============================================================================
// // Example 4: Advanced fuzzing with custom network and configuration
// //
// // This example demonstrates:
// // - Creating engine with custom proptest Config
// // - Using custom network settings
// // - Flexible strategy composition
// // - Multiple validation checks in closure
// // ============================================================================
//
// #[test]
// fn proptesting_example_4_advanced() {
//     // Create engine with custom proptest configuration
//     let mut config = Config::default();
//     config.cases = 100; // Run more test cases
//     let engine = SimplexFuzzEngine::new(config);
//
//     // Set default signer
//     engine.with_default_signer();
//
//     // Optionally configure custom network
//     engine.with_network(SimplicityNetwork::default_regtest());
//
//     // Run with matching strategy - all should succeed
//     let result = engine.run_with_check(
//         arb_failure_test_params_eq(),
//         |context: &FuzzContext,
//          args: &FailureTestArguments,
//          witness: &FailureTestWitness| {
//
//             let network = context.get_network();
//
//             // Step 1: Create program from arguments
//             let (program, _script) = get_failure_program(network, args.clone());
//
//             // Step 2: Build executable transaction
//             let ft = construct_executable_program_2(witness, args.clone(), network);
//             let (testing_pst, _map) = ft.extract_pst();
//
//             // Step 3: Execute program
//             let exec_result = program
//                 .as_ref()
//                 .execute(
//                     &testing_pst,
//                     &witness.build_witness(),
//                     0,
//                     network,
//                 );
//
//             // Step 4: Verify execution succeeded
//             match exec_result {
//                 Ok(_) => {
//                     // Success case - continue with additional checks if needed
//                     Ok(())
//                 }
//                 Err(e) => {
//                     Err(anyhow::anyhow!("Program execution failed: {:?}", e))
//                 }
//             }
//         },
//     );
//
//     assert!(result.is_ok(), "Advanced fuzz test failed");
// }
