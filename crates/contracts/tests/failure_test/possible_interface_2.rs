// use crate::failure_test::core::{MockProvider, DEFAULT_TEST_MNEMONIC};
// use simplex::provider::SimplicityNetwork;
// use simplex::signer::Signer;
// use simplex::program::core::ProgramTrait;
// use std::cell::RefCell;
// use proptest::prelude::Strategy;
// use proptest::test_runner::{Config, TestRunner};
// use proptest::strategy::ValueTree;
//
// /// Runtime context for fuzz testing - provides access to signer and network
// ///
// /// This is passed to setup and check closures. It's lightweight and only exposes
// /// what's needed for the user's test logic.
// pub struct FuzzContext {
//     signer: Option<Signer>,
//     network: SimplicityNetwork,
// }
//
// impl Default for FuzzContext {
//     fn default() -> Self {
//         let default_network = SimplicityNetwork::default_regtest();
//         Self {
//             signer: None,
//             network: default_network,
//         }
//     }
// }
//
// impl FuzzContext {
//     /// Get a reference to the signer if available
//     pub fn get_signer(&self) -> Option<&Signer> {
//         self.signer.as_ref()
//     }
//
//     /// Get the network configuration
//     pub fn get_network(&self) -> &SimplicityNetwork {
//         &self.network
//     }
//
//     /// Set the signer for this context
//     pub(crate) fn with_signer(&mut self, signer: Signer) {
//         self.signer = Some(signer);
//     }
//
//     /// Set the network for this context
//     pub(crate) fn with_network(&mut self, network: SimplicityNetwork) {
//         self.network = network;
//     }
// }
//
// /// Abstraction over the result of a fuzzing test execution
// ///
// /// This encapsulates the outcome of executing a program with given arguments
// /// and witness. Users check invariants against this result.
// pub struct FuzzExecutionResult {
//     /// Whether the execution succeeded (is_ok = true) or failed (is_ok = false)
//     pub is_ok: bool,
//     /// Error message if execution failed
//     pub error_msg: Option<String>,
// }
//
// impl FuzzExecutionResult {
//     /// Create a successful execution result
//     pub fn ok() -> Self {
//         Self {
//             is_ok: true,
//             error_msg: None,
//         }
//     }
//
//     /// Create a failed execution result with an error message
//     pub fn err(msg: String) -> Self {
//         Self {
//             is_ok: false,
//             error_msg: Some(msg),
//         }
//     }
//
//     /// Check if execution succeeded
//     pub fn succeeded(&self) -> bool {
//         self.is_ok
//     }
//
//     /// Get error message if any
//     pub fn error(&self) -> Option<&str> {
//         self.error_msg.as_deref()
//     }
// }
//
// /// SimplexFuzzEngine - A property-based testing framework for Simplicity contracts
// ///
// /// This engine provides a clean, high-level interface for fuzzing:
// /// - Generates test inputs using proptest strategies
// /// - Manages test context (signer, network)
// /// - Hides program execution complexity behind helper methods
// /// - Users focus on defining strategies and verifying invariants
// ///
// /// # Example
// /// ```ignore
// /// let engine = SimplexFuzzEngine::new(Config::default());
// /// engine.with_default_signer();
// ///
// /// // User just provides the strategy and a check closure
// /// // Execution details are hidden by the engine
// /// engine.run_with_check(
// ///     arb_failure_test_params(),
// ///     |context: &FuzzContext, args: &FailureTestArguments, witness: &FailureTestWitness| {
// ///         // Execute the program and verify result
// ///         let result = context.execute_failure_test(args, witness)?;
// ///         assert!(result.succeeded(), "Program should execute successfully");
// ///         Ok(())
// ///     },
// /// )?;
// /// ```
// pub struct SimplexFuzzEngine {
//     runner: RefCell<TestRunner>,
//     context: RefCell<FuzzContext>,
// }
//
// impl SimplexFuzzEngine {
//     /// Create a new fuzz engine with the given proptest configuration
//     pub fn new(config: Config) -> Self {
//         Self {
//             runner: RefCell::new(TestRunner::new(config)),
//             context: RefCell::new(FuzzContext::default()),
//         }
//     }
//
//     /// Create with default proptest configuration
//     pub fn with_config(config: Config) -> Self {
//         Self::new(config)
//     }
//
//     /// Set a custom signer in the fuzz context
//     pub fn with_signer(&self, signer: Signer) {
//         self.context.borrow_mut().with_signer(signer);
//     }
//
//     /// Set a default signer using DEFAULT_TEST_MNEMONIC
//     pub fn with_default_signer(&self) {
//         let network = self.context.borrow().network.clone();
//         self.context.borrow_mut().with_signer(Signer::new(
//             DEFAULT_TEST_MNEMONIC,
//             Box::new(MockProvider { network }),
//         ));
//     }
//
//     /// Set a custom network configuration
//     pub fn with_network(&self, network: SimplicityNetwork) {
//         self.context.borrow_mut().with_network(network);
//     }
//
//     /// Get a snapshot of the current fuzz context
//     // pub fn get_context(&self) -> &FuzzContext {
//     //     &*self.context.borrow()
//     // }
//
//     /// Run fuzz tests with a strategy and check function
//     ///
//     /// The engine:
//     /// 1. Generates test cases using the provided strategy
//     /// 2. Provides FuzzContext to the check closure
//     /// 3. User check closure focuses on invariants, not execution details
//     /// 4. Returns error if any check fails (enables shrinking)
//     ///
//     /// # Arguments
//     /// - `strategy`: A proptest Strategy that generates (Arguments, Witness) tuples
//     /// - `mut check`: A closure that validates each test case
//     ///
//     /// # Errors Returns the first error encountered during checking
//     pub fn run_with_check<A, W, S, F>(&self, strategy: S, mut check: F) -> anyhow::Result<()>
//     where
//         S: Strategy<Value = (A, W)> + 'static,
//         A: std::fmt::Debug + 'static,
//         W: std::fmt::Debug + 'static,
//         F: FnMut(&FuzzContext, &A, &W) -> anyhow::Result<()>,
//     {
//         let mut runner = self.runner.borrow_mut();
//
//         // Run the strategy for multiple iterations
//         for _ in 0..10 {
//             if let Ok(mut tree) = strategy.new_tree(&mut runner) {
//                 let (args, witness) = tree.current();
//
//                 // Clone context for the check closure
//                 let ctx = self.context.borrow();
//                 check(&ctx, &args, &witness)?;
//             }
//         }
//
//         Ok(())
//     }
//
//     /// Get a mutable reference to the test runner for advanced usage
//     pub fn runner_mut(&self) -> std::cell::RefMut<TestRunner> {
//         self.runner.borrow_mut()
//     }
// }
//
