// #[simplex_fuzz_test]
// fn whatever(fuzz_context: FuzzContext, engine: SimplexFuzzEngine) {
//     let s = fuzz_context.get_signer();
//     let a = LendingArguments::new();
//     let p = Lending::new(a);
//     let w = LendingWitness::new();
//
//     let ft = FinalTransaction::new();
//
//     // build ft
//
//     engine.with_value_mutator();
//     engine.with_witness_mutator(p, w);
//
//     engine.with_signer(signer);
//
//     engine.run_with_check(|execution_result: FuzzResult, ft: FinalTransaction| {
//         // asserts that execution_result is OK/not OK with the given ft
//     })
//
//     // run_with_check runs mutators on the transaction, executes bitmachine, and calls user lambda to check the invariant
// }

use crate::failure_test::core::{DEFAULT_TEST_MNEMONIC, MockProvider, arb_32_bytes};
use contracts::artifacts::failure_test::FailureTestProgram;
use contracts::artifacts::failure_test::derived_failure_test::{
    FailureTestArguments, FailureTestWitness,
};
use contracts::programs::program::SimplexProgram2;
use proptest::strategy::{BoxedStrategy, Strategy};
use proptest::test_runner::TestCaseError;
use simplex::program::{ArgumentsTrait, ProgramTrait, WitnessTrait};
use simplex::provider::SimplicityNetwork;
use simplex::signer::{Signer, SignerError};
use simplex::simplicityhl::elements::hashes::Hash;
use simplex::simplicityhl::elements::{OutPoint, Script, Transaction, TxOut, Txid};
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature, UTXO};
use std::cell::RefCell;
use std::marker::PhantomData;

pub struct FuzzContext {
    pub signer: Option<Signer>,
    pub mock_provider: MockProvider,
    pub network: SimplicityNetwork,
}

// impl FuzzableProgram<FailureTestProgram, FailureTestArguments> for FailureTestProgram {
//     fn build_program(
//         args: FailureTestArguments,
//         network: &SimplicityNetwork,
//     ) -> (Box<FailureTestProgram>, Script) {
//         let failure_program = FailureTestProgram::new(args);
//         let failure_script = failure_program.get_script_pubkey(network);
//         (Box::new(failure_program), failure_script)
//     }
// }

pub trait FuzzableProgram<P: SimplexProgram2, Args: ArgumentsTrait>: SimplexProgram2 {
    fn build_program(args: Args, network: &SimplicityNetwork) -> (Box<P>, Script);
}

pub trait FuzzableBaseContextGen<Program, Args, Wit> {
    fn build_base_transaction(
        &self,
        network: &SimplicityNetwork,
        args: Args,
        wit: Wit,
    ) -> FinalTransaction;
}

pub trait FuzzableContextGen<Program, Args, Wit> {
    fn modify_transaction(
        &self,
        signer: &Option<Signer>,
        ft: FinalTransaction,
        args: &Args,
        wit: &Wit,
    ) -> Result<Transaction, SignerError>;
}

#[derive(Default)]
pub struct DefaultBaseContextGen {}

impl<FuzzProgram, Args, Wit> FuzzableBaseContextGen<FuzzProgram, Args, Wit>
    for DefaultBaseContextGen
where
    FuzzProgram: FuzzableProgram<FuzzProgram, Args>,
    Args: ArgumentsTrait + Clone + 'static,
    Wit: WitnessTrait + Clone + 'static,
{
    fn build_base_transaction(
        &self,
        network: &SimplicityNetwork,
        args: Args,
        wit: Wit,
    ) -> FinalTransaction {
        const DEFAULT_FAUCET: u64 = 1 << 32;

        let mut ft = FinalTransaction::new();

        let (failure_program, failure_script) = FuzzProgram::build_program(args, network);

        let witness_ref: Box<dyn WitnessTrait> = Box::new(wit.clone());

        let txout = {
            let mut r = TxOut::new_fee(DEFAULT_FAUCET, network.policy_asset());
            r.script_pubkey = failure_script;
            r
        };

        ft.add_program_input(
            PartialInput::new(UTXO {
                outpoint: OutPoint::new(Txid::all_zeros(), 0),
                txout,
                secrets: None,
            }),
            ProgramInput::new(Box::new(failure_program.get_program().clone()), witness_ref),
            RequiredSignature::None,
        );

        ft
    }
}

#[derive(Default)]
pub struct DefaultContextGen {}

impl<
    FuzzProgram: FuzzableProgram<FuzzProgram, Args>,
    Args: ArgumentsTrait + Clone + 'static,
    Wit: WitnessTrait + Clone + 'static,
> FuzzableContextGen<FuzzProgram, Args, Wit> for DefaultContextGen
{
    fn modify_transaction(
        &self,
        signer: &Option<Signer>,
        ft: FinalTransaction,
        _args: &Args,
        _wit: &Wit,
    ) -> Result<Transaction, SignerError> {
        const DEFAULT_TARGET_BLOCKS: u32 = 6;

        match signer {
            None => Ok(ft.extract_pst().0.extract_tx()?),
            Some(s) => Ok(s.finalize_strict(&ft, DEFAULT_TARGET_BLOCKS)?.0),
        }
    }
}

pub struct SimplexFuzzEngineInner<Program, Args, Wit> {
    pub(crate) fuzz_context: FuzzContext,
    pub(crate) strategy_storage: Vec<Box<dyn ArgGenFuzzStrategy<Args, Wit>>>,
    pub(crate) base_gen: Option<Box<dyn FuzzableBaseContextGen<Program, Args, Wit>>>,
    pub(crate) mod_gen: Option<Box<dyn FuzzableContextGen<Program, Args, Wit>>>,
}

pub struct SimplexFuzzEngine<Program, Args, Wit> {
    runner: RefCell<proptest::test_runner::TestRunner>,
    inner: RefCell<SimplexFuzzEngineInner<Program, Args, Wit>>,
    _phantom: PhantomData<Program>,
}

impl Default for FuzzContext {
    fn default() -> Self {
        let default_network = SimplicityNetwork::default_regtest();
        Self {
            signer: None,
            network: default_network,
            mock_provider: MockProvider {
                network: default_network,
            },
        }
    }
}

impl FuzzContext {
    fn with_signer(&mut self, signer: Signer) {
        self.signer = Some(signer);
    }
}

pub trait ProgramCheck {
    fn call<
        FuzzProgram: FuzzableProgram<FuzzProgram, Args>,
        Args: ArgumentsTrait + Clone + 'static,
        Wit: WitnessTrait + Clone + 'static,
    >(
        &self,
        ctx: &FuzzContext,
        tx: &Transaction,
        program: Box<FuzzProgram>,
        witness: Box<dyn WitnessTrait>,
    ) -> Result<(), String>;
}

impl<FuzzProgram, Args, Wit> SimplexFuzzEngine<FuzzProgram, Args, Wit>
where
    Args: ArgumentsTrait + std::fmt::Debug + Clone + 'static,
    Wit: WitnessTrait + std::fmt::Debug + Clone + 'static,
    FuzzProgram: FuzzableProgram<FuzzProgram, Args> + Clone + 'static,
{
    pub fn from_config(
        config: proptest::test_runner::Config,
        _phantom: PhantomData<FuzzProgram>,
    ) -> Self {
        Self {
            runner: RefCell::new(proptest::test_runner::TestRunner::new(config)),
            inner: RefCell::new(SimplexFuzzEngineInner {
                fuzz_context: FuzzContext::default(),
                strategy_storage: vec![],
                base_gen: None,
                mod_gen: None,
            }),
            _phantom,
        }
    }

    pub fn with_signer(&self, signer: Signer) {
        self.inner.borrow_mut().fuzz_context.with_signer(signer);
    }

    pub fn with_default_signer(&self) {
        let network = self.inner.borrow().fuzz_context.network;
        self.inner
            .borrow_mut()
            .fuzz_context
            .with_signer(Signer::new(
                DEFAULT_TEST_MNEMONIC,
                Box::new(MockProvider { network }),
            ));
    }

    pub fn with_pset_base_gen_strategy<G>(&self)
    where
        G: FuzzableBaseContextGen<FuzzProgram, Args, Wit> + Default + 'static,
    {
        self.inner.borrow_mut().base_gen = Some(Box::new(G::default()));
    }

    pub fn with_pset_strategy<G>(&self)
    where
        G: FuzzableContextGen<FuzzProgram, Args, Wit> + Default + 'static,
    {
        self.inner.borrow_mut().mod_gen = Some(Box::new(G::default()));
    }

    pub fn with_arg_gen_strategy<S>(&self)
    where
        S: ArgGenFuzzStrategy<Args, Wit> + Default + 'static,
    {
        self.inner
            .borrow_mut()
            .strategy_storage
            .push(Box::new(S::default()));
    }

    pub fn run_with_check(&self, program_check_fn: impl ProgramCheck) {
        let mut runner = self.runner.borrow_mut();
        let inner = self.inner.borrow();

        let base_gen = inner
            .base_gen
            .as_ref()
            .expect("Base gen strategy must be configured");
        let modifier = inner
            .mod_gen
            .as_ref()
            .expect("Mod gen strategy must be configured");

        for strategy_gen in inner.strategy_storage.iter() {
            let strategy = strategy_gen.get_strategy(&inner.fuzz_context);

            runner.new_rng();
            runner
                .run(&strategy, |(args, wit)| {
                    let context = &inner.fuzz_context;
                    let ft = base_gen.build_base_transaction(
                        &context.network,
                        args.clone(),
                        wit.clone(),
                    );
                    // TODO: maybe make a couple of modification for one ft if non-default used?
                    let tx = modifier
                        .modify_transaction(&inner.fuzz_context.signer, ft, &args, &wit)
                        .unwrap();

                    let (failure_program, _script) =
                        FuzzProgram::build_program(args.clone(), &context.network);
                    let witness_ref: Box<dyn WitnessTrait> = Box::new(wit.clone());

                    match program_check_fn.call::<FuzzProgram, Args, Wit>(
                        context,
                        &tx,
                        failure_program,
                        witness_ref,
                    ) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(TestCaseError::fail(e)),
                    }
                })
                .unwrap();
        }
    }
}

pub trait ArgGenFuzzStrategy<Args, Wit> {
    fn get_strategy(&self, test_context: &FuzzContext) -> BoxedStrategy<(Args, Wit)>;
}

pub struct Random<Args, Wit> {
    phantom_data: PhantomData<(Args, Wit)>,
}

impl<Args, Wit> Default for Random<Args, Wit> {
    fn default() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

impl ArgGenFuzzStrategy<FailureTestArguments, FailureTestWitness>
    for Random<FailureTestArguments, FailureTestWitness>
{
    fn get_strategy(
        &self,
        _test_context: &FuzzContext,
    ) -> BoxedStrategy<(FailureTestArguments, FailureTestWitness)> {
        fn arb_failure_test_params()
        -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
            (
                arb_32_bytes().prop_map(|val| FailureTestArguments { failure_value: val }),
                arb_32_bytes().prop_map(|val| FailureTestWitness { cmp_value: val }),
            )
        }

        arb_failure_test_params().boxed()
    }
}

pub struct RandomEq<Args, Wit> {
    phantom_data: PhantomData<(Args, Wit)>,
}

impl<Args, Wit> Default for RandomEq<Args, Wit> {
    fn default() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

// general purpose runner
impl ArgGenFuzzStrategy<FailureTestArguments, FailureTestWitness>
    for RandomEq<FailureTestArguments, FailureTestWitness>
{
    fn get_strategy(
        &self,
        _test_context: &FuzzContext,
    ) -> BoxedStrategy<(FailureTestArguments, FailureTestWitness)> {
        fn arb_failure_test_params_eq()
        -> impl Strategy<Value = (FailureTestArguments, FailureTestWitness)> {
            arb_32_bytes().prop_map(|val| {
                (
                    FailureTestArguments { failure_value: val },
                    FailureTestWitness { cmp_value: val },
                )
            })
        }

        arb_failure_test_params_eq().boxed()
    }
}
