use crate::failure_test::core::{DEFAULT_TEST_MNEMONIC, MockProvider};
use crate::failure_test::possible_interface::{
    DefaultBaseContextGen, DefaultContextGen, FuzzContext, FuzzableProgram, ProgramCheck, Random,
    SimplexFuzzEngine,
};
use contracts::artifacts::failure_test::FailureTestProgram;
use contracts::artifacts::failure_test::derived_failure_test::{
    FailureTestArguments, FailureTestWitness,
};
use contracts::programs::program::SimplexProgram2;
use simplex::program::{ArgumentsTrait, Program, ProgramTrait, WitnessTrait};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;
use simplex::simplicityhl::elements::Transaction;
use std::fmt;
use std::marker::PhantomData;

impl FuzzableProgram<FailureTestProgram, FailureTestArguments> for FailureTestProgram {
    fn build_program(
        args: FailureTestArguments,
        network: &SimplicityNetwork,
    ) -> (Box<FailureTestProgram>, Script) {
        let prog = FailureTestProgram::new(args);
        let script = prog.get_script_pubkey(network);
        (Box::new(prog), script)
    }
}

struct FailureTestCheck;

impl ProgramCheck for FailureTestCheck {
    fn call<
        FuzzProgram: FuzzableProgram<FuzzProgram, Args>,
        Args: ArgumentsTrait + Clone + 'static,
        Wit: WitnessTrait + Clone + 'static,
    >(
        &self,
        context: &FuzzContext,
        tx: &Transaction,
        program: Box<FuzzProgram>,
        witness: Box<dyn WitnessTrait>,
    ) -> Result<(), String> {
        // fina; transaction
        let pst =
            simplex::simplicityhl::elements::pset::PartiallySignedTransaction::from_tx(tx.clone());
        // move to inner context
        match program
            .get_program()
            .execute(&pst, &witness.build_witness(), 0, &context.network)
            // add user implemtation asset for error or not  (pst + witness + cmp somthing)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Execution failed: {:?}", e)),
        }
    }
}

#[test]
fn possible_interface_2() -> anyhow::Result<()> {
    let fuzz_engine = SimplexFuzzEngine::<
        FailureTestProgram,
        FailureTestArguments,
        FailureTestWitness,
    >::from_config(proptest::test_runner::Config::default(), PhantomData);

    fuzz_engine.with_default_signer();
    fuzz_engine.with_pset_base_gen_strategy::<DefaultBaseContextGen>();
    fuzz_engine.with_pset_strategy::<DefaultContextGen>();
    fuzz_engine.with_arg_gen_strategy::<Random<FailureTestArguments, FailureTestWitness>>();

    fuzz_engine.run_with_check(FailureTestCheck);

    Ok(())
}
