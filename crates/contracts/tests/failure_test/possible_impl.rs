use crate::failure_test::possible_interface::{
    DefaultBaseContextGen, DefaultContextGen, FuzzContext, FuzzableProgram, ProgramCheck,
    ProgramExecResult, Random, SimplexFuzzEngine,
};
use contracts::artifacts::failure_test::FailureTestProgram;
use contracts::artifacts::failure_test::derived_failure_test::{
    FailureTestArguments, FailureTestWitness,
};
use contracts::programs::program::SimplexProgram2;
use simplex::program::{ArgumentsTrait, WitnessTrait};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;
use simplex::simplicityhl::elements::Transaction;
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
    fn call<Args: ArgumentsTrait + Clone + 'static, Wit: WitnessTrait + Clone + 'static>(
        &self,
        _ctx: &FuzzContext,
        _tx: &Transaction,
        _arguments: Box<dyn ArgumentsTrait>,
        _witness: Box<dyn WitnessTrait>,
        program_exec_result: ProgramExecResult,
    ) -> Result<(), String> {
        if program_exec_result.is_err() {
            return Err("Failed contract".into());
        }
        Ok(())
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
