use simplex::program::Program;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;

pub trait SimplexProgram {
    fn get_script_pubkey(&self) -> Script {
        self.get_program().get_script_pubkey(self.get_network())
    }

    fn get_script_hash(&self) -> [u8; 32] {
        self.get_program().get_script_hash(self.get_network())
    }

    fn get_program(&self) -> &Program;

    fn get_network(&self) -> &SimplicityNetwork;
}
