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

pub trait SimplexProgram2 {
    fn get_script_pubkey(&self, network: &SimplicityNetwork) -> Script {
        self.get_program().get_script_pubkey(network)
    }

    fn get_script_hash(&self, network: &SimplicityNetwork) -> [u8; 32] {
        self.get_program().get_script_hash(network)
    }

    fn get_program(&self) -> &Program;
    fn get_mut_program(&mut self) -> &mut Program;
}

pub trait SimplexProgramExtended: SimplexProgram2 {
    #[must_use]
    fn set_storage_at(&mut self, index: usize, new_value: [u8; 32]) {
        self.get_mut_program().set_storage_at(index, new_value);
    }
    #[must_use]
    fn get_storage_len(&self) -> usize {
        self.get_program().get_storage_len()
    }
    #[must_use]
    fn get_storage(&self) -> &[[u8; 32]] {
        self.get_program().get_storage()
    }
    #[must_use]
    fn get_storage_at(&self, index: usize) -> [u8; 32] {
        self.get_program().get_storage_at(index)
    }
    #[must_use]
    fn get_script_pubkey(&self, network: &SimplicityNetwork) -> Script {
        self.get_program().get_script_pubkey(network)
    }
    #[must_use]
    fn get_script_hash(&self, network: &SimplicityNetwork) -> [u8; 32] {
        self.get_program().get_script_hash(network)
    }
}
