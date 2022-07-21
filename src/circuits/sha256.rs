use crate::util::be_opt_vec_to_jubjub_scalar;
use crate::{Statement, WitnessScalar};
use dusk_jubjub::JubJubScalar;
use pairing::Engine;

#[derive(Clone)]
struct SHA256PreimageCircuit {
    preimage: Vec<Option<bool>>,
}

// impl Statement<Vec<Option<bool>>> for SHA256PreimageCircuit {
impl Statement for SHA256PreimageCircuit {
    // fn get_statement(&self) -> Vec<Option<bool>> {
    //     self.preimage
    // }
    fn get_statement_bytes(&self) -> &[u8] {
        b"TODO NG fake statement instead of hash digest"
    }
}
impl WitnessScalar for SHA256PreimageCircuit {
    fn get_witness_scalar(&self) -> JubJubScalar {
        assert!(self.preimage.len() <= 512);
        be_opt_vec_to_jubjub_scalar(&self.preimage)
    }
}
impl<E: Engine> bellman::Circuit<E> for SHA256PreimageCircuit {
    fn synthesize<CS: bellman::ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        //use bellman::ConstraintSystem;
        use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
        use sapling_crypto::circuit::sha256::sha256_block_no_padding;

        let mut preimage = vec![];

        for &bit in self.preimage.iter() {
            preimage.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }

        sha256_block_no_padding(&mut *cs, &preimage)?;
        // sha256_block_no_padding(&mut *cs, &preimage)?;
        // sha256_block_no_padding(&mut *cs, &preimage)?;
        // sha256_block_no_padding(&mut *cs, &preimage)?;

        Ok(())
    }
}
