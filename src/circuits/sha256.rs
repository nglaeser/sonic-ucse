use crate::util::bool_vec_to_bytes;
use crate::{Scalarable, Statement};
use dusk_jubjub::JubJubScalar;
use pairing::Engine;

#[derive(Clone)]
struct SHA256PreimageCircuit {
    preimage: Vec<Option<bool>>,
}

impl Statement for SHA256PreimageCircuit {
    fn get_statement(&self) -> &[u8] {
        b"TODO NG fake statement instead of hash digest"
    }
}
impl Scalarable for SHA256PreimageCircuit {
    fn to_scalar(&self) -> JubJubScalar {
        assert!(self.preimage.len() <= 512);
        JubJubScalar::from_bytes_wide(&bool_vec_to_bytes(&self.preimage))
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
