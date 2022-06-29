use crate::util::bool_vec_to_bytes;
use crate::{Scalarable, Statement};
use dusk_jubjub::JubJubScalar;

// 'a is a named lifetime (borrowed pointers are required to have lifetimes in impls)
pub struct PedersenHashPreimageCircuit<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> {
    pub preimage: Vec<Option<bool>>,
    pub params: &'a E::Params,
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> Statement
    for PedersenHashPreimageCircuit<'a, E>
{
    fn get_statement(&self) -> &[u8] {
        b"fake statement instead of hash digest"
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> Scalarable
    for PedersenHashPreimageCircuit<'a, E>
{
    fn to_scalar(&self) -> JubJubScalar {
        assert!(self.preimage.len() <= 512);
        JubJubScalar::from_bytes_wide(&bool_vec_to_bytes(&self.preimage))
    }
}
// trait Clone for PedersenHashPreimageCircuit
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> Clone
    for PedersenHashPreimageCircuit<'a, E>
{
    fn clone(&self) -> Self {
        PedersenHashPreimageCircuit {
            preimage: self.preimage.clone(),
            params: self.params,
        }
    }
}
// trait bellman::Circuit<Scalar: PrimeField> for PedersenHashPreimageCircuit
// https://docs.rs/bellman/0.11.1/bellman/trait.Circuit.html
// i.e. a circuit that can be syntehsized (with `synthesize` during CRSgen and P)
impl<'a, E: sapling_crypto::jubjub::JubjubEngine> bellman::Circuit<E>
    for PedersenHashPreimageCircuit<'a, E>
{
    fn synthesize<CS: bellman::ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        //use bellman::ConstraintSystem;
        use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
        use sapling_crypto::circuit::pedersen_hash;

        let mut preimage = vec![];

        for &bit in self.preimage.iter() {
            preimage.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }

        pedersen_hash::pedersen_hash(
            &mut *cs,
            pedersen_hash::Personalization::NoteCommitment,
            &preimage,
            self.params,
        )?;

        Ok(())
    }
}

// Language for Pedersen preimage OR cpk shift
use sapling_crypto::circuit::ecc::EdwardsPoint;
use sapling_crypto::jubjub::edwards::Point;
pub struct PedersenHashPreimageORShiftCircuit<
    'a,
    E: sapling_crypto::jubjub::JubjubEngine + 'a,
    Subgroup,
> {
    pub preimage: Vec<Option<bool>>,
    pub params: &'a E::Params,
    pub shift: Vec<Option<bool>>, // shift is a scalar
    // TODO NG this is part of statement not witness
    pub cpk_o: Point<E, Subgroup>,
    pub cpk: Point<E, Subgroup>,
    pub digest: Point<E, Subgroup>,
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Clone
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn clone(&self) -> Self {
        PedersenHashPreimageORShiftCircuit {
            preimage: self.preimage.clone(),
            params: self.params,
            shift: self.shift.clone(),
            cpk_o: self.cpk_o.clone(),
            cpk: self.cpk.clone(),
            digest: self.digest.clone(),
        }
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Statement
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn get_statement(&self) -> &[u8] {
        b"TODO NG fake statement instead of hash digest, cpk, cpk_o"
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Scalarable
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn to_scalar(&self) -> JubJubScalar {
        // TODO NG the below breaks elgamal::ElGamal::encrypt(&circuit.to_big_int(), &srs.pk) (outputs Err)
        // let left = bool_vec_to_big_int(&self.preimage);
        // let right = bool_vec_to_big_int(&self.shift);
        // (left << right.bit_length()) + right
        assert!(self.preimage.len() <= 512);
        JubJubScalar::from_bytes_wide(&bool_vec_to_bytes(&self.preimage))

        // bool_vec_to_big_int(&self.preimage)
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine, Subgroup> bellman::Circuit<E>
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn synthesize<CS: bellman::ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        //use bellman::ConstraintSystem;
        use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
        // use sapling_crypto::circuit::num::{AllocatedNum, Num};
        use sapling_crypto::circuit::pedersen_hash;

        let mut preimage = vec![];
        let mut shift = vec![];

        for &bit in self.preimage.iter() {
            preimage.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }
        for &bit in self.shift.iter() {
            shift.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }

        /*******************************************************************
         * OR statement: (cpk_0 * shift == cpk) OR (H(preimage) == digest)
         * as a linear constraint: (cpk' - cpk)*(h' - digest) == 0
         *   where cpk' := cpk_0 * shift and h' := H(preimage)
         ******************************************************************/

        // left branch: shift
        // - input cpk_o
        let cpk_o = EdwardsPoint::witness(&mut *cs, Some(self.cpk_o), self.params)?;
        // - input -cpk
        let neg_cpk = EdwardsPoint::witness(&mut *cs, Some(self.cpk.negate()), self.params)?;
        // - compute cpk' = cpk_o * shift
        let cpk_prime = cpk_o.mul(
            cs.namespace(|| "multiplication of shift to cpk_o"),
            &shift,
            self.params,
        )?;
        // - compute cpk' + (-cpk)
        let left_branch = cpk_prime.add(
            cs.namespace(|| "subtract cpk from cpk_prime"),
            &neg_cpk,
            self.params,
        )?;

        // right branch: hash
        // - input preimage (see above)
        // - input -digest
        let neg_digest = EdwardsPoint::witness(&mut *cs, Some(self.digest.negate()), self.params)?;
        // - compute h' = H(preimage)
        let h_prime = pedersen_hash::pedersen_hash(
            &mut *cs,
            pedersen_hash::Personalization::NoteCommitment,
            &preimage,
            self.params,
        )?;
        // - compute h' + (-digest)
        let right_branch = h_prime.add(
            cs.namespace(|| "subtract digest from h_prime"),
            &neg_digest,
            self.params,
        )?;

        // enforce = 0
        // - x-coordinate
        cs.enforce(
            || "or constraint",
            |lc| lc + left_branch.get_x().get_variable(),
            |lc| lc + right_branch.get_x().get_variable(),
            |lc| lc + &bellman::LinearCombination::<E>::zero(),
        );
        // - y-coordinate
        cs.enforce(
            || "or constraint",
            |lc| lc + left_branch.get_y().get_variable(),
            |lc| lc + right_branch.get_y().get_variable(),
            |lc| lc + &bellman::LinearCombination::<E>::zero(),
        );

        Ok(())
    }
}