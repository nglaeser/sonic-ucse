use crate::util::opt_vec_to_jubjub_scalar;
use crate::{Statement, WitnessScalar};
use dusk_jubjub::JubJubScalar;

// 'a is a named lifetime (borrowed pointers are required to have lifetimes in impls)
pub struct PedersenHashPreimageCircuit<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> {
    pub preimage: Vec<Option<bool>>,
    pub params: &'a E::Params,
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> Statement
    for PedersenHashPreimageCircuit<'a, E>
{
    fn get_statement_bytes(&self) -> &[u8] {
        b"fake statement instead of hash digest"
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> WitnessScalar
    for PedersenHashPreimageCircuit<'a, E>
{
    fn get_witness_scalar(&self) -> JubJubScalar {
        opt_vec_to_jubjub_scalar(&self.preimage)
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
    pub params: &'a E::Params,
    // x' = (x,c, cpk, cpk_o)
    pub digest: Point<E, Subgroup>,
    pub cpk: Point<E, Subgroup>,
    pub cpk_o: Point<E, Subgroup>,
    // w' = (w, omega, shift)
    pub preimage: Vec<Option<bool>>, // represents a Jubjub point
    pub shift: Vec<Option<bool>>,    // also represents a Jubjub scalar
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Clone
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn clone(&self) -> Self {
        PedersenHashPreimageORShiftCircuit {
            params: self.params,
            digest: self.digest.clone(),
            cpk: self.cpk.clone(),
            cpk_o: self.cpk_o.clone(),
            preimage: self.preimage.clone(),
            shift: self.shift.clone(),
        }
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Statement
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    // fn get_statement<T>(&self) -> Point<E, PrimeOrder> {
    //     self.digest
    // }
    fn get_statement_bytes(&self) -> &[u8] {
        b"TODO NG fake statement instead of hash digest, cpk, cpk_o"
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> WitnessScalar
    for PedersenHashPreimageORShiftCircuit<'a, E, Subgroup>
{
    fn get_witness_scalar(&self) -> JubJubScalar {
        opt_vec_to_jubjub_scalar(&self.preimage)
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
        // print!(
        //     "left branch: {}, {}",
        //     left_branch.get_x().get_value().unwrap(),
        //     left_branch.get_y().get_value().unwrap()
        // );

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
        // print!(
        //     "right branch: {}, {}",
        //     right_branch.get_x().get_value().unwrap(),
        //     right_branch.get_y().get_value().unwrap()
        // );

        // enforce = 0 (aka (0,1))
        // - x-coordinate
        cs.enforce(
            || "or constraint",
            |lc| lc + left_branch.get_x().get_variable(),
            |lc| lc + right_branch.get_x().get_variable(),
            |lc| lc + &bellman::LinearCombination::<E>::zero(),
        );
        // - y-coordinate // will be 1, not 0
        // cs.enforce(
        //     || "or constraint",
        //     |lc| lc + left_branch.get_y().get_variable(),
        //     |lc| lc + right_branch.get_y().get_variable(),
        //     |lc| lc + &bellman::LinearCombination::<E>::zero(),
        // );

        Ok(())
    }
}

// Full UC language for Pedersen preimage
// (i.e., (preimage OR cpk shift) AND ciphertext
pub struct PedersenHashPreimageUCCircuit<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup>
{
    pub params: &'a E::Params,
    pub pk: Point<E, Subgroup>,
    // x' = (x,c, cpk, cpk_o)
    pub digest: Point<E, Subgroup>,
    pub c: (Point<E, Subgroup>, Point<E, Subgroup>), // (gamma, delta)
    pub cpk: Point<E, Subgroup>,
    pub cpk_o: Point<E, Subgroup>,
    // w' = (w, omega, shift)
    pub preimage: Vec<Option<bool>>,     // represents a Jubjub point
    pub preimage_pt: Point<E, Subgroup>, // (specifically, this one)
    pub omega: Vec<Option<bool>>,        // represents a (Jubjub) scalar
    pub shift: Vec<Option<bool>>,        // also represents a Jubjub scalar
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Clone
    for PedersenHashPreimageUCCircuit<'a, E, Subgroup>
{
    fn clone(&self) -> Self {
        PedersenHashPreimageUCCircuit {
            params: self.params,
            pk: self.pk.clone(),
            digest: self.digest.clone(),
            c: self.c.clone(),
            cpk: self.cpk.clone(),
            cpk_o: self.cpk_o.clone(),
            preimage: self.preimage.clone(),
            preimage_pt: self.preimage_pt.clone(),
            omega: self.omega.clone(),
            shift: self.shift.clone(),
        }
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Statement
    for PedersenHashPreimageUCCircuit<'a, E, Subgroup>
{
    fn get_statement_bytes(&self) -> &[u8] {
        b"TODO NG fake statement instead of hash digest, cpk, cpk_o"
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> WitnessScalar
    for PedersenHashPreimageUCCircuit<'a, E, Subgroup>
{
    fn get_witness_scalar(&self) -> JubJubScalar {
        opt_vec_to_jubjub_scalar(&self.preimage)
    }
}
impl<'a, E: sapling_crypto::jubjub::JubjubEngine, Subgroup> bellman::Circuit<E>
    for PedersenHashPreimageUCCircuit<'a, E, Subgroup>
{
    fn synthesize<CS: bellman::ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
        use sapling_crypto::circuit::pedersen_hash;

        let mut preimage = vec![];
        let mut shift = vec![];
        let mut omega = vec![];

        for &bit in self.preimage.iter() {
            preimage.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }
        for &bit in self.shift.iter() {
            shift.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }
        for &bit in self.omega.iter() {
            omega.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
        }

        /*******************************************************************
         * Require UP.Enc(pk, w; omega) = c
         * (this is an additional constraint, so ANDs with the OR statement below)
         * as a linear constraint: (c' - c) == 0
         *   where c' := UP.Enc(pk, w; omega) = (G * omega, G * w + pk * omega)
         ******************************************************************/
        // input pk
        let pk = EdwardsPoint::witness(&mut *cs, Some(self.pk), self.params)?;
        // dbg!(
        //     "pk in circuit: {}, {}",
        //     pk.get_x().get_value(),
        //     pk.get_y().get_value()
        // );
        // input w (as a point)
        let preimage_msg = EdwardsPoint::witness(&mut *cs, Some(self.preimage_pt), self.params)?;
        // input omega (see above)
        // input G
        // TODO maybe rename cpk_o?
        let generator = EdwardsPoint::witness(&mut *cs, Some(self.cpk_o.clone()), self.params)?;
        // input c = (gamma, delta)
        // dbg!("gamma.into_xy(): {}", self.c.0.into_xy());
        let gamma = EdwardsPoint::witness(&mut *cs, Some(self.c.0), self.params)?;
        let delta = EdwardsPoint::witness(&mut *cs, Some(self.c.1), self.params)?;
        // input -c = (-gamma, -delta)
        // let neg_gamma = EdwardsPoint::witness(&mut *cs, Some(self.c.0.negate()), self.params)?;
        // let neg_delta = EdwardsPoint::witness(&mut *cs, Some(self.c.1.negate()), self.params)?;

        // compute c' = (gamma', delta') = UP.Enc(pk, w; omega)
        let s_prime = pk.mul(
            cs.namespace(|| "multiplication of pk to omega"),
            &omega,
            self.params,
        )?;
        let delta_prime = s_prime.add(
            cs.namespace(|| "add witness to s_prime"),
            &preimage_msg,
            self.params,
        )?;
        let gamma_prime = generator.mul(
            cs.namespace(|| "multiplication of generator to omega"),
            &omega,
            self.params,
        )?;

        // assert!(gamma.get_x().get_value().unwrap() == gamma_prime.get_x().get_value().unwrap());
        // assert!(gamma.get_y().get_value().unwrap() == gamma_prime.get_y().get_value().unwrap());
        // assert!(delta.get_x().get_value().unwrap() == delta_prime.get_x().get_value().unwrap());
        // assert!(delta.get_y().get_value().unwrap() == delta_prime.get_y().get_value().unwrap());

        // dbg!(
        //     "s_prime: {}, {}",
        //     s_prime.get_x().get_value(),
        //     s_prime.get_y().get_value()
        // );
        // dbg!(
        //     "gamma: {}, {}",
        //     gamma.get_x().get_value(),
        //     gamma.get_y().get_value()
        // );
        // dbg!(
        //     "gamma': {}, {}",
        //     gamma_prime.get_x().get_value().unwrap(),
        //     gamma_prime.get_y().get_value().unwrap()
        // );
        // // these match!
        // dbg!(
        //     "delta: {}, {}",
        //     delta.get_x().get_value().unwrap(),
        //     delta.get_y().get_value().unwrap()
        // );
        // dbg!(
        //     "delta': {}, {}",
        //     delta_prime.get_x().get_value().unwrap(),
        //     delta_prime.get_y().get_value().unwrap()
        // );

        // let gamma_constraint = gamma_prime.add(
        //     cs.namespace(|| "subtract gamma from gamma_prime"),
        //     &neg_gamma,
        //     self.params,
        // )?;
        // let delta_constraint = delta_prime.add(
        //     cs.namespace(|| "subtract delta from delta_prime"),
        //     &neg_delta,
        //     self.params,
        // )?;

        // enforce gamma = gamma'
        cs.enforce(
            || "ciphertext gamma constraint x-coord",
            |lc| lc + gamma.get_x().get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + gamma_prime.get_x().get_variable(),
        );
        cs.enforce(
            || "ciphertext gamma constraint y-coord",
            |lc| lc + gamma.get_y().get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + gamma_prime.get_y().get_variable(),
        );

        // enforce delta = delta'
        cs.enforce(
            || "ciphertext delta constraint x-coord",
            |lc| lc + delta.get_x().get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + delta_prime.get_x().get_variable(),
        );
        cs.enforce(
            || "ciphertext delta constraint y-coord",
            |lc| lc + delta.get_y().get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + delta_prime.get_y().get_variable(),
        );

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
        // print!(
        //     "right branch: {}, {}",
        //     right_branch.get_x().get_value().unwrap(),
        //     right_branch.get_y().get_value().unwrap()
        // );

        // enforce = 0 (aka (0,1))
        // - x-coordinate
        cs.enforce(
            || "or constraint",
            |lc| lc + left_branch.get_x().get_variable(),
            |lc| lc + right_branch.get_x().get_variable(),
            |lc| lc + &bellman::LinearCombination::<E>::zero(),
        );
        // - y-coordinate // will be 1, not 0
        // cs.enforce(
        //     || "or constraint",
        //     |lc| lc + left_branch.get_y().get_variable(),
        //     |lc| lc + right_branch.get_y().get_variable(),
        //     |lc| lc + &bellman::LinearCombination::<E>::zero(),
        // );

        Ok(())
    }
}
