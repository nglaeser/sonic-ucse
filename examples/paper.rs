extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::{Engine, Field, PrimeField};
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;
use sonic_ucse::util::bool_vec_to_bytes;
use sonic_ucse::{
    Circuit, Coeff, ConstraintSystem, LinearCombination, Scalarable, Statement, SynthesisError,
    Variable,
};
use std::marker::PhantomData;

struct Adaptor<'a, E: Engine, CS: ConstraintSystem<E> + 'a> {
    cs: &'a mut CS,
    _marker: PhantomData<E>,
}

// implements bellman::ConstraintSystem<Scalar: PrimeField> trait for Adaptor struct
// defined above
// https://docs.rs/bellman/0.11.1/bellman/trait.ConstraintSystem.html
impl<'a, E: Engine, CS: ConstraintSystem<E> + 'a> bellman::ConstraintSystem<E>
    for Adaptor<'a, E, CS>
{
    type Root = Self;

    fn one() -> bellman::Variable {
        bellman::Variable::new_unchecked(bellman::Index::Input(1))
    }

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<bellman::Variable, bellman::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = self
            .cs
            .alloc(|| f().map_err(|_| SynthesisError::AssignmentMissing))
            .map_err(|_| bellman::SynthesisError::AssignmentMissing)?;

        Ok(match var {
            Variable::A(index) => bellman::Variable::new_unchecked(bellman::Index::Input(index)),
            Variable::B(index) => bellman::Variable::new_unchecked(bellman::Index::Aux(index)),
            _ => unreachable!(),
        })
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _: A,
        f: F,
    ) -> Result<bellman::Variable, bellman::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = self
            .cs
            .alloc_input(|| f().map_err(|_| SynthesisError::AssignmentMissing))
            .map_err(|_| bellman::SynthesisError::AssignmentMissing)?;

        Ok(match var {
            Variable::A(index) => bellman::Variable::new_unchecked(bellman::Index::Input(index)),
            Variable::B(index) => bellman::Variable::new_unchecked(bellman::Index::Aux(index)),
            _ => unreachable!(),
        })
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
        LB: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
        LC: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
    {
        fn convert<E: Engine>(lc: bellman::LinearCombination<E>) -> LinearCombination<E> {
            let mut ret = LinearCombination::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let var = match v.get_unchecked() {
                    bellman::Index::Input(i) => Variable::A(i),
                    bellman::Index::Aux(i) => Variable::B(i),
                };

                ret = ret + (Coeff::Full(coeff), var);
            }

            ret
        }

        fn eval<E: Engine, CS: ConstraintSystem<E>>(
            lc: &LinearCombination<E>,
            cs: &CS,
        ) -> Option<E::Fr> {
            let mut ret = E::Fr::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let mut tmp = match cs.get_value(v) {
                    Ok(tmp) => tmp,
                    Err(_) => return None,
                };
                coeff.multiply(&mut tmp);
                ret.add_assign(&tmp);
            }

            Some(ret)
        }

        let a_lc = convert(a(bellman::LinearCombination::zero()));
        let a_value = eval(&a_lc, &*self.cs);
        let b_lc = convert(b(bellman::LinearCombination::zero()));
        let b_value = eval(&b_lc, &*self.cs);
        let c_lc = convert(c(bellman::LinearCombination::zero()));
        let c_value = eval(&c_lc, &*self.cs);

        let (a, b, c) = self
            .cs
            .multiply(|| Ok((a_value.unwrap(), b_value.unwrap(), c_value.unwrap())))
            .unwrap();

        self.cs.enforce_zero(a_lc - a);
        self.cs.enforce_zero(b_lc - b);
        self.cs.enforce_zero(c_lc - c);
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

struct AdaptorCircuit<T>(T);

// implement sonic_ucse::Circuit trait (lib.rs:16) for AdaptorCircuit struct defined above
impl<'a, E: Engine, C: bellman::Circuit<E> + Clone> Circuit<E> for AdaptorCircuit<C> {
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut adaptor = Adaptor {
            cs: cs,
            _marker: PhantomData,
        };

        match self.0.clone().synthesize(&mut adaptor) {
            Err(_) => return Err(SynthesisError::AssignmentMissing),
            Ok(_) => {}
        };

        Ok(())
    }
}
impl<C: Scalarable> Scalarable for AdaptorCircuit<C> {
    fn to_scalar(&self) -> dusk_plonk::jubjub::JubJubScalar {
        self.0.to_scalar()
    }
}
impl<C: Statement> Statement for AdaptorCircuit<C> {
    fn get_statement(&self) -> &[u8] {
        self.0.get_statement()
    }
}

fn main() {
    use dusk_plonk::jubjub::JubJubScalar;
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use std::time::Instant;

    // 'a is a named lifetime (borrowed pointers are required to have lifetimes in impls)
    struct PedersenHashPreimageCircuit<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a> {
        preimage: Vec<Option<bool>>,
        params: &'a E::Params,
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
    struct PedersenHashPreimageORShiftCircuit<
        'a,
        E: sapling_crypto::jubjub::JubjubEngine + 'a,
        Subgroup,
    > {
        preimage: Vec<Option<bool>>,
        params: &'a E::Params,
        shift: Vec<Option<bool>>, // shift is a scalar
        // TODO NG this is part of statement not witness
        cpk_o: Point<E, Subgroup>,
        cpk: Point<E, Subgroup>,
        digest: Point<E, Subgroup>,
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
            use sapling_crypto::circuit::num::{AllocatedNum, Num};
            use sapling_crypto::circuit::pedersen_hash;

            let mut preimage = vec![];
            let mut shift = vec![];

            for &bit in self.preimage.iter() {
                preimage.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
            }
            for &bit in self.shift.iter() {
                shift.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
            }
            // let cpk_o_point = EdwardsPoint::witness(&mut *cs, Some(self.cpk_o), self.params)?;

            // TODO NG add OR
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
            let neg_digest =
                EdwardsPoint::witness(&mut *cs, Some(self.digest.negate()), self.params)?;
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

            // enforce x-coordinate
            cs.enforce(
                || "or constraint",
                |lc| lc + left_branch.get_x().get_variable(),
                |lc| lc + right_branch.get_x().get_variable(),
                |lc| lc + &bellman::LinearCombination::<E>::zero(),
            );
            // enforce y-coordinate
            cs.enforce(
                || "or constraint",
                |lc| lc + left_branch.get_y().get_variable(),
                |lc| lc + right_branch.get_y().get_variable(),
                |lc| lc + &bellman::LinearCombination::<E>::zero(),
            );

            Ok(())
        }
    }

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

    {
        use sapling_crypto::jubjub::{PrimeOrder, Unknown};

        // Fr = prime (scalar) field of the groups
        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        // TODO NG why create a dummy srs and not a real one?
        let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
        // let srs = SRS::<Bls12>::new(830564,
        //     srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());

        type ChosenBackend = Permutation3;

        let samples: usize = 5;

        const PEDERSEN_PREIMAGE_BITS: usize = 384;
        const JUBJUB_SCALAR_BITS: u32 = Fr::NUM_BITS;
        let _DALEK_SCALAR_BITS: usize =
            curve25519_dalek::scalar::Scalar::one().as_bytes().len() * 8;

        let params = sapling_crypto::jubjub::JubjubBls12::new();

        // TODO NG: also input cpk into the circuit (circuit will check for some (scalar) witness w := shift that cpk_o * shift = cpk (remember ECs are additive groups))

        // set cpk_o to the generator of the prime-order subgroup
        use dusk_plonk::jubjub::{JubJubExtended, GENERATOR_EXTENDED};
        let cpk_o_dusk: JubJubExtended = GENERATOR_EXTENDED;
        let cpk_o_sapling: Point<_, PrimeOrder> = sapling_crypto::jubjub::edwards::Point::new(
            // convert each coordiniate from BlsScalar to (Bls12::)Fr
            Fr::from_repr(FrRepr(cpk_o_dusk.get_x().0)).unwrap(),
            Fr::from_repr(FrRepr(cpk_o_dusk.get_y().0)).unwrap(),
            // T = T1 * T2 = XY/Z
            Fr::from_repr(FrRepr((cpk_o_dusk.get_t1() * cpk_o_dusk.get_t2()).0)).unwrap(),
            Fr::from_repr(FrRepr(cpk_o_dusk.get_z().0)).unwrap(),
        );

        use sapling_crypto::pedersen_hash;
        let preimage_opt = vec![Some(true); PEDERSEN_PREIMAGE_BITS];
        let preimage_bool = vec![true; PEDERSEN_PREIMAGE_BITS];
        let circuit = PedersenHashPreimageORShiftCircuit {
            preimage: preimage_opt,
            params: &params,
            shift: vec![Some(true); std::convert::TryInto::try_into(JUBJUB_SCALAR_BITS).unwrap()],
            cpk_o: cpk_o_sapling,
            cpk: sapling_crypto::jubjub::edwards::Point::zero(), // TODO NG
            digest: pedersen_hash::pedersen_hash(
                pedersen_hash::Personalization::NoteCommitment,
                preimage_bool,
                &params,
            ),
        };

        println!("creating proof");
        let start = Instant::now();
        // Bls12: Engine, ChosenBackend: SynthesisDriver
        // runs AdaptorCircuit::synthesize
        // which runs circuit.synthesize(adaptor: Adaptor)
        // Adaptor implements bellman::ConstraintSystem
        let proof = create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
            .unwrap();
        println!("done in {:?}", start.elapsed());

        println!("creating advice");
        let start = Instant::now();
        let advice = create_advice::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &proof,
            &srs,
        );
        println!("done in {:?}", start.elapsed());

        println!("creating aggregate for {} proofs", samples);
        let start = Instant::now();
        let proofs: Vec<_> = (0..samples)
            .map(|_| (proof.clone(), advice.clone()))
            .collect();
        let aggregate = create_aggregate::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &proofs,
            &srs,
        );
        println!("done in {:?}", start.elapsed());

        {
            let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
                AdaptorCircuit(circuit.clone()),
                &srs,
            )
            .unwrap();
            println!("verifying 1 proof without advice");
            let start = Instant::now();
            {
                for _ in 0..1 {
                    // proof from line 442
                    verifier.add_proof(&proof, &[], |_, _| None);
                }
                // protocol.rs:294
                // Note: just running verification on the proof itself (not crs)
                assert_eq!(verifier.check_all(), true); // TODO
            }
            println!("done in {:?}", start.elapsed());
        }

        {
            let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
                AdaptorCircuit(circuit.clone()),
                &srs,
            )
            .unwrap();
            println!("verifying {} proofs without advice", samples);
            let start = Instant::now();
            {
                for _ in 0..samples {
                    verifier.add_proof(&proof, &[], |_, _| None);
                }
                assert_eq!(verifier.check_all(), true); // TODO
            }
            println!("done in {:?}", start.elapsed());
        }

        {
            let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
                AdaptorCircuit(circuit.clone()),
                &srs,
            )
            .unwrap();
            println!("verifying 100 proofs with advice");
            let start = Instant::now();
            {
                for (ref proof, ref advice) in &proofs {
                    verifier.add_proof_with_advice(proof, &[], advice);
                }
                verifier.add_aggregate(&proofs, &aggregate);
                assert_eq!(verifier.check_all(), true); // TODO
            }
            println!("done in {:?}", start.elapsed());
        }
    }
}
