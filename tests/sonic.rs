#[cfg(test)]
mod tests {
    extern crate sapling_crypto;
    extern crate sonic_ucse;

    use dusk_bytes::Serializable;
    use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;
    use sapling_crypto::circuit;
    use sapling_crypto::jubjub::fs::FsRepr;
    use sapling_crypto::jubjub::JubjubBls12;
    use sapling_crypto::jubjub::PrimeOrder;
    use sonic_ucse::circuits::adaptor::AdaptorCircuit;
    use sonic_ucse::util::{
        byte_arr_to_be_arr, byte_arr_to_bool_arr, dusk_to_sapling, le_bytes_to_le_bits,
        le_bytes_to_sapling_scalar, le_opt_vec_to_sapling_scalar, opt_vec_to_jubjub_scalar,
    };
    use sonic_ucse::{protocol::*, srs::SRS, synthesis::Permutation3};
    const PEDERSEN_PREIMAGE_BITS: usize = 384;

    struct Vars {
        srs: SRS<Bls12>,
        params: JubjubBls12,
        preimage: Preimage,
        rand: Rand,
    }
    impl Vars {
        fn new() -> Vars {
            let srs = SRS::<Bls12>::dummy(
                830564,
                Fr::from_str("23923").unwrap(),
                Fr::from_str("23728792").unwrap(),
            );
            let params = sapling_crypto::jubjub::JubjubBls12::new();
            let preimage = Preimage::dummy();
            let rand = Rand::new();
            Vars {
                srs,
                params,
                preimage,
                rand,
            }
        }
    }

    struct Preimage {
        opt: Vec<Option<bool>>,
        pt: JubJubExtended,
        sapling: sapling_crypto::jubjub::edwards::Point<Bls12, PrimeOrder>,
        bool: [bool; PEDERSEN_PREIMAGE_BITS],
    }
    impl Preimage {
        fn dummy() -> Preimage {
            let opt = vec![Some(true); PEDERSEN_PREIMAGE_BITS];
            let pt = GENERATOR_EXTENDED * opt_vec_to_jubjub_scalar(&opt);
            let sapling = dusk_to_sapling(pt);
            let bool =
                std::convert::TryInto::try_into(opt.iter().map(|b| b.unwrap()).collect::<Vec<_>>())
                    .unwrap();
            assert_eq!(bool, [true; PEDERSEN_PREIMAGE_BITS]);
            Preimage {
                opt,
                pt,
                sapling,
                bool,
            }
        }
    }

    struct Rand {
        scalar: JubJubScalar,
        // bool: [bool; JubJubScalar::SIZE * 8],
        opt: Vec<Option<bool>>,
        sapling: FsRepr,
        // sapling_le: FsRepr,
    }
    impl Rand {
        fn new() -> Rand {
            let scalar = JubJubScalar::random(&mut rand::thread_rng());
            let be_bytes = scalar
                .to_bytes()
                .iter()
                .rev()
                .map(|x| *x)
                .collect::<Vec<u8>>();
            let le_bytes = scalar.to_bytes();

            // scalar to little-endian *bit* order
            let mut bits_le = [false; JubJubScalar::SIZE * 8];
            le_bytes_to_le_bits(le_bytes.as_slice(), JubJubScalar::SIZE, &mut bits_le);
            let opt_le = bits_le.iter().map(|x| Some(*x)).collect::<Vec<_>>();

            // sapling scalar
            let mut sapling = FsRepr([0; 4]);
            use pairing::PrimeFieldRepr;
            sapling.read_le(le_bytes.as_slice());
            // sapling.read_be(be_bytes.as_slice());
            // let mut sapling_le = FsRepr([0; 4]);
            // sapling_le.read_be(le_bytes.as_slice());

            Rand {
                scalar,
                // bool,
                opt: opt_le,
                sapling,
                // sapling_le,
            }
        }
    }

    #[test]
    fn test_dusk_sapling_ops() {
        #![allow(non_snake_case)]
        use dusk_jubjub::JubJubScalar;
        let a = JubJubScalar::random(&mut rand::thread_rng());
        let A = GENERATOR_EXTENDED * a;
        let b = JubJubScalar::random(&mut rand::thread_rng());
        let B = GENERATOR_EXTENDED * b;
        let sum_dusk = A + B;

        let A_sapling = dusk_to_sapling(A);
        let B_sapling = dusk_to_sapling(B);
        let params = sapling_crypto::jubjub::JubjubBls12::new();

        // point addition
        let sum_sapling = A_sapling.add(&B_sapling, &params);

        assert!(dusk_to_sapling(sum_dusk) == sum_sapling);

        // scalar multiplication
        let s = JubJubScalar::random(&mut rand::thread_rng());
        let prod_dusk = A * s;
        print!("{:?}", prod_dusk);

        let s_bytes = s.to_bytes(); // little-endian
        let s_sapling = le_bytes_to_sapling_scalar(s_bytes);
        let prod_sapling = A_sapling.mul(s_sapling, &params);
        print!("{:?}", prod_sapling.into_xy());
        print!("{:?}", dusk_to_sapling(prod_dusk).into_xy());

        assert!(dusk_to_sapling(prod_dusk) == prod_sapling);
    }

    #[test]
    fn test_elgamal_comp_dusk() {
        use dusk_jubjub::GENERATOR_EXTENDED;

        // variables
        let vars = Vars::new();

        // encrypt using jubjub-elgamal
        let c: jubjub_elgamal::Cypher = vars.srs.pk.encrypt(vars.preimage.pt, vars.rand.scalar);

        // encrypt manually
        let gamma_prime = GENERATOR_EXTENDED * vars.rand.scalar;
        let delta_prime = vars.srs.pk.0 * vars.rand.scalar + vars.preimage.pt;

        assert_eq!(c.gamma(), gamma_prime);
        assert_eq!(c.delta(), delta_prime);
    }

    #[test]
    fn test_elgamal_comp_sapling() {
        use dusk_jubjub::GENERATOR_EXTENDED;

        // variables
        let vars = Vars::new();
        let generator_sapling = dusk_to_sapling(GENERATOR_EXTENDED);
        let pk_sapling = dusk_to_sapling(vars.srs.pk.0);
        // let preimage_sapling = dusk_to_sapling(vars.preimage.pt);

        // encrypt using jubjub-elgamal
        let c_dusk: jubjub_elgamal::Cypher =
            vars.srs.pk.encrypt(vars.preimage.pt, vars.rand.scalar);
        let c_sapling = (
            dusk_to_sapling(c_dusk.gamma()),
            dusk_to_sapling(c_dusk.delta()),
        );

        // encrypt manually *in sapling*
        let gamma_prime = generator_sapling.mul(vars.rand.sapling, &vars.params);
        let delta_prime = pk_sapling
            .mul(vars.rand.sapling, &vars.params)
            .add(&vars.preimage.sapling, &vars.params);

        // dbg!(
        //     "gamma: {}\ngamma': {}\n",
        //     c_sapling.0.into_xy(),
        //     gamma_prime.into_xy()
        // );
        // dbg!(
        //     "delta: {}\ndelta': {}",
        //     c_sapling.1.into_xy(),
        //     delta_prime.into_xy()
        // );
        assert!(c_sapling.0 == gamma_prime);
        assert!(c_sapling.1 == delta_prime);
    }

    #[test]
    #[ignore]
    fn test_sapling_ops_out_in_circuit() {
        // do the same ops as in the test_dusk_sapling_ops
        // sapling outside the circuit
        // AND inside the circuit (simple circuit)
        // check they are the same.
        use sapling_crypto::jubjub::edwards::Point;
        use sonic_ucse::{Statement, WitnessScalar};
        pub struct TestCircuit<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> {
            pub params: &'a E::Params,
            pub A: Point<E, Subgroup>,
            pub B: Point<E, Subgroup>,
            pub s: Vec<Option<bool>>,
            pub sum: Point<E, Subgroup>,
            pub prod: Point<E, Subgroup>,
        }
        impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Clone
            for TestCircuit<'a, E, Subgroup>
        {
            fn clone(&self) -> Self {
                TestCircuit {
                    params: self.params,
                    A: self.A.clone(),
                    B: self.B.clone(),
                    s: self.s.clone(),
                    sum: self.sum.clone(),
                    prod: self.prod.clone(),
                }
            }
        }
        impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> Statement
            for TestCircuit<'a, E, Subgroup>
        {
            fn get_statement_bytes(&self) -> &[u8] {
                b"dummy statement"
            }
        }
        impl<'a, E: sapling_crypto::jubjub::JubjubEngine + 'a, Subgroup> WitnessScalar
            for TestCircuit<'a, E, Subgroup>
        {
            fn get_witness_scalar(&self) -> JubJubScalar {
                JubJubScalar::from(0u64)
            }
        }
        impl<'a, E: sapling_crypto::jubjub::JubjubEngine, Subgroup> bellman::Circuit<E>
            for TestCircuit<'a, E, Subgroup>
        {
            fn synthesize<CS: bellman::ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), bellman::SynthesisError> {
                use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
                use sapling_crypto::circuit::ecc::EdwardsPoint;

                // input scalars
                let mut s = vec![];
                for &bit in self.s.iter() {
                    s.push(Boolean::from(AllocatedBit::alloc(&mut *cs, bit)?));
                }
                // input points
                let A = EdwardsPoint::witness(&mut *cs, Some(self.A), self.params)?;
                let B = EdwardsPoint::witness(&mut *cs, Some(self.B), self.params)?;
                let sum = EdwardsPoint::witness(&mut *cs, Some(self.sum), self.params)?;
                let prod = EdwardsPoint::witness(&mut *cs, Some(self.prod), self.params)?;

                // point addition
                let sum_prime = A.add(cs.namespace(|| "point addition"), &B, self.params)?;

                // scalar multiplication
                let prod_prime =
                    A.mul(cs.namespace(|| "scalar multiplication"), &s, self.params)?;

                println!(
                    "sum: {:?}, {:?}, sum': {:?}, {:?}",
                    sum.get_x().get_value(),
                    sum.get_y().get_value(),
                    sum_prime.get_x().get_value(),
                    sum_prime.get_y().get_value()
                );
                dbg!(
                    "prod: {}, {}, prod': {}, {}",
                    prod.get_x().get_value(),
                    prod.get_y().get_value(),
                    prod_prime.get_x().get_value(),
                    prod_prime.get_y().get_value()
                );

                cs.enforce(
                    || "sum constraint x-coord",
                    |lc| lc + sum.get_x().get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + sum_prime.get_x().get_variable(),
                );
                cs.enforce(
                    || "sum constraint y-coord",
                    |lc| lc + sum.get_y().get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + sum_prime.get_y().get_variable(),
                );
                cs.enforce(
                    || "prod constraint x-coord",
                    |lc| lc + prod.get_x().get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + prod_prime.get_x().get_variable(),
                );
                cs.enforce(
                    || "prod constraint y-coord",
                    |lc| lc + prod.get_y().get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + prod_prime.get_y().get_variable(),
                );

                Ok(())
            }
        }
        let a = JubJubScalar::random(&mut rand::thread_rng());
        let A = GENERATOR_EXTENDED * a;
        let b = JubJubScalar::random(&mut rand::thread_rng());
        let B = GENERATOR_EXTENDED * b;
        let s = JubJubScalar::random(&mut rand::thread_rng());
        // let s = JubJubScalar::from(2u64);

        // point addition
        let sum_dusk = A + B;
        // scalar multiplication
        let prod_dusk = A * s;

        let s_le_bytes = s.to_bytes();
        // let s_be_bytes = s.to_bytes().iter().rev().map(|x| *x).collect::<Vec<u8>>();
        let mut s_bool = [false; JubJubScalar::SIZE * 8];
        le_bytes_to_le_bits(s_le_bytes.as_slice(), JubJubScalar::SIZE, &mut s_bool);
        // byte_arr_to_bool_arr(s_be_bytes.as_slice(), JubJubScalar::SIZE, &mut s_bool);
        // byte_arr_to_bool_arr(s_le_bytes.as_slice(), JubJubScalar::SIZE, &mut s_bool);
        let s_opt = s_bool.iter().map(|x| Some(*x)).collect::<Vec<_>>();

        let params = JubjubBls12::new();
        let circuit = TestCircuit {
            params: &params,
            A: dusk_to_sapling(A),
            B: dusk_to_sapling(B),
            s: s_opt,
            sum: dusk_to_sapling(sum_dusk),
            prod: dusk_to_sapling(prod_dusk),
        };

        print!("create proof");
        type ChosenBackend = Permutation3;
        let vars = Vars::new();
        let proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &vars.srs,
        )
        .unwrap();

        print!("verify proof");
        let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
            AdaptorCircuit(circuit.clone()),
            &vars.srs,
        )
        .unwrap();
        verifier.add_underlying_proof(&proof, &[], |_, _| None);
        assert_eq!(verifier.check_all(), true);
    }

    #[test]
    #[ignore]
    fn test_uc_proof_pedersen_sapling_in() {
        // We already saw in the previous test (`test_elgamal_comp_sapling`) that
        // manual sapling encryption is equivalent to jubjub-elgamal encryption.
        // Let's pass in the manual sapling ctxt instead of the jubjub-elgamal ctxt
        // and see if the proof passes then.
        use sapling_crypto::pedersen_hash;
        use sonic_ucse::circuits::adaptor::AdaptorCircuit;
        use sonic_ucse::circuits::pedersen::PedersenHashPreimageUCCircuit;
        use sonic_ucse::util::dusk_to_sapling;

        // set up proof statement variables
        let vars = Vars::new();
        let digest = pedersen_hash::pedersen_hash(
            pedersen_hash::Personalization::NoteCommitment,
            vars.preimage.bool,
            &vars.params,
        );
        // compute ctxt manually in sapling
        let generator_sapling = dusk_to_sapling(GENERATOR_EXTENDED);
        let pk_sapling = dusk_to_sapling(vars.srs.pk.0);
        let gamma = generator_sapling.mul(vars.rand.sapling, &vars.params);
        // let gamma = generator_sapling.mul(vars.rand.sapling, &vars.params);
        let s = pk_sapling.mul(vars.rand.sapling, &vars.params);
        let delta = pk_sapling
            .mul(vars.rand.sapling, &vars.params)
            .add(&vars.preimage.sapling, &vars.params);
        let c_sapling = (gamma, delta);
        // TODO this^ should be the same thing happening inside the circuit? And yet it doesn't pass... is something wrong with the computation in the circuit?
        // dbg!("pk outside circuit: {}", pk_sapling.into_xy());
        dbg!("s: {}", s.into_xy());
        // dbg!("gamma.into_xy(): {}", c_sapling.0.into_xy());

        let circuit = PedersenHashPreimageUCCircuit {
            params: &vars.params,
            pk: pk_sapling,
            // x' = (x, c, cpk, cpk_o)
            digest,
            c: c_sapling,
            cpk: dusk_to_sapling(*vars.srs.cpk.as_ref()),
            cpk_o: generator_sapling,
            //dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
            // w' = (w, omega, shift)
            preimage: vars.preimage.opt,
            preimage_pt: vars.preimage.sapling,
            omega: vars.rand.opt,
            shift: vec![Some(true); JubJubScalar::SIZE], // garbage shift (shift is unknown to honest prover)
        };
        print!("create proof");
        type ChosenBackend = Permutation3;
        let proof =
            create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &vars.srs)
                .unwrap();
        // let proof = create_proof::<Bls12>(&srs, digest, preimage_opt).unwrap();

        // print!("verify proof");
        // let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
        //     AdaptorCircuit(circuit.clone()),
        //     &vars.srs,
        // )
        // .unwrap();
        // verifier.add_proof(&proof, &[], |_, _| None);
        // assert_eq!(verifier.check_all(), true); // TODO
    }

    #[test]
    fn test_uc_proof_pedersen() {
        use sapling_crypto::pedersen_hash;
        use sonic_ucse::circuits::adaptor::AdaptorCircuit;
        use sonic_ucse::circuits::pedersen::PedersenHashPreimageUCCircuit;
        use sonic_ucse::util::dusk_to_sapling;

        // set up proof statement variables
        let vars = Vars::new();
        let digest = pedersen_hash::pedersen_hash(
            pedersen_hash::Personalization::NoteCommitment,
            vars.preimage.bool,
            &vars.params,
        );
        let c: jubjub_elgamal::Cypher = vars.srs.pk.encrypt(vars.preimage.pt, vars.rand.scalar);

        let circuit = PedersenHashPreimageUCCircuit {
            params: &vars.params,
            pk: dusk_to_sapling(vars.srs.pk.0),
            // x' = (x, c, cpk, cpk_o)
            digest,
            c: (dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta())),
            cpk: dusk_to_sapling(*vars.srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
            // w' = (w, omega, shift)
            preimage: vars.preimage.opt,
            preimage_pt: vars.preimage.sapling,
            omega: vars.rand.opt,
            shift: vec![Some(true); JubJubScalar::SIZE], // garbage shift (shift is unknown to honest prover)
        };
        print!("create proof");
        type ChosenBackend = Permutation3;
        let proof =
            create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &vars.srs)
                .unwrap();
        // let proof = create_proof::<Bls12>(&srs, digest, preimage_opt).unwrap();

        print!("verify proof");
        let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
            AdaptorCircuit(circuit.clone()),
            &vars.srs,
        )
        .unwrap();
        verifier.add_proof(&proof, &[], |_, _| None);
        assert_eq!(verifier.check_all(), true);
    }

    #[test]
    #[ignore]
    fn test_or_proof_pedersen() {
        use sapling_crypto::pedersen_hash;
        use sonic_ucse::circuits::adaptor::AdaptorCircuit;
        use sonic_ucse::circuits::pedersen::PedersenHashPreimageORShiftCircuit;
        use sonic_ucse::util::dusk_to_sapling;
        const PEDERSEN_PREIMAGE_BITS: usize = 384;
        const JUBJUB_SCALAR_BITS: u32 = Fr::NUM_BITS;

        print!("make srs");
        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();
        let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);

        // set up proof statement variables
        let params = sapling_crypto::jubjub::JubjubBls12::new();
        let preimage_opt = vec![Some(true); PEDERSEN_PREIMAGE_BITS];
        let preimage_bool = vec![true; PEDERSEN_PREIMAGE_BITS];
        let digest = pedersen_hash::pedersen_hash(
            pedersen_hash::Personalization::NoteCommitment,
            preimage_bool,
            &params,
        );
        let circuit = PedersenHashPreimageORShiftCircuit {
            params: &params,
            digest: digest,
            cpk: dusk_to_sapling(*srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
            preimage: preimage_opt,
            shift: vec![Some(true); std::convert::TryInto::try_into(JUBJUB_SCALAR_BITS).unwrap()], // garbage shift (shift is unknown to honest prover)
        };
        print!("create proof");
        type ChosenBackend = Permutation3;
        let proof = create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
            .unwrap();
        // let proof = create_proof::<Bls12>(&srs, digest, preimage_opt).unwrap();

        print!("verify proof");
        let mut verifier =
            MultiVerifier::<Bls12, _, ChosenBackend>::new(AdaptorCircuit(circuit.clone()), &srs)
                .unwrap();
        verifier.add_proof(&proof, &[], |_, _| None);
        assert_eq!(verifier.check_all(), true);
    }

    #[test]
    #[ignore]
    fn test_proof_pedersen() {
        use sonic_ucse::circuits::pedersen::PedersenHashPreimageCircuit;
        const PEDERSEN_PREIMAGE_BITS: usize = 384;

        print!("make srs");
        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();
        let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);

        // set up proof statement variables
        let params = sapling_crypto::jubjub::JubjubBls12::new();
        // x' := (digest, c, cpk, cpk_0) // TODO add c (AND)
        let preimage_opt = vec![Some(true); PEDERSEN_PREIMAGE_BITS];
        let circuit = PedersenHashPreimageCircuit {
            preimage: preimage_opt,
            params: &params,
        };

        print!("create proof");
        type ChosenBackend = Permutation3;
        let proof = create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
            .unwrap();

        print!("verify proof");
        let mut verifier =
            MultiVerifier::<Bls12, _, ChosenBackend>::new(AdaptorCircuit(circuit.clone()), &srs)
                .unwrap();
        verifier.add_proof(&proof, &[], |_, _| None);
        assert_eq!(verifier.check_all(), true); // TODO
    }
}
