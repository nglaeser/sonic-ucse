#[cfg(test)]
mod tests {
    extern crate sapling_crypto;
    extern crate sonic_ucse;

    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;
    use sonic_ucse::circuits::adaptor::AdaptorCircuit;
    use sonic_ucse::{protocol::*, srs::SRS, synthesis::Permutation3};
    #[test]
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
        // let preimage_bytes: Vec<u8> = bool_vec_to_bytes(&preimage_opt);
        let circuit = PedersenHashPreimageORShiftCircuit {
            params: &params,
            // x' = (x,c, cpk, cpk_o)
            digest: digest,
            // TODO NG add c (AND statement)
            cpk: dusk_to_sapling(*srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
            // w' = (w, omega, shift)
            preimage: preimage_opt,
            // TODO NG add omega
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
        assert_eq!(verifier.check_all(), true); // TODO
    }

    #[test]
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
