extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::PrimeField;
use sapling_crypto::jubjub::edwards::Point;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::pedersen::PedersenHashPreimageORShiftCircuit;
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;

fn main() {
    use pairing::bls12_381::{Bls12, Fr};
    use std::time::Instant;

    {
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

        use sonic_ucse::util::{dusk_to_sapling, opt_vec_to_jubjub_scalar};
        // convert cpk_o, cpk from dusk to sapling representation
        // - cpk_o = generator of the prime-order subgroup
        let cpk_o_sapling: Point<_, _> = dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED);
        let cpk_sapling: Point<_, _> = dusk_to_sapling(*srs.cpk.as_ref());

        use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
        use sapling_crypto::pedersen_hash;
        const PEDERSEN_PREIMAGE_BITS: usize = 384;
        const JUBJUB_SCALAR_BITS: u32 = Fr::NUM_BITS;
        let preimage_opt = vec![Some(true); PEDERSEN_PREIMAGE_BITS];
        let preimage_bool = vec![true; PEDERSEN_PREIMAGE_BITS];
        let message = GENERATOR_EXTENDED * opt_vec_to_jubjub_scalar(&preimage_opt);
        let rand = JubJubScalar::random(&mut rand::thread_rng());
        let c: jubjub_elgamal::Cypher = srs.pk.encrypt(message, rand);
        // circuit will check for some (scalar) witness w := shift that cpk_o * shift = cpk (remember ECs are additive groups)
        let params = sapling_crypto::jubjub::JubjubBls12::new();
        let circuit = PedersenHashPreimageORShiftCircuit {
            params: &params,
            // x' = (x, ct, cpk, cpk_o)
            digest: pedersen_hash::pedersen_hash(
                pedersen_hash::Personalization::NoteCommitment,
                preimage_bool,
                &params,
            ),
            cpk: cpk_sapling,
            cpk_o: cpk_o_sapling,
            // w' = (w, omega, shift)
            preimage: preimage_opt,
            shift: vec![Some(true); std::convert::TryInto::try_into(JUBJUB_SCALAR_BITS).unwrap()],
        };

        println!("creating proof");
        let start = Instant::now();
        let proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &srs,
        )
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
            proofs.as_slice(),
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
                    verifier.add_underlying_proof(&proof, &[], |_, _| None);
                }
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
                    verifier.add_underlying_proof(&proof, &[], |_, _| None);
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
            // TODO NG uncomment
            // println!("verifying 100 proofs with advice");
            // let start = Instant::now();
            // {
            //     for (ref proof, ref advice) in &proofs {
            //         verifier.add_proof_with_advice(proof, &[], advice);
            //     }
            //     verifier.add_aggregate(proofs.as_slice(), &aggregate);
            //     assert_eq!(verifier.check_all(), true); // TODO
            // }
            // println!("done in {:?}", start.elapsed());
        }
    }
}
