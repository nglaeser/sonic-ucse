extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::PrimeField;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::pedersen::PedersenHashPreimageUCCircuit;
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;
use sonic_ucse::util::{le_bytes_to_le_bits, dusk_to_sapling, be_opt_vec_to_jubjub_scalar};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use dusk_bytes::Serializable;
use sapling_crypto::pedersen_hash;
const PEDERSEN_PREIMAGE_BITS: usize = 384;

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

        // hash preimage (underlying witness)
        let preimage_bool = vec![true; PEDERSEN_PREIMAGE_BITS];
        let preimage_opt = preimage_bool.iter().map(|x| Some(*x)).collect::<Vec<Option<bool>>>();
        let preimage_dusk = GENERATOR_EXTENDED * be_opt_vec_to_jubjub_scalar(&preimage_opt);

        // randomness for encryption (part of witness)
        let rand = JubJubScalar::random(&mut rand::thread_rng());
        let mut rand_le_bits = [false; JubJubScalar::SIZE * 8];
        le_bytes_to_le_bits(rand.to_bytes().as_slice(), JubJubScalar::SIZE, &mut rand_le_bits);
        let rand_le_opt = rand_le_bits.iter().map(|x| Some(*x)).collect::<Vec<Option<bool>>>();

        // compute ciphertext
        let c: jubjub_elgamal::Cypher = srs.pk.encrypt(preimage_dusk, rand);

        // inputs to UC circuit
        let params = sapling_crypto::jubjub::JubjubBls12::new();
        let circuit = PedersenHashPreimageUCCircuit {
            params: &params,
            pk: dusk_to_sapling(srs.pk.0),
            // x' = (x, c, cpk, cpk_o)
            digest: pedersen_hash::pedersen_hash(
                pedersen_hash::Personalization::NoteCommitment,
                preimage_bool,
                &params,
            ),
            c: (dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta())),
            cpk: dusk_to_sapling(*srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
            // w' = (w, omega, shift)
            preimage: preimage_opt,
            preimage_pt: dusk_to_sapling(preimage_dusk),
            omega: rand_le_opt,
            shift: vec![Some(true); JubJubScalar::SIZE], // garbage shift (shift is unknown to honest prover)
        };

        println!("creating proof");
        let start = Instant::now();
        let proof = create_proof::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &srs,
        )
        .unwrap();
        println!("done in {:?}", start.elapsed());

        println!("creating advice");
        let start = Instant::now();
        let advice = create_advice::<Bls12, _, ChosenBackend>(
            &AdaptorCircuit(circuit.clone()),
            &proof.pi,
            &srs,
        );
        println!("done in {:?}", start.elapsed());

        println!("creating aggregate for {} proofs", samples);
        let start = Instant::now();
        let proofs: Vec<_> = (0..samples)
            .map(|_| (proof.pi.clone(), advice.clone()))
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
                    verifier.add_proof(&proof, &[], |_, _| None);
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
                    verifier.add_underlying_proof_with_advice(proof, &[], advice);
                }
                verifier.add_aggregate(proofs.as_slice(), &aggregate);
                assert_eq!(verifier.check_all(), true); // TODO
            }
            println!("done in {:?}", start.elapsed());
        }
    }
}
