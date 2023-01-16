extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use pairing::PrimeField;
use sapling_crypto::jubjub::PrimeOrder;
use sapling_crypto::pedersen_hash;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::{
    pedersen::PedersenHashPreimageUCCircuit, sha256::SHA256PreimageUCCircuit,
};
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;
use sonic_ucse::util::{be_opt_vec_to_jubjub_scalar, dusk_to_sapling, le_bytes_to_le_bits};
const PEDERSEN_PREIMAGE_BITS: usize = 48;
// const PEDERSEN_PREIMAGE_BITS: usize = 384;
// const SHA256_PREIMAGE_BITS: usize = 512;
const SHA256_PREIMAGE_BITS: usize = 1024;
// const SHA256_PREIMAGE_BITS: usize = 2048;
const DO_PEDERSEN: bool = true;
// const DO_PEDERSEN: bool = false;

fn main() {
    use pairing::bls12_381::{Bls12, Fr};
    use std::time::Instant;

    {
        if DO_PEDERSEN {
            println!(
                "UC-SE for Pedersen preimage size {}\n",
                PEDERSEN_PREIMAGE_BITS
            );
        } else {
            println!("UC-SE for SHA256 preimage size {}\n", SHA256_PREIMAGE_BITS);
        };

        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
        // let srs = SRS::<Bls12>::new(830564,
        //     srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());

        type ChosenBackend = Permutation3;
        // let samples: usize = 10;
        let samples: usize = 5;

        let params = sapling_crypto::jubjub::JubjubBls12::new();

        if DO_PEDERSEN {
            // hash preimage (underlying witness)
            let preimage_bool = vec![true; PEDERSEN_PREIMAGE_BITS];
            let preimage_opt = preimage_bool
                .iter()
                .map(|x| Some(*x))
                .collect::<Vec<Option<bool>>>();
            let preimage_chunks_dusk = be_opt_vec_to_jubjub_scalar(&preimage_opt)
                .iter()
                .map(|scalar| GENERATOR_EXTENDED * scalar)
                .collect::<Vec<_>>();
            let preimage_chunk_pts = preimage_chunks_dusk
                .iter()
                .map(|chunk| dusk_to_sapling(*chunk))
                .collect::<Vec<_>>();

            // encrypt the underlying witness (part of UC witness)
            let mut rands = vec![];
            let mut rand_le_bits_vec = vec![];
            let mut rand_le_opt_vec = vec![];
            let mut cts_sapling = vec![];
            for i in 0..preimage_chunks_dusk.len() {
                // randomness
                let rand = JubJubScalar::random(&mut rand::thread_rng());
                rands.push(rand);

                let mut buf = [false; JubJubScalar::SIZE * 8];
                le_bytes_to_le_bits(rand.to_bytes().as_slice(), JubJubScalar::SIZE, &mut buf);
                rand_le_bits_vec.push(buf);

                let rand_le_opt = buf.iter().map(|x| Some(*x)).collect::<Vec<Option<bool>>>();
                rand_le_opt_vec.push(rand_le_opt);

                // compute ciphertext
                let c = srs.pk.encrypt(preimage_chunks_dusk[i], rand);
                let c_sapling = (dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta()));
                cts_sapling.push(c_sapling);
            }

            // inputs to UC circuit
            let circuit = PedersenHashPreimageUCCircuit {
                params: &params,
                pk: dusk_to_sapling(srs.pk.0),
                // x' = (x, c, cpk, cpk_o)
                digest: pedersen_hash::pedersen_hash(
                    pedersen_hash::Personalization::NoteCommitment,
                    preimage_bool,
                    &params,
                ),
                c: cts_sapling,
                cpk: dusk_to_sapling(*srs.cpk.as_ref()),
                cpk_o: dusk_to_sapling(dusk_jubjub::GENERATOR_EXTENDED),
                // w' = (w, omega, shift)
                preimage: preimage_opt,
                preimage_pts: preimage_chunk_pts,
                omegas: rand_le_opt_vec,
                shift: vec![Some(true); JubJubScalar::SIZE], // garbage shift (shift is unknown to honest prover)
            };

            println!("creating {} proofs", samples);
            let start = Instant::now();
            let proof =
                create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
                    .unwrap();
            for _ in 0..(samples - 1) {
                let _proof =
                    create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
                        .unwrap();
            }
            let proof_time = start.elapsed();
            println!("done in {:?}", proof_time);
            println!("average time per proof: {:?}", proof_time / samples as u32);

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

            let verify_time = {
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
                    assert!(verifier.check_all()); // TODO
                }
                let verify_time = start.elapsed();
                println!("done in {:?}", verify_time);
                println!("average time per proof: {:?}", verify_time / samples as u32);
                verify_time / samples as u32
            };

            {
                let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
                    AdaptorCircuit(circuit.clone()),
                    &srs,
                )
                .unwrap();
                println!("verifying {} proofs with advice", samples);
                let start = Instant::now();
                {
                    for (ref proof, ref advice) in &proofs {
                        verifier.add_underlying_proof_with_advice(proof, &[], advice);
                    }
                    verifier.add_aggregate(proofs.as_slice(), &aggregate);
                    assert!(verifier.check_all()); // TODO
                }
                let verify_advice_time = start.elapsed();
                println!("done in {:?}", verify_advice_time);
                println!(
                    "marginal cost of helped verifier: {:?}",
                    (verify_advice_time - verify_time) / (samples - 1) as u32
                );
            }
        } else {
            // DO SHA256
            // inputs to UC circuit
            let circuit =
                SHA256PreimageUCCircuit::<_, PrimeOrder>::new(&srs, &params, SHA256_PREIMAGE_BITS);

            println!("creating {} proofs", samples);
            let start = Instant::now();
            let proof =
                create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
                    .unwrap();
            for _ in 0..(samples - 1) {
                let _proof =
                    create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
                        .unwrap();
            }
            let proof_time = start.elapsed();
            println!("done in {:?}", proof_time);
            println!("average time per proof: {:?}", proof_time / samples as u32);

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

            let verify_time = {
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
                    // assert!(verifier.check_all()); // TODO
                    let _verif = verifier.check_all(); // TODO NG
                }
                let verify_time = start.elapsed();
                println!("done in {:?}", verify_time);
                println!("average time per proof: {:?}", verify_time / samples as u32);
                verify_time / samples as u32
            };

            {
                let mut verifier = MultiVerifier::<Bls12, _, ChosenBackend>::new(
                    AdaptorCircuit(circuit.clone()),
                    &srs,
                )
                .unwrap();
                println!("verifying {} proofs with advice", samples);
                let start = Instant::now();
                {
                    for (ref proof, ref advice) in &proofs {
                        verifier.add_underlying_proof_with_advice(proof, &[], advice);
                    }
                    verifier.add_aggregate(proofs.as_slice(), &aggregate);
                    // assert!(verifier.check_all()); // TODO
                    let _verif = verifier.check_all(); // TODO NG
                }
                let verify_advice_time = start.elapsed();
                println!("done in {:?}", verify_advice_time);
                println!(
                    "marginal cost of helped verifier: {:?}",
                    (verify_advice_time - verify_time) / (samples - 1) as u32
                );
            }
        }
    }
}
