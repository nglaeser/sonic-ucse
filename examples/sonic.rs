extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::PrimeField;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::{pedersen::PedersenHashPreimageCircuit, sha256::SHA256PreimageCircuit};
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;
const PEDERSEN_PREIMAGE_BITS: usize = 48;
// const PEDERSEN_PREIMAGE_BITS: usize = 384;
// const SHA256_PREIMAGE_BITS: usize = 512;
const SHA256_PREIMAGE_BITS: usize = 1024;
const DO_PEDERSEN: bool = true;
// const DO_PEDERSEN: bool = false;

fn main() {
    use pairing::bls12_381::{Bls12, Fr};
    use std::time::Instant;

    {
        if DO_PEDERSEN {
            println!(
                "Sonic for Pedersen preimage size {}\n",
                PEDERSEN_PREIMAGE_BITS
            );
        } else {
            println!("Sonic for SHA256 preimage size {}\n", SHA256_PREIMAGE_BITS);
        };

        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        // let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
        // let srs = SRS::<Bls12>::new(830564,
        //     srs_x, srs_alpha);
        // SHA256 with 1024 preimage: need larger d for larger circuits
        // not sure how large is needed, so use 4 * wires.len()
        // wires.len() = 337586
        let srs = SRS::<Bls12>::dummy(337586 * 4, srs_x, srs_alpha);
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

            let circuit = PedersenHashPreimageCircuit {
                preimage: preimage_opt,
                params: &params,
            };

            println!("creating {} proofs", samples);
            let start = Instant::now();
            let proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
                &AdaptorCircuit(circuit.clone()),
                &srs,
            )
            .unwrap();
            for _ in 0..(samples - 1) {
                let _proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
                    &AdaptorCircuit(circuit.clone()),
                    &srs,
                )
                .unwrap();
            }
            let proof_time = start.elapsed();
            println!("done in {:?}", proof_time);
            println!("average time per proof: {:?}", proof_time / samples as u32);

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
                        verifier.add_underlying_proof(&proof, &[], |_, _| None);
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
            // hash preimage (underlying witness)
            let preimage_bool = vec![true; SHA256_PREIMAGE_BITS];
            let preimage_opt = preimage_bool
                .iter()
                .map(|x| Some(*x))
                .collect::<Vec<Option<bool>>>();

            let circuit = SHA256PreimageCircuit {
                preimage: preimage_opt,
            };

            println!("creating {} proofs", samples);
            let start = Instant::now();
            let proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
                &AdaptorCircuit(circuit.clone()),
                &srs,
            )
            .unwrap();
            for _ in 0..(samples - 1) {
                let _proof = create_underlying_proof::<Bls12, _, ChosenBackend>(
                    &AdaptorCircuit(circuit.clone()),
                    &srs,
                )
                .unwrap();
            }
            let proof_time = start.elapsed();
            println!("done in {:?}", proof_time);
            println!("average time per proof: {:?}", proof_time / samples as u32);

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
                        verifier.add_underlying_proof(&proof, &[], |_, _| None);
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
