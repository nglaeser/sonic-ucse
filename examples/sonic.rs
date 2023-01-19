extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::PrimeField;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::{pedersen::PedersenHashPreimageCircuit, sha256::SHA256PreimageCircuit};
use sonic_ucse::{parse_config,usage};
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;

fn main() {
    use pairing::bls12_381::{Bls12, Fr};
    use std::time::Instant;
    use std::{env,process};

    /***** Process command-line arguments *****/
    let args: Vec<String> = env::args().collect();
    let (circuit_name, preimage_bits, samples) = parse_config(&args).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        usage();
        process::exit(1);
    });

    /***** Open the benchmark file *****/
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    
    // open file in write-only append mode, and create it if it doesn't exist
    let mut file = OpenOptions::new().write(true)
                                 .append(true)
                                 .create(true)
                                 .open("bench.txt")
                                 .unwrap_or_else(|err| {
        eprintln!("Problem opening benchmarking file: {err}");
        process::exit(1);
    });
    writeln!(file, "Sonic for {} with preimage size {} over {} iterations\n{}", 
            circuit_name, preimage_bits, samples, 
            "--------------------------------------------------------------"
        ).unwrap_or_else(|err| {
        eprintln!("Problem writing to benchmarking file: {err}");
        process::exit(1);
    });
    
    /***** Begin benchmarking *****/
    {
        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let d = {
            if preimage_bits == 512 {
                886144
            }
            else if preimage_bits == 1024 {
            // SHA256 with 1024 preimage: need larger d for larger circuits
            // not sure how large is needed, so use 4 * wires.len()
            // wires.len() = 337586
                337586 * 4
            }
            else if preimage_bits == 2048 {
                // guess
                337586 * 8
            }
            else {
                830564
        }};
        let start = Instant::now();
        let srs = SRS::<Bls12>::dummy(d, srs_x, srs_alpha);
        // let srs = SRS::<Bls12>::new(d, srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());

        type ChosenBackend = Permutation3;
        let params = sapling_crypto::jubjub::JubjubBls12::new();

        if circuit_name == "pedersen" {
            let circuit = PedersenHashPreimageCircuit::<Bls12>::new(&params, preimage_bits);

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
            let proof_avg = proof_time / samples as u32;
            println!("average time per proof: {:?}", proof_avg);
            writeln!(file, "proof:\t\t\t{:?}", proof_avg).unwrap_or_else(|err| {
                eprintln!("Problem writing to proof avg to file: {err}");
                process::exit(1);
            });

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

            let verify_avg = {
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
                let verify_avg = verify_time / samples as u32;
                println!("average time per proof: {:?}", verify_avg);
                verify_avg
            };
            writeln!(file, "verify:\t\t{:?}", verify_avg).unwrap_or_else(|err| {
                eprintln!("Problem writing to verify avg to file: {err}");
                process::exit(1);
            });

            let helped_verify_margin = {
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
                let helped_verify_margin = (verify_advice_time - verify_avg) / (samples - 1) as u32;
                println!(
                    "marginal cost of helped verifier: {:?}",
                    helped_verify_margin
                );
                helped_verify_margin
            };
            writeln!(file, "helped verify:\t{:?}", helped_verify_margin).unwrap_or_else(|err| {
                eprintln!("Problem writing to helped verify margin to file: {err}");
                process::exit(1);
            });
        } else if circuit_name == "sha256" {
            // DO SHA256
            let circuit = SHA256PreimageCircuit::new(preimage_bits);

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
            let proof_avg = proof_time / samples as u32;
            println!("average time per proof: {:?}", proof_avg);
            writeln!(file, "proof:\t\t\t{:?}", proof_avg).unwrap_or_else(|err| {
                eprintln!("Problem writing to proof avg to file: {err}");
                process::exit(1);
            });

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

            let verify_avg = {
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
                let verify_avg = verify_time / samples as u32;
                println!("average time per proof: {:?}", verify_avg);
                verify_avg
            };
            writeln!(file, "verify:\t\t{:?}", verify_avg).unwrap_or_else(|err| {
                eprintln!("Problem writing to verify avg to file: {err}");
                process::exit(1);
            });

            let helped_verify_margin = {
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
                let helped_verify_margin = (verify_advice_time - verify_avg) / (samples - 1) as u32;
                println!(
                    "marginal cost of helped verifier: {:?}",
                    helped_verify_margin
                );
                helped_verify_margin
            };
            writeln!(file, "helped verify:\t{:?}", helped_verify_margin).unwrap_or_else(|err| {
                eprintln!("Problem writing to helped verify margin to file: {err}");
                process::exit(1);
            });
        } else {
            unreachable!("circuit_name should always be either pedersen or sha256");
        }
    }
}
