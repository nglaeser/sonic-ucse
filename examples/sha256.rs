extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sonic_ucse;

use pairing::PrimeField;
use sapling_crypto::jubjub::PrimeOrder;
use sonic_ucse::circuits::adaptor::AdaptorCircuit;
use sonic_ucse::circuits::sha256::SHA256PreimageUCCircuit;
use sonic_ucse::protocol::*;
use sonic_ucse::srs::SRS;
use sonic_ucse::synthesis::*;
const SHA256_PREIMAGE_BITS: usize = 512;
// const SHA256_PREIMAGE_BITS: usize = 1024;

fn main() {
    use pairing::bls12_381::{Bls12, Fr};
    use std::time::Instant;

    {
        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
        // let srs = SRS::<Bls12>::new(830564,
        //     srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());

        type ChosenBackend = Permutation3;
        let samples: usize = 1;
        let iters: usize = 1;
        let params = sapling_crypto::jubjub::JubjubBls12::new();

        // inputs to UC circuit
        let circuit =
            SHA256PreimageUCCircuit::<_, PrimeOrder>::new(&srs, &params, SHA256_PREIMAGE_BITS);

        println!("creating {} proofs", iters);
        let start = Instant::now();
        let proof = create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
            .unwrap();
        for _ in 0..(iters - 1) {
            let _proof =
                create_proof::<Bls12, _, ChosenBackend>(&AdaptorCircuit(circuit.clone()), &srs)
                    .unwrap();
        }
        let proof_time = start.elapsed();
        println!("done in {:?}", proof_time);
        println!("average time per proof: {:?}", proof_time / iters as u32);

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
            println!("verifying {} proofs without advice", iters);
            let start = Instant::now();
            {
                for _ in 0..samples {
                    verifier.add_proof(&proof, &[], |_, _| None);
                }
                assert!(verifier.check_all()); // TODO
            }
            let verify_time = start.elapsed();
            println!("done in {:?}", verify_time);
            println!("average time per proof: {:?}", verify_time / iters as u32);
            verify_time / iters as u32
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
                (verify_advice_time - verify_time / iters as u32) / (samples - 1) as u32
            );
        }
    }
}
