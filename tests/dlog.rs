#[cfg(test)]
mod tests {
    extern crate sonic_ucse;

    use dusk_plonk::jubjub::{JubJubScalar, GENERATOR_EXTENDED};
    use merlin::Transcript;
    use sonic_ucse::dlog::*;

    #[test]
    fn test_dlog_proof() {
        let x = JubJubScalar::random(&mut rand::thread_rng());
        let h = GENERATOR_EXTENDED * x;

        let mut transcript_prover = Transcript::new(&[]);
        let proof = prove_dlog(&mut transcript_prover, &h, &GENERATOR_EXTENDED, &x);

        let mut transcript_verifier = Transcript::new(&[]);
        assert!(vrfy_dlog(&mut transcript_verifier, &h, &GENERATOR_EXTENDED, proof).is_ok());
    }
}
