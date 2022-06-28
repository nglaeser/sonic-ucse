#[cfg(test)]
mod tests {
    extern crate sonic_ucse;

    use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
    use sonic_ucse::dlog::*;
    #[test]
    fn test_dlog_proof_jubjub() {
        let x = JubJubScalar::random(&mut rand::thread_rng());
        let h = GENERATOR_EXTENDED * x;

        let mut transcript_prover = DLogProtocol::<JubJub>::new(&[]);
        let proof = prove_dlog(&mut transcript_prover, &h, &GENERATOR_EXTENDED, &x);

        let mut transcript_verifier = DLogProtocol::<JubJub>::new(&[]);
        assert!(vrfy_dlog(&mut transcript_verifier, &h, &GENERATOR_EXTENDED, proof).is_ok());
    }
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    #[test]
    fn test_dlog_proof_ristretto() {
        let x = Ristretto::random_scalar(&mut rand::thread_rng());
        let h = RISTRETTO_BASEPOINT_POINT * x;

        let mut transcript_prover = DLogProtocol::<Ristretto>::new(&[]);
        let proof = prove_dlog(&mut transcript_prover, &h, &RISTRETTO_BASEPOINT_POINT, &x);

        let mut transcript_verifier = DLogProtocol::<Ristretto>::new(&[]);
        assert!(vrfy_dlog(
            &mut transcript_verifier,
            &h,
            &RISTRETTO_BASEPOINT_POINT,
            proof
        )
        .is_ok());
    }
}
