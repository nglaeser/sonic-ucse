#[cfg(test)]
mod tests {
    // to test correctness of new primitives implemented for UC-SE
    extern crate sonic_ucse;

    use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
    use dusk_pki::{PublicKey as VerificationKey, SecretKey};
    use jubjub_elgamal::{Cypher, PrivateKey, PublicKey};
    use jubjub_schnorr::Signature;
    use sonic_ucse::dlog::*;
    use sonic_ucse::protocol::*;
    use sonic_ucse::schnorrots::SchnorrOTS;
    use sonic_ucse::usig::*;

    #[test]
    fn test_kupke() {
        // keygen
        let sk = PrivateKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(sk);

        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());

        // enc
        let r = JubJubScalar::random(&mut rand::thread_rng());
        let ctext: Cypher = pk.encrypt(message, r);

        // dec
        let ptext: JubJubExtended = ctext.decrypt(sk);

        assert_eq!(message, ptext);
    }

    use sonic_ucse::kupke::{KeyUpdate, SKeyUpdate};
    #[test]
    fn test_kupke_update_proof() {
        // gen keypair
        let sk = PrivateKey::new(&mut rand::thread_rng());
        let mut pk = PublicKey::from(sk);

        // get update proof
        let mut csprng = rand::rngs::OsRng {};
        let pk_prev = pk.clone();
        let (up_sk, proof) = pk.upk(&mut csprng);

        // check that the update is correct
        assert_eq!(pk_prev.0 * up_sk.up, pk.0);

        // check that update proof verifies
        let mut transcript_verifier = DLogProtocol::<JubJub>::new(&[]);
        assert!(vrfy_dlog(&mut transcript_verifier, &pk.0, &pk_prev.0, proof).is_ok());
    }
    #[test]
    fn test_kupke_update() {
        let sk = PrivateKey::new(&mut rand::thread_rng());
        let mut pk = PublicKey::from(sk);
        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());

        let mut csprng = rand::rngs::OsRng {};
        let (up_sk, _proof) = pk.upk(&mut csprng); // updates pk as well
        let sk_up: PrivateKey = sk.usk(&up_sk);

        let r = JubJubScalar::random(&mut rand::thread_rng());
        let ctext_up: Cypher = pk.encrypt(message, r);
        let ptext_up: JubJubExtended = ctext_up.decrypt(sk_up);

        // check that keys are still a valid keypair after update
        // i.e., Dec(sk_up, Enc(pk_up, m)) == m
        assert_eq!(message, ptext_up);
    }

    #[test]
    fn test_proof_to_bytes() {
        use pairing::bls12_381::Bls12;
        let dummyproof = SonicProof::<Bls12>::dummy();
        let _: &[u8] = &dummyproof.to_bytes();
    }

    #[test]
    fn test_usig() {
        // keygen
        let usig = Schnorr;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();

        // sign
        let message: u64 = rand::random();
        let sigma: Signature = usig.sign(sk, message);

        // verify
        assert!(usig.verify(pk, message, sigma));
    }
    #[test]
    fn test_usig_update_proof() {
        // gen keypair
        let usig = Schnorr;
        let (_sk, pk): (SecretKey, VerificationKey) = usig.kgen();

        // get update proof
        let (pk_up, up_sk, proof) = usig.upk(pk);

        // check that the update is correct
        assert_eq!(pk_up, pk.add(up_sk * GENERATOR_EXTENDED));

        // check that update proof verifies
        let mut transcript_verifier = DLogProtocol::<JubJub>::new(&[]);
        assert!(vrfy_dlog(
            &mut transcript_verifier,
            &(pk_up.as_ref() - pk.as_ref()),
            &GENERATOR_EXTENDED,
            proof
        )
        .is_ok());
    }
    #[test]
    fn test_usig_update() {
        let usig = Schnorr;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();

        let message: u64 = rand::random();
        let sigma: Signature = usig.sign(sk, message);

        // update sk, pk
        let (pk_up, up_sk, _proof) = usig.upk(pk);
        let sk_up = usig.usk(sk, up_sk);
        assert_eq!(pk_up, VerificationKey::from(&sk_up));

        // update sig
        let sigma_up = usig.usig(message, sigma, up_sk);

        // check that updated sig verifies under updated keypair
        assert!(usig.verify(pk_up, message, sigma_up));
    }

    use ring::digest::SHA256;
    #[test]
    fn test_ot_sig() {
        // keygen
        let (sk_ot, pk_ot) = SchnorrOTS::kgen();

        // sign
        let proof_bytes: &[u8] = b"dummy message";
        let sigma_ot = SchnorrOTS::sign(sk_ot, &pk_ot, proof_bytes);

        // verify
        let sigma_ot_valid = SchnorrOTS::verify(&pk_ot, proof_bytes, &sigma_ot);
        assert!(sigma_ot_valid);
    }

    #[test]
    fn test_usig_pk_ot() {
        // keygen
        let usig = Schnorr;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();
        let (_, pk_ot) = SchnorrOTS::kgen();

        // sign
        // pk_ot is way more than 8 bytes so we hash it
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        pk_ot.hash(&mut hasher);
        let pk_ot_hash = hasher.finish(); // outputs a u64

        let sigma: Signature = usig.sign(sk, pk_ot_hash);

        // verify
        assert!(usig.verify(pk, pk_ot_hash, sigma));
    }
}
