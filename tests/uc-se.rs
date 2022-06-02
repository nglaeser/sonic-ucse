#[cfg(test)]
mod tests {
    // to test correctness of new primitives implemented for UC-SE
    extern crate sonic_ucse;

    use lamport_sigs;
    use merlin::Transcript;
    use pairing::bls12_381::Fr;
    use pairing::bls12_381::G1Affine;
    use sonic_ucse::protocol::*;
    use sonic_ucse::usig::*;
    use starsig::{Signature, VerificationKey};

    use dusk_plonk::jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
    use jubjub_elgamal::{Cypher, PrivateKey, PublicKey};
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
    fn test_kupke_update() {
        // check that keys are still a valid keypair after update
        // i.e., Dec(sk_up, Enc(pk_up, m)) == m
        let sk = PrivateKey::new(&mut rand::thread_rng());
        let mut pk = PublicKey::from(sk);
        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());

        let mut csprng = rand::rngs::OsRng {};
        let up_sk = pk.upk(&mut csprng); // updates pk as well
        let sk_up: PrivateKey = sk.usk(&up_sk);

        let r = JubJubScalar::random(&mut rand::thread_rng());
        let ctext_up: Cypher = pk.encrypt(message, r);
        let ptext_up: JubJubExtended = ctext_up.decrypt(sk_up);

        assert_eq!(message, ptext_up);
    }

    #[test]
    fn test_proof_to_bytes() {
        let dummyproof = SonicProof::<G1Affine, Fr>::dummy();
        let _: &[u8] = &dummyproof.to_bytes();
    }

    #[test]
    fn test_usig() {
        // keygen
        let usig = Starsig;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();

        // sign
        let message: &[u8] = b"dummy message";
        let sigma: Signature = usig.sign(sk, &mut Transcript::new(message));

        // verify
        assert!(usig
            .verify(pk, &mut Transcript::new(message), sigma)
            .is_ok());
    }

    #[test]
    fn test_usig_update() {
        let usig = Starsig;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();
        let message: &[u8] = b"dummy message";
        let sigma: Signature = usig.sign(sk, &mut Transcript::new(message));

        // update sk, pk
        let (pk_up, up_sk) = usig.upk(pk);
        let sk_up = usig.usk(sk, up_sk);
        assert_eq!(pk_up, VerificationKey::from_secret(&(sk_up.scalar)));

        // update sig
        let sigma_up = usig.usig(&mut Transcript::new(message), sigma, up_sk);

        // check that updated sig verifies under updated keypair
        assert!(usig
            .verify(pk_up, &mut Transcript::new(message), sigma_up)
            .is_ok());
    }

    use ring::digest::SHA256;
    #[test]
    fn test_ot_sig() {
        // keygen
        let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
        let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();

        // sign
        let proof_bytes: &[u8] = b"dummy message";
        let sigma_ot = sk_ot.sign(proof_bytes);

        // verify
        let sigma_ot_valid = match sigma_ot {
            Ok(sig) => pk_ot.verify_signature(&sig, proof_bytes),
            Err(_) => false,
        };
        assert!(sigma_ot_valid);
    }

    #[test]
    fn test_usig_pk_ot() {
        // keygen
        let usig = Starsig;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();
        let sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
        let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();

        // sign
        let _message: &[u8] = &pk_ot.to_bytes();
        let message: &[u8] = b"TODO NG should be pk_ot";
        let sigma: Signature = usig.sign(sk, &mut Transcript::new(message));

        // verify
        assert!(usig
            .verify(pk, &mut Transcript::new(message), sigma)
            .is_ok());
        assert!(false); // reminder to fix todo above
    }
}
