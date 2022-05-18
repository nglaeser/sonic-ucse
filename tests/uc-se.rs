#[cfg(test)]
mod tests {
    // to test correctness of new primitives implemented for UC-SE
    extern crate sonic_ucse;

    use sonic_ucse::protocol::*;
    use sonic_ucse::usig::*;
    use lamport_sigs;
    use pairing::bls12_381::Fr;
    use pairing::bls12_381::{G1Affine};
    use starsig::{Signature,VerificationKey};


    use curv::BigInt;
    use elgamal::{
        ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,ElGamalCiphertext,ElGamalError
    };
    #[test]
    fn test_kupke() {
        // setup
        let lambda: usize = 128;
        let pp: ElGamalPP = ElGamalPP::generate_safe(lambda);

        // keygen
        let keypair: ElGamalKeyPair = ElGamalKeyPair::generate(&pp);

        // enc
        let message = BigInt::from(42);
        let ctext: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair.pk).unwrap();

        // dec
        let ptext: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext, &keypair.sk);
        assert_eq!(message, ptext.unwrap());
    }

    use sonic_ucse::kupke::{KeyUpdate,SKeyUpdate};
    #[test]
    fn test_kupke_update() {
        let lambda: usize = 128;
        let pp: ElGamalPP = ElGamalPP::generate_safe(lambda);
        let mut keypair: ElGamalKeyPair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(42);

        let up_sk = keypair.pk.upk();
        let sk_up: ElGamalPrivateKey = keypair.sk.usk(&up_sk);
        let ctext_up: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        // TODO NG probably make upk just directly update the keypair
        let ptext_up: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext_up, &sk_up);

        assert_eq!(message, ptext_up.unwrap());
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
        let sigma: Signature = usig.sign(sk, message);

        // verify
        assert!(usig.verify(pk, message, sigma).is_ok());
    }

    #[test]
    fn test_usig_update() {
        let usig = Starsig;
        let (sk, pk): (SecretKey, VerificationKey) = usig.kgen();
        let message: &[u8] = b"dummy message";
        let sigma: Signature = usig.sign(sk, message);

        // update sk, pk
        let (pk_up, up_sk) = usig.upk(pk);
        let sk_up = usig.usk(sk, up_sk);
        assert_eq!(pk_up, VerificationKey::from_secret(&(sk_up.scalar)));

        // update sig
        let sigma_up = usig.usig(message, sigma, up_sk);

        // check that updated sig verifies under updated keypair
        assert!(usig.verify(pk_up, message, sigma_up).is_ok());
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
            Ok(sig) => pk_ot.verify_signature(&sig,proof_bytes),
            Err(_) => false
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
        let sigma: Signature = usig.sign(sk, message);

        // verify
        assert!(usig.verify(pk, message, sigma).is_ok());
        assert!(false);
    }
}