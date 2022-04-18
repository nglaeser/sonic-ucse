extern crate sonic;

use sonic::protocol::*;
use sonic::kupke::{KeyUpdate,SKeyUpdate};
use lamport_sigs;
use ring::digest::SHA256;
use curv::BigInt;
use elgamal::{
    ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,ElGamalCiphertext,ElGamalError
};
use pairing::bls12_381::Fr;
use pairing::bls12_381::{G1Affine};
use starsig::{Signature,VerificationKey};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

fn main() {
    // to test correctness of new primitives implemented for UC-SE

    use rand::rngs::OsRng;
    // use std::time::{Instant};

    println!("\nTesting key-updatable PKE");
    print!("- Setup...");
    let lambda: usize = 128;
    let pp: ElGamalPP = ElGamalPP::generate_safe(lambda);
    println!("done");

    print!("- KeyGen...");
    let mut keypair_pke: ElGamalKeyPair = ElGamalKeyPair::generate(&pp);
    println!("done");

    print!("- Encrypt...");
    let message_num: u64 = 13;
    let message = BigInt::from(message_num);
    let ctext: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair_pke.pk).unwrap();
    println!("done");

    print!("- Decrypt...");
    let ptext: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext, &keypair_pke.sk);
    assert_eq!(message, ptext.unwrap());
    println!("done");

    print!("- Update...");
    let up_sk = keypair_pke.pk.upk();
    let sk_up: ElGamalPrivateKey = keypair_pke.sk.usk(&up_sk);
    let ctext_up: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair_pke.pk).unwrap();
    // TODO NG probably make upk just directly update the keypair
    let ptext_up: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext_up, &sk_up);
    assert_eq!(message, ptext_up.unwrap());
    println!("done");

    print!("\nTesting turning Sonic proof into bytes...");
    let dummyproof = SonicProof::<G1Affine, Fr>::dummy();
    let _sonic_bytes: &[u8] = &dummyproof.to_bytes();
    println!("done\n");

    println!("Testing signature schemes");
    print!("- KeyGen...");
    let mut csprng = OsRng{};
    // updatable sig
    let sk_l: Scalar = Scalar::random(&mut csprng);
    let pk_l: VerificationKey = VerificationKey::from_secret(&sk_l);

    // OT
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();
    println!("done");

    print!("- Sign...");
    // updatable sig
    let pk_ot_message: &[u8] = &pk_ot.to_bytes(); // TODO use proper message
    let pk_ot_message: &[u8] = b"This is a dummy message instead of pk_ot";
    let sigma: Signature = Signature::sign(&mut Transcript::new(pk_ot_message), sk_l);

    // OT
    let proof_bytes: &[u8] = b"This is a dummy message instead of pi,x,c,pk_l,sigma";
    let sigma_ot = sk_ot.sign(proof_bytes);
    println!("done");

    print!("- Verify...");
    // updatable sig
    assert!(sigma
        .verify(&mut Transcript::new(pk_ot_message), pk_l)
        .is_ok());
    // OT
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_bytes),
        Err(_) => false
    };
    assert!(sigma_ot_valid);
    println!("done");

    print!("- Update...");
    // updatable sig only
    use std::ops::Add;

    // update sk
    // sk_up := sk `op` up_sk
    // in the case of starsig, `op` is +
    let sk_l_scalar: Scalar = sk_l.clone();
    let up_sk_l: Scalar = Scalar::random(&mut csprng);
    let sk_l_up: Scalar = sk_l_scalar.add(up_sk_l);

    // update sig
    // sigma_up := sigma + c * up_sk 
    //           = (r + c * sk) + c * up_sk = r + c * sk_up
    use starsig::TranscriptProtocol;
    let mut transcript = Transcript::new(pk_ot_message);
    let c = {
        transcript.starsig_domain_sep();
        transcript.append_point(b"R", &sigma.R);
        transcript.challenge_scalar(b"c")
    };
    let s_new = sigma.s + c * up_sk_l;
    let sigma_up = Signature { s: s_new, R: sigma.R };

    // update pk
    // pk_up := pk mu(`op`) up_sk
    // in the case of starsig, mu(`op`) b is + b * RISTRETTO_BASEPOINT_POINT
    // pk_up  = (sk * RISTRETTO_BASEPOINT_POINT) + (up_sk * RISTRETTO_BASEPOINT_POINT)
    //        = (sk + up_sk) * RISTRETTO_BASEPOINT_POINT
    //        = sk_up * RISTRETTO_BASEPOINT_POINT
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let pk_l_compressed: CompressedRistretto = pk_l.into();
    let pk_l_point: RistrettoPoint = pk_l_compressed.decompress().unwrap();
    let pk_l_up: VerificationKey = VerificationKey::from(pk_l_point + (up_sk_l*RISTRETTO_BASEPOINT_POINT));
    assert_eq!(pk_l_up, VerificationKey::from_secret(&(sk_l_up)));

    // check that updated sig verifies under updated keypair
    // verify(pk_up, m, sigma_up)
    assert!(sigma_up
        .verify(&mut Transcript::new(pk_ot_message), pk_l_up)
        .is_ok());
    println!("done");
}