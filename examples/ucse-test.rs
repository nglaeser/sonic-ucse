extern crate sonic;

use sonic::protocol::*;
use sonic::kupke::{KeyUpdate,SKeyUpdate};
use sonic::usig::*;
use lamport_sigs;
use ring::digest::SHA256;
use curv::BigInt;
use elgamal::{
    ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,ElGamalCiphertext,ElGamalError
};
use pairing::bls12_381::Fr;
use pairing::bls12_381::{G1Affine};
use starsig::{Signature,VerificationKey};

fn main() {
    // to test correctness of new primitives implemented for UC-SE

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
    // updatable sig
    let usig = Starsig;
    let (sk_l, pk_l): (SecretKey, VerificationKey) = usig.kgen();

    // OT
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();
    println!("done");

    print!("- Sign...");
    // updatable sig
    let pk_ot_message: &[u8] = &pk_ot.to_bytes(); // TODO use proper message
    let pk_ot_message: &[u8] = b"This is a dummy message instead of pk_ot";
    let sigma: Signature = usig.sign(sk_l, pk_ot_message);

    // OT
    let proof_bytes: &[u8] = b"This is a dummy message instead of pi,x,c,pk_l,sigma";
    let sigma_ot = sk_ot.sign(proof_bytes);
    println!("done");

    print!("- Verify...");
    // updatable sig
    assert!(usig.verify(pk_l, pk_ot_message, sigma).is_ok());
    // OT
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_bytes),
        Err(_) => false
    };
    assert!(sigma_ot_valid);
    println!("done");

    print!("- Update...");
    // updatable sig only

    // update sk, pk
    let (pk_l_up, up_sk_l) = usig.upk(pk_l);
    let sk_l_up = usig.usk(sk_l, up_sk_l);
    assert_eq!(pk_l_up, VerificationKey::from_secret(&(sk_l_up.scalar)));

    // update sig
    let sigma_up = usig.usig(pk_ot_message, sigma, up_sk_l);

    // check that updated sig verifies under updated keypair
    assert!(usig.verify(pk_l_up, pk_ot_message, sigma_up).is_ok());
    println!("done");
}