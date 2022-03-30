extern crate sonic;

use sonic::protocol::*;
use sonic::kupke::{KeyUpdate,SKeyUpdate,Serialize};
use lamport_sigs;
use ring::digest::SHA256;
use curv::BigInt;
use curv::arithmetic::traits::Modulo;
use elgamal::{
    ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,ElGamalCiphertext,ElGamalError
};
// TODO NG fix differences between bls12_381 and pairing::bls12_381
// (upgrade paper code to use bls12_381 instead of the older pairing::bls12_381)
// use pairing::bls12_381::{Bls12,G1Affine,G2Affine,Fr,Scalar};
use pairing::bls12_381::Fr;
use bls12_381::{G1Affine,G2Affine,Scalar};
use pairing::{Engine,CurveAffine,Field};
use group::{UncompressedEncoding,ff::PrimeField};
use std::convert::TryInto;

fn main() {
    // to test correctness of new primitives implemented for UC-SE

    use rand::rngs::OsRng;
    use ed25519_dalek::{Keypair,Signature,PublicKey,Signer,Verifier};
    // use std::time::{Instant};

    println!("\nTesting key-updatable PKE");
    println!("-------------------------");
    print!("Setup...");
    let lambda: usize = 128;
    let pp: ElGamalPP = ElGamalPP::generate_safe(lambda);
    println!("done");

    print!("KeyGen...");
    let keypair_pke: ElGamalKeyPair = ElGamalKeyPair::generate(&pp);
    println!("done");

    print!("Encrypt...");
    let message_num: u64 = 13;
    let message = BigInt::from(message_num);
    let ctext: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair_pke.pk).unwrap();
    println!("done");

    print!("Decrypt...");
    let ptext: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext, &keypair_pke.sk);
    assert_eq!(message, ptext.unwrap());
    println!("done");

    print!("Update...");
    let (pk_up, up_sk) = keypair_pke.pk.upk();
    let sk_up: ElGamalPrivateKey = keypair_pke.sk.usk(&up_sk);
    let ctext_up: ElGamalCiphertext = ElGamal::encrypt(&message, &pk_up).unwrap();
    let ptext_up: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext_up, &sk_up);
    // TODO NG probably make upk just directly update the keypair
    assert_eq!(message, ptext_up.unwrap());
    println!("done");

    println!("\nTurning Sonic proof into u8");
    println!("-------------------------");
    let dummyproof = SonicProof::<G1Affine, Scalar>::dummy();
    let sonic_bytes: &[u8] = &dummyproof.to_bytes();

    println!("Testing signature schemes");
    println!("-------------------------");
    print!("KeyGen...");
    let mut csprng = OsRng{};
    let keypair_l: Keypair = Keypair::generate(&mut csprng);
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();
    println!("done");

    print!("Sign...");
    // \Sigma.Sign(sk_l, pk_ot)
    let pk_l: PublicKey = keypair_l.public;
    let pk_ot_message: &[u8] = &pk_ot.to_bytes();
    let sigma: Signature = keypair_l.sign(pk_ot_message);

    // \Sigma_OT.Sign(sk_ot, pi||x||c||pk_l||sigma)
    let x: &[u8] = b"fake statement";
    let mut c_bytes: Vec<u8> = ctext_up.to_bytes();
    let pk_l_bytes: [u8; 32] = pk_l.to_bytes();
    let sigma_bytes: [u8; 64] = sigma.to_bytes();

    let mut res: Vec<u8> = Vec::<u8>::with_capacity(448);
    res.extend_from_slice(sonic_bytes);
    res.extend_from_slice(x);
    res.append(&mut c_bytes);
    res.extend_from_slice(&pk_l_bytes);
    res.extend_from_slice(&sigma_bytes);

    let proof_bytes: &[u8] = res[0..res.len()].try_into().expect("slice with incorrect length");
    // let proof_bytes: &[u8] = sonic_bytes;
    // let proof_bytes: &[u8] = b"TODO NG This is a dummy message instead of pi,x,c,pk_l,sigma";

    let sigma_ot = sk_ot.sign(proof_bytes);
    println!("done");

    print!("Verify...");
    assert!(pk_l.verify(pk_ot_message,&sigma).is_ok());
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_bytes),
        Err(_) => false
    };
    assert!(sigma_ot_valid);
    println!("done");

}