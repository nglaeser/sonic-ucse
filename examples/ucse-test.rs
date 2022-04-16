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

fn main() {
    // to test correctness of new primitives implemented for UC-SE

    // use rand::rngs::OsRng;
    // use ed25519_dalek::{Keypair,Signature,PublicKey,Signer,Verifier};

    use schnorrkel::{Keypair,Signature,PublicKey,SecretKey,context};

    // use std::time::{Instant};

    println!("\nTesting key-updatable PKE");
    // println!("-------------------------");
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
    // let dummyproof = SonicProof::<G1Affine, Scalar>::dummy();
    let dummyproof = SonicProof::<G1Affine, Fr>::dummy();
    let _sonic_bytes: &[u8] = &dummyproof.to_bytes();
    println!("done\n");

    println!("Testing signature schemes");
    // println!("-------------------------");
    print!("- KeyGen...");
    // let mut csprng = OsRng{};
    // updataable
    // let keypair_l: Keypair = Keypair::generate(&mut csprng);
    let keypair_l: Keypair = Keypair::generate();

    // OT
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();
    println!("done");

    print!("- Sign...");
    // \Sigma.Sign(sk_l, pk_ot)
    let pk_l: PublicKey = keypair_l.public; // same for both EdDSA and Schnorr (change imports)
    let pk_ot_message: &[u8] = &pk_ot.to_bytes();
    // let sigma: Signature = keypair_l.sign(pk_ot_message);
    let context = context::signing_context(b"Sign one-time pk");
    let sigma: Signature = keypair_l.sign(context.bytes(pk_ot_message));

    // \Sigma_OT.Sign(sk_ot, pi||x||c||pk_l||sigma)
    let proof_bytes: &[u8] = b"This is a dummy message instead of pi,x,c,pk_l,sigma";
    let sigma_ot = sk_ot.sign(proof_bytes);
    println!("done");

    print!("- Verify...");
    // assert!(pk_l.verify(pk_ot_message,&sigma).is_ok());
    assert!(pk_l.verify(context.bytes(pk_ot_message),&sigma).is_ok());
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_bytes),
        Err(_) => false
    };
    assert!(sigma_ot_valid);
    println!("done");

    print!("- Update...");
    use std::ops::Mul;
    use curve25519_dalek::scalar::Scalar;

    // get current sk as scalar
    let keypair_l_bytes = keypair_l.secret.to_bytes();
    let mut sk_l_bytes: [u8; 32] = [0u8; 32];
    sk_l_bytes.copy_from_slice(&keypair_l_bytes[00..32]);
    let sk_l_scalar: Scalar = Scalar::from_canonical_bytes(sk_l_bytes).unwrap();
    // pick up_sk as scalar
    let up_sk_l: SecretKey = SecretKey::generate();
    let mut up_sk_l_bytes: [u8; 32] = [0u8; 32];
    up_sk_l_bytes.copy_from_slice(&up_sk_l.to_bytes()[00..32]);
    let up_sk_l_scalar: Scalar = Scalar::from_canonical_bytes(up_sk_l_bytes).unwrap();
    // sk_up := sk * up_sk
    let sk_l_up_scalar: Scalar = sk_l_scalar.mul(up_sk_l_scalar);
    let sk_l_up_bytes: [u8; 32] = sk_l_up_scalar.to_bytes();

    // get original nonce
    let mut sk_l_up_nonce: [u8; 32] = [0u8; 32];
    sk_l_up_nonce.copy_from_slice(&keypair_l_bytes[32..64]);

    // let sk_l_up = SecretKey{ key: sk_l_up_scalar, nonce: sk_l_up_nonce };
    let mut bytes: [u8; 64] = [0u8; 64];
    bytes[..32].copy_from_slice(&sk_l_up_bytes[..]);
    bytes[32..].copy_from_slice(&sk_l_up_nonce[..]);
    let sk_l_up: SecretKey = SecretKey::from_bytes(&bytes).unwrap();
    let keypair_l_up: Keypair = sk_l_up.to_keypair();

    // schnorrkel::Signature.R is "e" in the Schnorr Wikipekdia algo
    // schnorrkel::Signature.s is (argh!!!!) a hash output again!
    // for more see schnorrkel/sign.rs:36-58

    // TODO update sigma_up manually using sk_up and then check that the new keypair verifies the updated sig
    // let sigma_up: Signature = ;
    let sigma_up: Signature = keypair_l_up.sign(context.bytes(pk_ot_message));

    let pk_l_up: PublicKey = keypair_l_up.public;
    assert!(pk_l_up.verify(context.bytes(pk_ot_message), &sigma_up).is_ok());
    println!("done");
}