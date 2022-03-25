extern crate sonic;
extern crate ed25519_dalek;

use sonic::protocol::*;
use lamport_sigs;
use ring::digest::{Algorithm, SHA256, SHA512};

fn main() {
    use rand::rngs::OsRng;
    use ed25519_dalek::{Keypair,Signature,PublicKey,Signer,Verifier};
    use std::time::{Instant};

    println!("Testing signature schemes");
    println!("-------------------------");
    // keygen
    print!("KeyGen...");
    let mut csprng = OsRng{};
    let keypair_l: Keypair = Keypair::generate(&mut csprng);
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();
    println!("done");

    print!("Sign...");
    let pk_l: PublicKey = keypair_l.public;
    // \Sigma.Sign(sk_l, pk_ot)
    let pk_ot_message: &[u8] = &pk_ot.to_bytes();
    let sigma: Signature = keypair_l.sign(pk_ot_message);
    // \Sigma_OT.Sign(sk_ot, pi||x||c||pk_l||sigma)
    let proof_str: &[u8] = b"TODO This is a dummy message instead of pi,x,c,pk_l,sigma";
    let sigma_ot = sk_ot.sign(proof_str);
    println!("done");

    println!("Verify...");
    println!("- EdDSA: {}", pk_l.verify(pk_ot_message,&sigma).is_ok());
    // if !&self.sigma_ot[i].is_ok_and(|&x| pk.verify_signature(x,message)) { return false }
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_str),
        Err(error) => false
    };
    println!("- OT: {}", sigma_ot_valid);
    println!("done");
}