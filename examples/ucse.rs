extern crate sonic;

use sonic::protocol::*;
use sonic::kupke::{KeyUpdate,SKeyUpdate};
use lamport_sigs;
use ring::digest::{Algorithm, SHA256, SHA512};
use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,
    ElGamalPublicKey,ExponentElGamal,ElGamalCiphertext,ElGamalError
};

fn main() {
    use rand::rngs::OsRng;
    use ed25519_dalek::{Keypair,Signature,PublicKey,Signer,Verifier};
    use std::time::{Instant};

    println!("Testing signature schemes");
    println!("-------------------------");
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

    print!("Verify...");
    assert!(pk_l.verify(pk_ot_message,&sigma).is_ok());
    let sigma_ot_valid = match sigma_ot {
        Ok(sig) => pk_ot.verify_signature(&sig,proof_str),
        Err(error) => false
    };
    assert!(sigma_ot_valid);
    println!("done");

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
    let message = BigInt::from(13);
    let ctext: ElGamalCiphertext = ElGamal::encrypt(&message, &keypair_pke.pk).unwrap();
    println!("done");

    print!("Decrypt...");
    let ptext: Result<BigInt, ElGamalError> = ElGamal::decrypt(&ctext, &keypair_pke.sk);
    assert_eq!(message, ptext.unwrap());
    println!("done");

    print!("Update...");
    let (pk_up, up_sk) = keypair_pke.pk.upk();
    let sk_up: ElGamalPrivateKey = keypair_pke.sk.usk(up_sk);
    println!("done");
}