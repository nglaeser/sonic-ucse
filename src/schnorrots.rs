use schnorrkel::Keypair;
pub use schnorrkel::{PublicKey, SecretKey, Signature};

pub struct SchnorrOTS;

// starsig digital signature algorithms
impl SchnorrOTS {
    pub fn kgen() -> (SecretKey, PublicKey) {
        let keypair = Keypair::generate();
        (keypair.secret.clone(), keypair.public)
    }

    pub fn sign(sk: SecretKey, pk: &PublicKey, m: &[u8]) -> Signature {
        sk.sign_simple(b"OTS", m, pk)
    }

    pub fn verify(pk: &PublicKey, m: &[u8], sigma: &Signature) -> bool {
        pk.verify_simple(b"OTS", m, sigma).is_ok()
    }
}
