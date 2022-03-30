use curv::BigInt;
use curv::arithmetic::traits::{Modulo,Samplable};
use curv::arithmetic::Converter;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,
    ElGamalPublicKey,ExponentElGamal,ElGamalCiphertext,
};

pub trait KeyUpdate {
    fn upk(&self) -> (ElGamalPublicKey, SKUpdate);
}
impl KeyUpdate for ElGamalPublicKey {
    fn upk(&self) -> (ElGamalPublicKey, SKUpdate) {
        let up_sk: SKUpdate = SKUpdate::random(&self.pp);
        let pk_up: ElGamalPublicKey = self.exp(&up_sk.up);
        (pk_up, up_sk)
    }
}

pub trait Serialize {
    fn to_bytes(&self) -> Vec<u8>;
}
impl Serialize for ElGamalCiphertext {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = self.c1.to_bytes();
        res.append(&mut self.c2.to_bytes());
        res
    }
}

pub trait SKeyUpdate {
    fn usk(&self, up_sk: &SKUpdate) -> Self;
}
impl SKeyUpdate for ElGamalPrivateKey {
    fn usk(&self, up_sk: &SKUpdate) -> Self {
        ElGamalPrivateKey { 
            pp: self.pp.clone(),
            x: BigInt::mod_mul(&self.x, &up_sk.up, &self.pp.q),
        }
    }
}

pub trait Exponentiation {
    fn exp(&self, exp: &BigInt) -> ElGamalPublicKey;
}
impl Exponentiation for ElGamalPublicKey {
    fn exp(&self, exp: &BigInt) -> ElGamalPublicKey {
        let h_up = BigInt::mod_pow(&self.h, &exp, &self.pp.p);
        ElGamalPublicKey { pp: self.pp.clone(), h: h_up }
    }
}

pub struct SKUpdate {
    pub up: BigInt,
}
impl SKUpdate {
    pub fn random(pp: &ElGamalPP) -> Self {
        let up: BigInt = BigInt::sample_below(&pp.q);
        SKUpdate { up }
    }
}

// pub fn setup(lambda: usize) -> ElGamalPP {
//     ElGamalPP::generate_safe(lambda)
// }

// pub fn kgen(pp: ElGamalPP) -> ElGamalKeyPair {
//     ElGamalKeyPair::generate(pp)
// }

// pub fn upk(pp: ElGamalPP, pk: ElGamalPublicKey) -> (ElGamalPublicKey, SKUpdate) {
//     let up_sk: SKUpdate = SKUpdate::random();
//     let pk_up: ElGamalPublicKey = pk.exp(up_sk);
//     (pk_up, up_sk)
// }

// // pub fn vpk()

// pub fn enc(pk: &ElGamalPublicKey, m: &BigInt) -> Result<ElGamalCiphertext, ElGamalError> {
//     ElGamal::encrypt(m, pk)
// }

// pub fn dec(sk: &ElGamalPrivateKey, c: &ElGamalCiphertext) -> Result<BigInt, ElGamalError> {
//     ElGamal::decrypt(c, sk)
// }