use curv::arithmetic::traits::{Modulo, Samplable};
use curv::arithmetic::Converter;
use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPP, ElGamalPrivateKey, ElGamalPublicKey};
// use elgamal::{ElGamal,ElGamalKeyPair};

pub trait KeyUpdate {
    fn upk(&mut self) -> SKUpdate;
}
impl KeyUpdate for ElGamalPublicKey {
    fn upk(&mut self) -> SKUpdate {
        let up_sk: SKUpdate = SKUpdate::random(&self.pp);
        self.exp(&up_sk.up);
        up_sk // TODO add proof
    }
}

pub trait Serialize {
    fn to_bytes(&self) -> Vec<u8>;
}
impl Serialize for ElGamalCiphertext {
    fn to_bytes(&self) -> Vec<u8> {
        [self.c1.to_bytes(), self.c2.to_bytes()].concat()
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
    fn exp(&mut self, exp: &BigInt) -> ();
}
impl Exponentiation for ElGamalPublicKey {
    fn exp(&mut self, exp: &BigInt) -> () {
        let h_up = BigInt::mod_pow(&self.h, &exp, &self.pp.p);
        // ElGamalPublicKey { pp: self.pp.clone(), h: h_up }
        self.h = h_up;
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
