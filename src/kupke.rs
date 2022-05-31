use curv::arithmetic::traits::{Modulo, Samplable};
use curv::arithmetic::Converter;
use curv::BigInt;
use elgamal::{ElGamalCiphertext, ElGamalPP, ElGamalPrivateKey, ElGamalPublicKey};
// use elgamal::{ElGamal,ElGamalKeyPair};
use dusk_plonk::jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use jubjub_elgamal::{PrivateKey, PublicKey};
use rand::{CryptoRng, Rng};
use std::ops::Mul;

pub trait KeyUpdate<T, R> {
    fn upk(&mut self, rng: R) -> SKUpdate<T>;
}
impl<R> KeyUpdate<BigInt, R> for ElGamalPublicKey {
    fn upk(&mut self, _: R) -> SKUpdate<BigInt> {
        let up_sk: SKUpdate<BigInt> = SKUpdate::<BigInt>::random(&self.pp);
        self.exp(&up_sk.up);
        up_sk // TODO add proof
    }
}
impl<R> KeyUpdate<JubJubScalar, R> for PublicKey
where
    R: Rng + CryptoRng,
{
    fn upk(&mut self, rng: R) -> SKUpdate<JubJubScalar> {
        // because sk_up = sk + up_sk
        //     and pk = sk * GENERATOR_EXTENDED
        // we have
        // pk_up := sk_up * GENERATOR_EXTENDED
        //        = (sk + up_sk) * GENERATOR_EXTENDED
        //        = pk + (up_sk * GENERATOR_EXTENDED)
        let up_sk: SKUpdate<JubJubScalar> = SKUpdate::<JubJubScalar>::random(rng);
        *self += GENERATOR_EXTENDED * &up_sk;
        // self.exp(&up_sk.up);
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

pub trait SKeyUpdate<T> {
    fn usk(&self, up_sk: &SKUpdate<T>) -> Self;
}
impl SKeyUpdate<BigInt> for ElGamalPrivateKey {
    fn usk(&self, up_sk: &SKUpdate<BigInt>) -> Self {
        ElGamalPrivateKey {
            pp: self.pp.clone(),
            x: BigInt::mod_mul(&self.x, &up_sk.up, &self.pp.q),
        }
    }
}
impl SKeyUpdate<JubJubScalar> for PrivateKey {
    fn usk(&self, up_sk: &SKUpdate<JubJubScalar>) -> Self {
        // sk_up := sk + up_sk
        *self + up_sk.up
    }
}

pub trait Exponentiation<T> {
    fn exp(&mut self, exp: &T) -> ();
}
impl Exponentiation<BigInt> for ElGamalPublicKey {
    fn exp(&mut self, exp: &BigInt) -> () {
        let h_up = BigInt::mod_pow(&self.h, &exp, &self.pp.p);
        // ElGamalPublicKey { pp: self.pp.clone(), h: h_up }
        self.h = h_up;
    }
}
impl Exponentiation<JubJubScalar> for PublicKey {
    fn exp(&mut self, exp: &JubJubScalar) -> () {
        *self *= *exp;
    }
}

pub struct SKUpdate<T> {
    pub up: T,
}
impl SKUpdate<BigInt> {
    pub fn random(pp: &ElGamalPP) -> Self {
        let up: BigInt = BigInt::sample_below(&pp.q);
        SKUpdate { up }
    }
}
impl SKUpdate<JubJubScalar> {
    pub fn random<R>(mut rng: R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let up: JubJubScalar = JubJubScalar::random(&mut rng);
        SKUpdate { up }
    }
}
impl Mul<&SKUpdate<JubJubScalar>> for JubJubExtended {
    type Output = JubJubExtended;

    fn mul(self, rhs: &SKUpdate<JubJubScalar>) -> JubJubExtended {
        self * rhs.up
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
