use crate::dlog::*;
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use jubjub_elgamal::{PrivateKey, PublicKey};
use rand_core::{CryptoRng, RngCore};
use std::ops::Mul;

pub trait KeyUpdate<T, R> {
    fn upk(&mut self, rng: R) -> (SKUpdate<T>, DLogProof<JubJub>);
}
impl<R> KeyUpdate<JubJubScalar, R> for PublicKey
where
    R: RngCore + CryptoRng,
{
    fn upk(&mut self, rng: R) -> (SKUpdate<JubJubScalar>, DLogProof<JubJub>) {
        // because sk_up = sk * up_sk
        //     and pk = GENERATOR_EXTENDED * sk
        // we have
        // pk_up := GENERATOR_EXTENDED * sk_up
        //        = GENERATOR_EXTENDED * (sk * up_sk)
        //        = pk * up_sk
        let up_sk: SKUpdate<JubJubScalar> = SKUpdate::<JubJubScalar>::random(rng);
        let pk_prev = self.clone();
        // *self += GENERATOR_EXTENDED * &up_sk;
        *self *= up_sk.up;

        let mut transcript = DLogProtocol::new(&[]);
        let proof = prove_dlog(&mut transcript, &self.0, &pk_prev.0, &up_sk.up);

        (up_sk, proof) // TODO should the proof be verified anywhere?
    }
}

pub trait SKeyUpdate<T> {
    fn usk(&self, up_sk: &SKUpdate<T>) -> Self;
}
impl SKeyUpdate<JubJubScalar> for PrivateKey {
    fn usk(&self, up_sk: &SKUpdate<JubJubScalar>) -> Self {
        // sk_up := sk * up_sk
        *self * up_sk.up
    }
}

pub struct SKUpdate<T> {
    pub up: T,
}
impl SKUpdate<JubJubScalar> {
    pub fn random<R>(mut rng: R) -> Self
    where
        R: RngCore + CryptoRng,
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
