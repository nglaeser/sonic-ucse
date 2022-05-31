use dusk_plonk::jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use jubjub_elgamal::{PrivateKey, PublicKey};
use rand::{CryptoRng, Rng};
use std::ops::Mul;

pub trait KeyUpdate<T, R> {
    fn upk(&mut self, rng: R) -> SKUpdate<T>;
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
        up_sk // TODO add proof
    }
}

pub trait SKeyUpdate<T> {
    fn usk(&self, up_sk: &SKUpdate<T>) -> Self;
}
impl SKeyUpdate<JubJubScalar> for PrivateKey {
    fn usk(&self, up_sk: &SKUpdate<JubJubScalar>) -> Self {
        // sk_up := sk + up_sk
        *self + up_sk.up
    }
}

pub struct SKUpdate<T> {
    pub up: T,
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
