use crate::BigIntable;
use curv::elliptic::{curves, curves::ECScalar, curves::Ristretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use starsig::TranscriptProtocol;
use std::ops::{Add, Mul};

// collection of algorithms that make up a digital signature
pub struct Starsig;
pub trait Sig<SK, VK, S, E> {
    fn kgen(&self) -> (SK, VK);
    fn sign(&self, _: SK, _: &[u8]) -> S;
    fn verify(&self, _: VK, _: &[u8], _: S) -> Result<(), E>;
}
use starsig::{Signature, StarsigError, VerificationKey};

// starsig secret key
#[derive(Copy, Clone)]
pub struct SecretKey {
    // from group of prime order l = 2^252 + 27742317777372353535851937790883648493
    // (ristretto 255)
    pub scalar: Scalar,
}
impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = Scalar::random(rng);
        SecretKey { scalar }
    }
}
impl Add<Update<Scalar>> for SecretKey {
    type Output = SecretKey;
    fn add(self, up: Update<Scalar>) -> SecretKey {
        SecretKey {
            scalar: self.scalar + up.scalar,
        }
    }
}

// updatability of keys
pub trait Updatable<T>
where
    T: Clone + Copy,
{
    fn update(self, _: Update<T>) -> Self;
}
// how to update starsig secret and public keys
// TODO these ops will not work for dlog proof of update
impl Updatable<Scalar> for SecretKey {
    fn update(self, up: Update<Scalar>) -> Self {
        // for starsig sk, `op` is +
        // sk_up := sk + up_sk
        self + up
    }
}
impl Updatable<Scalar> for VerificationKey {
    fn update(self, up: Update<Scalar>) -> Self {
        // for starsig, `mu(op) up` is `+ up * RISTRETTO_BASEPOINT_POINT`
        // pk_up := (sk * RISTRETTO_BASEPOINT_POINT) + (up_sk * RISTRETTO_BASEPOINT_POINT)
        // correctness:
        // pk_up  = (sk + up_sk) * RISTRETTO_BASEPOINT_POINT
        //        = sk_up * RISTRETTO_BASEPOINT_POINT
        let pk_compressed: CompressedRistretto = self.into();
        let pk_point: RistrettoPoint = pk_compressed.decompress().unwrap();
        let pk_up = VerificationKey::from(pk_point + (up * RISTRETTO_BASEPOINT_POINT));
        pk_up // TODO add proof
    }
}

// starsig digital signature algorithms
impl Sig<SecretKey, VerificationKey, Signature, StarsigError> for Starsig {
    fn kgen(&self) -> (SecretKey, VerificationKey) {
        let mut csprng = OsRng {};
        let sk = SecretKey::random(&mut csprng);
        let pk = VerificationKey::from_secret(&sk.scalar);
        (sk, pk)
    }
    fn sign(&self, sk: SecretKey, m: &[u8]) -> Signature {
        Signature::sign_message(b"signature", m, sk.scalar)
    }
    fn verify(&self, vk: VerificationKey, m: &[u8], sigma: Signature) -> Result<(), StarsigError> {
        sigma.verify_message(b"signature", m, vk)
    }
}

// updating information
#[derive(Copy, Clone)]
pub struct Update<T>
where
    T: Copy + Clone,
{
    pub scalar: T,
}
impl Mul<RistrettoPoint> for Update<Scalar> {
    type Output = RistrettoPoint;
    fn mul(self, point: RistrettoPoint) -> RistrettoPoint {
        self.scalar * point
    }
}
impl Mul<Update<Scalar>> for Scalar {
    type Output = Scalar;
    fn mul(self, up: Update<Scalar>) -> Scalar {
        self * up.scalar
    }
}
impl BigIntable for Update<Scalar> {
    fn to_big_int(&self) -> curv::BigInt {
        let rs: curves::Scalar<Ristretto> =
            curves::Scalar::from_raw(ECScalar::from_underlying(self.scalar));
        rs.to_bigint()
    }
}

// additional algorithms for *updatable* signature
pub trait UpdatableSig<SK, VK, S, T: Copy + Clone> {
    // sk_up := sk `op` up_sk
    // pk_up := pk mu(`op`) up_sk
    fn upk(&self, _: VK) -> (VK, Update<T>);
    fn usk(&self, _: SK, _: Update<T>) -> SK;
    fn usig(&self, _: &[u8], _: S, _: Update<T>) -> S;
}
impl UpdatableSig<SecretKey, VerificationKey, Signature, Scalar> for Starsig {
    fn upk(&self, pk: VerificationKey) -> (VerificationKey, Update<Scalar>) {
        let mut csprng = OsRng {};
        let r = Scalar::random(&mut csprng);
        let up = Update { scalar: r };

        let pk_up: VerificationKey = pk.update(up);

        (pk_up, up)
    }
    fn usk(&self, sk: SecretKey, up: Update<Scalar>) -> SecretKey {
        sk.update(up)
    }
    fn usig(&self, m: &[u8], sigma: Signature, up: Update<Scalar>) -> Signature {
        // sigma_up := sigma + c * up_sk
        //           = (r + c * sk) + c * up_sk = r + c * sk_up
        let mut transcript = Transcript::new(b"Starsig.sign_message");
        transcript.append_message(b"signature", m);
        let c = {
            transcript.starsig_domain_sep();
            transcript.append_point(b"R", &sigma.R);
            transcript.challenge_scalar(b"c")
        };
        sigma + c * up
    }
}
