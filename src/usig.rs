use rand::rngs::OsRng;
use rand::{RngCore, CryptoRng};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use starsig::TranscriptProtocol;
use merlin::Transcript;
use std::ops::Add;

pub struct Starsig;
pub trait Sig<SK, VK, S, E> {
    fn kgen(&self) -> (SK, VK);
    fn sign(&self, _: SK, _: &'static [u8]) -> S;
    fn verify(&self, _: VK, _: &'static [u8], _: S) -> Result<(), E>;
}
use starsig::{Signature,VerificationKey,StarsigError};

#[derive(Copy,Clone)]
pub struct SecretKey {
    pub scalar: Scalar,
}
impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = Scalar::random(rng);
        SecretKey{ scalar }
    }
}
impl Sig<SecretKey, VerificationKey, Signature, StarsigError> for Starsig {
    fn kgen(&self) -> (SecretKey, VerificationKey) {
        let mut csprng = OsRng{};
        let sk = SecretKey::random(&mut csprng);
        let pk = VerificationKey::from_secret(&sk.scalar);
        (sk, pk)
    }
    fn sign(&self, sk: SecretKey, m: &'static [u8]) -> Signature {
        Signature::sign(&mut Transcript::new(m), sk.scalar)
    }
    fn verify(&self, vk: VerificationKey, m: &'static [u8], sigma: Signature) -> Result<(), StarsigError> {
        sigma.verify(&mut Transcript::new(m), vk)
    }
}

// TODO impl Mul
#[derive(Copy,Clone)]
pub struct Update<T> where T: Copy + Clone {
    pub up: T,
}
pub trait Updatable<SK, VK, S, T: Copy + Clone> {
    // sk_up := sk `op` up_sk
    // pk_up := pk mu(`op`) up_sk
    fn upk(&self, _: VK) -> (VK, Update<T>);
    fn usk(&self, _: SK, _: Update<T>) -> SK;
    fn usig(&self, _: &'static [u8], _: S, _: Update<T>) -> S;
}
// impl Updatable<SecretKey, VerificationKey, Signature, Scalar> for dyn Sig<SecretKey, VerificationKey, Signature, StarsigError> {
impl Updatable<SecretKey, VerificationKey, Signature, Scalar> for Starsig {
    fn upk(&self, pk: VerificationKey) -> (VerificationKey, Update<Scalar>) {
        // in the case of starsig, mu(`op`) b is + b * RISTRETTO_BASEPOINT_POINT
        // pk_up  = (sk * RISTRETTO_BASEPOINT_POINT) + (up_sk * RISTRETTO_BASEPOINT_POINT)
        //        = (sk + up_sk) * RISTRETTO_BASEPOINT_POINT
        //        = sk_up * RISTRETTO_BASEPOINT_POINT
        let mut csprng = OsRng{};
        let r = Scalar::random(&mut csprng);
        let up = Update{ up: r };

        let pk_compressed: CompressedRistretto = pk.into();
        let pk_point: RistrettoPoint = pk_compressed.decompress().unwrap();
        let pk_up: VerificationKey = VerificationKey::from(pk_point + (up.up*RISTRETTO_BASEPOINT_POINT));

        (pk_up, up)
    }
    fn usk(&self, sk: SecretKey, up: Update<Scalar>) -> SecretKey {
        // in the case of starsig, `op` is +
        SecretKey{ scalar: sk.scalar.add(up.up) } // TODO impl Add
    }
    fn usig(&self, m: &'static [u8], sigma: Signature, up: Update<Scalar>) -> Signature {
        // sigma_up := sigma + c * up_sk 
        //           = (r + c * sk) + c * up_sk = r + c * sk_up
        let mut transcript = Transcript::new(m);
        let c = {
            transcript.starsig_domain_sep();
            transcript.append_point(b"R", &sigma.R);
            transcript.challenge_scalar(b"c")
        };
        let s_new = sigma.s + c * up.up;

        Signature { s: s_new, R: sigma.R }
    }
}