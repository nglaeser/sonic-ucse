use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use merlin::{Transcript, TranscriptRng, TranscriptRngBuilder};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DLogProtocol<T: DLogGroup>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    pub transcript: Transcript,
    _foo: PhantomData<T>,
}
impl<T: DLogGroup> DLogProtocol<T>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    pub fn new(label: &'static [u8]) -> DLogProtocol<T> {
        DLogProtocol {
            transcript: Transcript::new(label),
            _foo: PhantomData,
        }
    }
    fn domain_sep(&mut self) {
        self.transcript.append_message(b"dom-sep", b"DLogProtocol");
    }
    fn append_point(&mut self, label: &'static [u8], point: &T::P) {
        self.transcript
            .append_message(label, &T::point_to_bytes(point));
    }
    fn _append_scalar(&mut self, label: &'static [u8], scalar: &T::S) {
        self.transcript
            .append_message(label, &T::scalar_to_bytes(scalar));
    }
    fn challenge_scalar(&mut self, label: &'static [u8]) -> T::S {
        let mut buf = [0; 64];
        self.transcript.challenge_bytes(label, &mut buf);
        T::scalar_from_bytes(&buf)
    }
}

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use std::cmp::PartialEq;
use std::ops::{Add, Mul};

pub trait DLogGroup
where
    for<'a> &'a Self::P: Mul<Self::S, Output = Self::P>,
    for<'a> Self::S: Mul<&'a Self::S, Output = Self::S>,
{
    type P: Mul<Self::S, Output = Self::P> + Add<Self::P, Output = Self::P> + PartialEq + Default;
    type S: Add<Self::S, Output = Self::S> + Mul<Self::S, Output = Self::S> + Copy + Default;

    fn scalar_to_bytes(scalar: &Self::S) -> [u8; 32];
    fn scalar_from_bytes(bytes: &[u8; 64]) -> Self::S;
    fn point_to_bytes(point: &Self::P) -> [u8; 32];
    fn random_scalar<T>(rand: &mut T) -> Self::S
    where
        T: RngCore + CryptoRng;
}
pub struct JubJub(JubJubExtended, JubJubScalar);
impl DLogGroup for JubJub {
    type P = JubJubExtended;
    type S = JubJubScalar;

    fn scalar_to_bytes(scalar: &JubJubScalar) -> [u8; 32] {
        scalar.to_bytes()
    }
    fn scalar_from_bytes(bytes: &[u8; 64]) -> JubJubScalar {
        JubJubScalar::from_bytes_wide(&bytes)
    }
    fn point_to_bytes(point: &JubJubExtended) -> [u8; 32] {
        JubJubAffine::from(point).to_bytes()
    }
    fn random_scalar<T>(rand: &mut T) -> JubJubScalar
    where
        T: RngCore + CryptoRng,
    {
        JubJubScalar::random(rand)
    }
}
pub struct Ristretto(RistrettoPoint, DalekScalar);
impl DLogGroup for Ristretto {
    type P = RistrettoPoint;
    type S = DalekScalar;

    fn scalar_to_bytes(scalar: &DalekScalar) -> [u8; 32] {
        scalar.to_bytes()
    }
    fn scalar_from_bytes(bytes: &[u8; 64]) -> DalekScalar {
        DalekScalar::from_bytes_mod_order_wide(&bytes)
    }
    fn point_to_bytes(point: &RistrettoPoint) -> [u8; 32] {
        point.compress().to_bytes()
    }
    fn random_scalar<T>(rand: &mut T) -> DalekScalar
    where
        T: RngCore + CryptoRng,
    {
        DalekScalar::random(rand)
    }
}

pub struct DLogProof<T: DLogGroup>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    pub a: T::P,
    pub z: T::S,
}
impl<T: DLogGroup> Default for DLogProof<T>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    fn default() -> DLogProof<T> {
        DLogProof::<T> {
            a: T::P::default(),
            z: T::S::default(),
        }
    }
}
// prove knowledge of x, the discrete logarithm of h wrt b (i.e., ((h,b), x) s.t. b^x = h)
pub fn prove_dlog<T: DLogGroup>(
    protocol: &mut DLogProtocol<T>,
    h: &T::P,
    b: &T::P,
    x: &T::S,
) -> DLogProof<T>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    // commit to proof label
    protocol.domain_sep();
    // commit to public parameters
    protocol.append_point(b"h", h);
    protocol.append_point(b"b", &b);

    // generate randomness
    let mut rng_builder: TranscriptRngBuilder = protocol.transcript.build_rng();
    rng_builder = rng_builder.rekey_with_witness_bytes(b"witness", &T::scalar_to_bytes(&x));
    let mut transcript_rng: TranscriptRng = rng_builder.finalize(&mut rand::thread_rng());
    let r = T::random_scalar(&mut transcript_rng);

    // round 1 message
    let a: T::P = b * r;
    protocol.append_point(b"b^r", &a);

    // generate challenge
    let ch: T::S = protocol.challenge_scalar(b"ch");

    // response
    let z = r + ch * x;
    DLogProof { a, z }
}
pub enum ProofError {
    GenericError,
}
pub fn vrfy_dlog<T: DLogGroup>(
    protocol: &mut DLogProtocol<T>,
    h: &T::P,
    b: &T::P,
    proof: DLogProof<T>,
) -> Result<(), ProofError>
where
    for<'a> &'a T::P: Mul<T::S, Output = T::P>,
    for<'a> T::S: Mul<&'a T::S, Output = T::S>,
{
    // commit to proof label
    protocol.domain_sep();
    // commit to public parameters
    protocol.append_point(b"h", h);
    protocol.append_point(b"b", &b);

    // round 1 message
    protocol.append_point(b"b^r", &proof.a);
    // generate challenge
    let ch: T::S = protocol.challenge_scalar(b"ch");

    let lhs = b * proof.z;
    let rhs = proof.a + h * ch;
    match lhs == rhs {
        true => Ok(()),
        false => Err(ProofError::GenericError),
    }
}
