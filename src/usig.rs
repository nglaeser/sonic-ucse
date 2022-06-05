use crate::dlog::Ristretto as RistrettoDLogGroup;
use crate::dlog::{prove_dlog, DLogGroup, DLogProof, DLogProtocol};
use crate::BigIntable;
use curv::elliptic::{curves, curves::ECScalar, curves::Ristretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
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
pub trait EasyAdd<T> {
    fn add(self, rhs: T) -> Self;
}
impl EasyAdd<RistrettoPoint> for VerificationKey {
    fn add(self, rhs: RistrettoPoint) -> VerificationKey {
        VerificationKey::from(self.point.decompress().unwrap() + rhs)
    }
}

// starsig secret key
#[derive(Copy, Clone)]
pub struct SecretKey {
    // from group of prime order l = 2^252 + 27742317777372353535851937790883648493
    // (ristretto 255)
    pub scalar: DalekScalar,
}
impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = DalekScalar::random(rng);
        SecretKey { scalar }
    }
}
impl Add<Update<DalekScalar>> for SecretKey {
    type Output = SecretKey;
    fn add(self, rhs: Update<DalekScalar>) -> SecretKey {
        SecretKey {
            scalar: self.scalar + rhs.scalar,
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
impl Updatable<DalekScalar> for SecretKey {
    fn update(self, up: Update<DalekScalar>) -> Self {
        // for starsig sk, `op` is +
        // sk_up := sk + up_sk
        self + up
    }
}
impl Updatable<DalekScalar> for VerificationKey {
    fn update(self, up: Update<DalekScalar>) -> Self {
        // for starsig, `mu(op) up` is `+ up * RISTRETTO_BASEPOINT_POINT`
        // pk_up := (sk * RISTRETTO_BASEPOINT_POINT) + (up_sk * RISTRETTO_BASEPOINT_POINT)
        // correctness:
        // pk_up  = (sk + up_sk) * RISTRETTO_BASEPOINT_POINT
        //        = sk_up * RISTRETTO_BASEPOINT_POINT
        let pk_up = self.add(up * RISTRETTO_BASEPOINT_POINT);
        pk_up
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
impl Mul<RistrettoPoint> for Update<DalekScalar> {
    type Output = RistrettoPoint;
    fn mul(self, point: RistrettoPoint) -> RistrettoPoint {
        self.scalar * point
    }
}
impl Mul<Update<DalekScalar>> for DalekScalar {
    type Output = DalekScalar;
    fn mul(self, up: Update<DalekScalar>) -> DalekScalar {
        self * up.scalar
    }
}
impl BigIntable for Update<DalekScalar> {
    fn to_big_int(&self) -> curv::BigInt {
        let rs: curves::Scalar<Ristretto> =
            curves::Scalar::from_raw(ECScalar::from_underlying(self.scalar));
        rs.to_bigint()
    }
}

// additional algorithms for *updatable* signature
pub trait UpdatableSig<G, SK, VK, S, T: Copy + Clone>
where
    G: DLogGroup,
    for<'a> &'a G::P: Mul<G::S, Output = G::P>,
    for<'a> G::S: Mul<&'a G::S, Output = G::S>,
{
    // sk_up := sk `op` up_sk
    // pk_up := pk mu(`op`) up_sk
    fn upk(&self, _: VK) -> (VK, Update<T>, DLogProof<G>);
    fn usk(&self, _: SK, _: Update<T>) -> SK;
    fn usig(&self, _: &[u8], _: S, _: Update<T>) -> S;
}
impl UpdatableSig<RistrettoDLogGroup, SecretKey, VerificationKey, Signature, DalekScalar>
    for Starsig
{
    fn upk(
        &self,
        pk: VerificationKey,
    ) -> (
        VerificationKey,
        Update<DalekScalar>,
        DLogProof<RistrettoDLogGroup>,
    ) {
        let mut csprng = OsRng {};
        let r = DalekScalar::random(&mut csprng);
        let up = Update { scalar: r };

        let pk_up: VerificationKey = pk.update(up);

        // prove knowledge of up_sk s.t. pk_up = pk + up_sk * RISTRETTO_BASEPOINT_POINT
        // written as a dlog statement:
        // knowledge of dlog of pk_up - pk wrt RISTRETTO_BASEPOINT_POINT
        // since pk_up - pk = up_sk * RISTRETTO_BASEPOINT_POINT
        let mut transcript = DLogProtocol::<RistrettoDLogGroup>::new(&[]);
        let proof = prove_dlog(
            &mut transcript,
            &(pk_up.point.decompress().unwrap() - pk.point.decompress().unwrap()),
            &RISTRETTO_BASEPOINT_POINT,
            &up.scalar,
        );

        (pk_up, up, proof) // TODO should the proof be verified anywhere?
    }
    fn usk(&self, sk: SecretKey, up: Update<DalekScalar>) -> SecretKey {
        sk.update(up)
    }
    fn usig(&self, m: &[u8], sigma: Signature, up: Update<DalekScalar>) -> Signature {
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
