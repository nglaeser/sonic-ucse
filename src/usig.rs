use crate::dlog::JubJub as JubJubDLogGroup;
use crate::dlog::{prove_dlog, DLogGroup, DLogProof, DLogProtocol};
use std::ops::{Add, Mul};

// collection of algorithms that make up a digital signature
pub struct Schnorr;
pub trait Sig<SK, VK, S> {
    fn kgen(&self) -> (SK, VK);
    fn sign(&self, _: SK, _: u64) -> S;
    fn verify(&self, _: VK, _: u64, _: S) -> bool;
}
use dusk_jubjub::{BlsScalar, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use dusk_pki::{PublicKey, SecretKey};
use jubjub_schnorr::Signature;
pub trait EasyAdd<T> {
    fn add(self, rhs: T) -> Self;
}
impl EasyAdd<JubJubExtended> for PublicKey {
    fn add(self, rhs: JubJubExtended) -> PublicKey {
        PublicKey::from(*self.as_ref() + rhs)
    }
}
impl Add<Update<JubJubScalar>> for SecretKey {
    type Output = SecretKey;
    fn add(self, rhs: Update<JubJubScalar>) -> SecretKey {
        SecretKey::from(*self.as_ref() + rhs.scalar)
    }
}

// updatability of keys
pub trait Updatable<T>
where
    T: Clone + Copy,
{
    fn update(self, _: Update<T>) -> Self;
}
// how to update secret and public keys
impl Updatable<JubJubScalar> for SecretKey {
    fn update(self, up: Update<JubJubScalar>) -> Self {
        // sk_up := sk + up_sk
        self + up
    }
}
impl Updatable<JubJubScalar> for PublicKey {
    fn update(self, up: Update<JubJubScalar>) -> Self {
        // pk_up := pk + (up_sk * G)
        //        = (sk * G) + (up_sk * G)
        //        = (sk + up_sk) * G
        //        = sk_up * G
        let pk_up = self.add(up * GENERATOR_EXTENDED);
        pk_up
    }
}

// starsig digital signature algorithms
impl Sig<SecretKey, PublicKey, Signature> for Schnorr {
    fn kgen(&self) -> (SecretKey, PublicKey) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }
    fn sign(&self, sk: SecretKey, m: u64) -> Signature {
        Signature::new(&sk, &mut rand::thread_rng(), BlsScalar::from(m))
    }
    fn verify(&self, pk: PublicKey, m: u64, sigma: Signature) -> bool {
        sigma.verify(&pk, BlsScalar::from(m))
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
impl Mul<JubJubExtended> for Update<JubJubScalar> {
    type Output = JubJubExtended;
    fn mul(self, point: JubJubExtended) -> JubJubExtended {
        point * self.scalar
    }
}
impl Mul<Update<JubJubScalar>> for JubJubScalar {
    type Output = JubJubScalar;
    fn mul(self, up: Update<JubJubScalar>) -> JubJubScalar {
        self * up.scalar
    }
}
// impl BigIntable for Update<DalekScalar> {
//     fn to_big_int(&self) -> curv::BigInt {
//         let rs: curves::Scalar<Ristretto> =
//             curves::Scalar::from_raw(ECScalar::from_underlying(self.scalar));
//         rs.to_bigint()
//     }
// }

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
    fn usig(&self, _: u64, _: S, _: Update<T>) -> S;
}
impl UpdatableSig<JubJubDLogGroup, SecretKey, PublicKey, Signature, JubJubScalar> for Schnorr {
    fn upk(&self, pk: PublicKey) -> (PublicKey, Update<JubJubScalar>, DLogProof<JubJubDLogGroup>) {
        let r = JubJubScalar::random(&mut rand::thread_rng());
        let up = Update { scalar: r };

        let pk_up: PublicKey = pk.update(up);

        // prove knowledge of up_sk s.t. pk_up = pk + up_sk * G
        // written as a dlog statement:
        //      knowledge of dlog of (pk_up - pk) wrt G
        //      since pk_up - pk = up_sk * G
        let mut transcript = DLogProtocol::<JubJubDLogGroup>::new(&[]);
        let proof = prove_dlog(
            &mut transcript,
            &(pk_up.as_ref() - pk.as_ref()),
            &GENERATOR_EXTENDED,
            &up.scalar,
        );

        (pk_up, up, proof) // TODO should the proof be verified anywhere?
    }
    fn usk(&self, sk: SecretKey, up: Update<JubJubScalar>) -> SecretKey {
        sk.update(up)
    }
    fn usig(&self, m: u64, sigma: Signature, up: Update<JubJubScalar>) -> Signature {
        // sigma_up.u := sigma - (c * up_sk)
        //             = (r - c * sk) - (c * up_sk) = r - c * (sk + up_sk)
        //             = r - (c * sk_up)
        let c = challenge_hash(sigma.R, BlsScalar::from(m));
        Signature {
            u: sigma.u - (c * up),
            R: sigma.R,
        }
    }
}
/// copy of https://github.com/nglaeser/jubjub-schnorr/blob/main/src/key_variants/single_key.rs#L19-L24
/// Method to create a challenge hash for signature scheme
use dusk_poseidon::sponge;
#[allow(non_snake_case)]
fn challenge_hash(R: JubJubExtended, message: BlsScalar) -> JubJubScalar {
    let R_scalar = R.to_hash_inputs();

    sponge::truncated::hash(&[R_scalar[0], R_scalar[1], message])
}
