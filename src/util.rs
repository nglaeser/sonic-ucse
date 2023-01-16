use crate::protocol::SonicProof;
use crate::SynthesisError;
use dusk_bytes::Serializable;
use dusk_pki::PublicKey;
use jubjub_elgamal::Cypher as ElGamalCtext;
use jubjub_schnorr::Signature;
use merlin::Transcript;
use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField, PrimeFieldRepr};
use std::io;

use dusk_jubjub::JubJubExtended;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use sapling_crypto::jubjub::edwards::Point;
use sapling_crypto::jubjub::{PrimeOrder, Unknown};
pub fn dusk_to_sapling(dusk_jubjub_point: JubJubExtended) -> Point<Bls12, PrimeOrder> {
    Point::new(
        // convert each coordiniate from BlsScalar to (Bls12::)Fr
        Fr::from_repr(FrRepr(dusk_jubjub_point.get_x().0)).unwrap(),
        Fr::from_repr(FrRepr(dusk_jubjub_point.get_y().0)).unwrap(),
        // T = T1 * T2 = XY/Z
        Fr::from_repr(FrRepr(
            (dusk_jubjub_point.get_t1() * dusk_jubjub_point.get_t2()).0,
        ))
        .unwrap(),
        Fr::from_repr(FrRepr(dusk_jubjub_point.get_z().0)).unwrap(),
    )
}
use dusk_jubjub::JubJubScalar;
pub fn be_opt_vec_to_jubjub_scalar(vec: &Vec<Option<bool>>) -> Vec<JubJubScalar> {
    let mut scalars = vec![];
    let num_blocks = vec.len() / 512 + 1;
    for i in 0..num_blocks {
        // let block = vec[i * 512..(i + 1) * 512].to_vec();
        let block = vec[i * 48..(i + 1) * 48].to_vec();
        let be_bytes = opt_vec_to_bytes(&block);
        let mut be_bytes_arr = [0u8; 64];
        for i in 0..be_bytes.len() {
            be_bytes_arr[i] = be_bytes[i];
        }

        let scalar = JubJubScalar::from_bytes_wide(&be_bytes_arr);
        scalars.push(scalar);
    }
    scalars
}

pub fn le_bytes_to_le_bits(arr: &[u8], len: usize, buf: &mut [bool]) {
    for i in 0..len {
        let mut mask: u8 = 0b10000000;
        let byte = arr[i];
        for j in 0..8 {
            buf[i * 8 + (7 - j)] = mask & byte != 0u8;
            mask = mask >> 1;
        }
    }
}

pub fn byte_arr_to_bool_arr(arr: &[u8], len: usize, buf: &mut [bool]) {
    for i in 0..len {
        let mut mask: u8 = 0b10000000;
        let byte = arr[i];
        for j in 0..8 {
            buf[i * 8 + j] = mask & byte != 0u8;
            mask = mask >> 1;
        }
    }
}

pub fn opt_vec_to_bytes(vec: &Vec<Option<bool>>) -> Vec<u8> {
    let out: Vec<bool> = vec.iter().map(|x| x.unwrap()).collect::<Vec<bool>>();
    bool_vec_to_bytes(&out)
}
pub fn bool_vec_to_bytes(vec: &Vec<bool>) -> Vec<u8> {
    // re-interpret the bit vector as a byte vector
    let mut out = Vec::new();

    let mut slice = vec![false; 8];
    for i in 0..(vec.len() / 8) {
        let start = i * 8;
        let end = (i + 1) * 8;
        slice.copy_from_slice(&vec[start..end]);
        let tmp: u8 = vec.iter().rev().fold(0, |acc, &b| (acc << 1) + b as u8);
        out.push(tmp);
    }
    out
}

pub fn bool_vec_to_big_int(vec: &Vec<Option<bool>>) -> curv::BigInt {
    let len = vec.len();

    let mut slice = vec![Some(false); 64];
    let mut out = curv::BigInt::from(0);
    for i in 0..(len / 64) {
        let start = i * 64;
        let end = (i + 1) * 64;
        slice.copy_from_slice(&vec[start..end]);

        // convert slice to u64
        let tmp: u64 = vec
            .iter()
            .rev()
            .fold(0, |acc, &b| (acc << 1) + b.unwrap() as u64);
        out = out + tmp;
    }
    out
}

pub fn to_be_bytes<E: Engine>(
    pi: &SonicProof<E>,
    x_bytes: &[u8],
    cts: &Vec<ElGamalCtext>,
    pk_l: &PublicKey,
    sigma: Signature,
) -> Vec<u8> {
    let mut bytes = [
        &pi.to_bytes(), // sonic_bytes,
        x_bytes,        // x_bytes,
    ]
    .concat();

    // ciphertexts
    let mut c_bytes = cts.iter().flat_map(|c| c.to_bytes()).collect::<Vec<_>>();
    bytes.append(&mut c_bytes);

    bytes.append(
        &mut [
            pk_l.to_bytes().as_slice(),  // &pk_l_bytes,
            sigma.to_bytes().as_slice(), // &sigma_bytes
        ]
        .concat(),
    );
    bytes
}

pub trait TranscriptProtocol {
    fn commit_point<G: CurveAffine>(&mut self, point: &G);
    fn commit_scalar<F: PrimeField>(&mut self, scalar: &F);
    fn get_challenge_scalar<F: PrimeField>(&mut self) -> F;
}

impl TranscriptProtocol for Transcript {
    fn commit_point<G: CurveAffine>(&mut self, point: &G) {
        self.append_message(b"point", point.into_compressed().as_ref());
    }

    fn commit_scalar<F: PrimeField>(&mut self, scalar: &F) {
        let mut v = vec![];
        scalar.into_repr().write_le(&mut v).unwrap();

        self.append_message(b"scalar", &v);
    }

    fn get_challenge_scalar<F: PrimeField>(&mut self) -> F {
        loop {
            let mut repr: F::Repr = Default::default();
            repr.read_be(TranscriptReader(self)).unwrap();

            if let Ok(result) = F::from_repr(repr) {
                return result;
            }
        }
    }
}

struct TranscriptReader<'a>(&'a mut Transcript);

impl<'a> io::Read for TranscriptReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.challenge_bytes(b"read", buf);

        Ok(buf.len())
    }
}

pub trait ChainExt: Iterator {
    fn chain_ext<U>(self, other: U) -> Chain<Self, U::IntoIter>
    where
        Self: Sized,
        U: IntoIterator<Item = Self::Item>,
    {
        Chain {
            t: self,
            u: other.into_iter(),
        }
    }
}

impl<I: Iterator> ChainExt for I {}

#[derive(Clone)]
pub struct Chain<T, U> {
    t: T,
    u: U,
}

impl<T, U> Iterator for Chain<T, U>
where
    T: Iterator,
    U: Iterator<Item = T::Item>,
{
    type Item = T::Item;

    fn next(&mut self) -> Option<T::Item> {
        match self.t.next() {
            Some(v) => Some(v),
            None => match self.u.next() {
                Some(v) => Some(v),
                None => None,
            },
        }
    }
}

impl<T, U> ExactSizeIterator for Chain<T, U>
where
    T: Iterator,
    U: Iterator<Item = T::Item>,
    T: ExactSizeIterator,
    U: ExactSizeIterator,
{
    fn len(&self) -> usize {
        self.t.len() + self.u.len()
    }
}

impl<T, U> DoubleEndedIterator for Chain<T, U>
where
    T: Iterator,
    U: Iterator<Item = T::Item>,
    T: DoubleEndedIterator,
    U: DoubleEndedIterator,
{
    fn next_back(&mut self) -> Option<T::Item> {
        match self.u.next_back() {
            Some(v) => Some(v),
            None => match self.t.next_back() {
                Some(v) => Some(v),
                None => None,
            },
        }
    }
}

pub fn multiexp<
    'a,
    G: CurveAffine,
    IB: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a G::Scalar>,
>(
    g: IB,
    s: IS,
) -> G::Projective
where
    IB::IntoIter: ExactSizeIterator + Clone,
    IS::IntoIter: ExactSizeIterator,
{
    let g = g.into_iter();
    let s = s.into_iter();
    assert_eq!(g.len(), s.len());

    let c = if s.len() < 32 {
        3u32
    } else {
        (f64::from(s.len() as u32)).ln().ceil() as u32
    };

    // Convert all of the scalars into representations
    let mut s = s.map(|s| s.into_repr()).collect::<Vec<_>>();

    let mut windows = vec![];
    let mut buckets = vec![];

    let mask = (1u64 << c) - 1u64;
    let mut cur = 0;
    while cur <= <G::Engine as Engine>::Fr::NUM_BITS {
        let mut acc = G::Projective::zero();

        buckets.truncate(0);
        buckets.resize((1 << c) - 1, G::Projective::zero());

        let g = g.clone();

        for (s, g) in s.iter_mut().zip(g) {
            let index = (s.as_ref()[0] & mask) as usize;

            if index != 0 {
                buckets[index - 1].add_assign_mixed(g);
            }

            s.shr(c as u32);
        }

        let mut running_sum = G::Projective::zero();
        for exp in buckets.iter().rev() {
            running_sum.add_assign(exp);
            acc.add_assign(&running_sum);
        }

        windows.push(acc);

        cur += c;
    }

    let mut acc = G::Projective::zero();

    for window in windows.into_iter().rev() {
        for _ in 0..c {
            acc.double();
        }

        acc.add_assign(&window);
    }

    acc
}

/// Divides polynomial `a` in `x` by `x - b` with
/// no remainder.
pub fn kate_divison<'a, F: Field, I: IntoIterator<Item = &'a F>>(a: I, mut b: F) -> Vec<F>
where
    I::IntoIter: DoubleEndedIterator + ExactSizeIterator,
{
    b.negate();
    let a = a.into_iter();

    let mut q = vec![F::zero(); a.len() - 1];

    let mut tmp = F::zero();
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = *r;
        lead_coeff.sub_assign(&tmp);
        *q = lead_coeff;
        tmp = lead_coeff;
        tmp.mul_assign(&b);
    }

    q
}

#[test]
fn laurent_division() {
    use pairing::bls12_381::Fr;
    use pairing::PrimeField;

    let mut poly = vec![
        Fr::from_str("328947234").unwrap(),
        Fr::from_str("3545623451111").unwrap(),
        Fr::from_str("112").unwrap(),
        Fr::from_str("55555").unwrap(),
        Fr::from_str("1235685").unwrap(),
    ];

    fn eval(poly: &[Fr], point: Fr) -> Fr {
        let point_inv = point.inverse().unwrap();

        let mut acc = Fr::zero();
        let mut tmp = Fr::one();
        for p in &poly[2..] {
            let mut t = *p;
            t.mul_assign(&tmp);
            acc.add_assign(&t);
            tmp.mul_assign(&point);
        }
        let mut tmp = point_inv;
        for p in poly[0..2].iter().rev() {
            let mut t = *p;
            t.mul_assign(&tmp);
            acc.add_assign(&t);
            tmp.mul_assign(&point_inv);
        }

        acc
    }

    let x = Fr::from_str("23").unwrap();
    let z = Fr::from_str("2000").unwrap();

    let p_at_x = eval(&poly, x);
    let p_at_z = eval(&poly, z);

    // poly = poly(X) - poly(z)
    poly[2].sub_assign(&p_at_z);

    let quotient_poly = kate_divison(&poly, z);

    let quotient = eval(&quotient_poly, x);

    // check that
    // quotient * (x - z) = p_at_x - p_at_z

    let mut lhs = x;
    lhs.sub_assign(&z);
    lhs.mul_assign(&quotient);

    let mut rhs = p_at_x;
    rhs.sub_assign(&p_at_z);

    assert_eq!(lhs, rhs);
}

pub fn multiply_polynomials<E: Engine>(mut a: Vec<E::Fr>, mut b: Vec<E::Fr>) -> Vec<E::Fr> {
    let result_len = a.len() + b.len() - 1;

    // Compute the size of our evaluation domain
    let mut m = 1;
    let mut exp = 0;
    while m < result_len {
        m *= 2;
        exp += 1;

        // The pairing-friendly curve may not be able to support
        // large enough (radix2) evaluation domains.
        if exp >= E::Fr::S {
            panic!("polynomial too large")
        }
    }

    // Compute omega, the 2^exp primitive root of unity
    let mut omega = E::Fr::root_of_unity();
    for _ in exp..E::Fr::S {
        omega.square();
    }

    // Extend with zeroes
    a.resize(m, E::Fr::zero());
    b.resize(m, E::Fr::zero());

    serial_fft::<E>(&mut a[..], &omega, exp);
    serial_fft::<E>(&mut b[..], &omega, exp);

    for (a, b) in a.iter_mut().zip(b.iter()) {
        a.mul_assign(b);
    }

    serial_fft::<E>(&mut a[..], &omega.inverse().unwrap(), exp);

    a.truncate(result_len);

    let minv = E::Fr::from_str(&format!("{}", m))
        .unwrap()
        .inverse()
        .unwrap();

    for a in a.iter_mut() {
        a.mul_assign(&minv);
    }

    a
}

fn serial_fft<E: Engine>(a: &mut [E::Fr], omega: &E::Fr, log_n: u32) {
    fn bitreverse(mut n: u32, l: u32) -> u32 {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m = omega.pow(&[(n / (2 * m)) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = E::Fr::one();
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t.mul_assign(&w);
                let mut tmp = a[(k + j) as usize];
                tmp.sub_assign(&t);
                a[(k + j + m) as usize] = tmp;
                a[(k + j) as usize].add_assign(&t);
                w.mul_assign(&w_m);
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

pub trait OptionExt<T> {
    fn get(self) -> Result<T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn get(self) -> Result<T, SynthesisError> {
        match self {
            Some(t) => Ok(t),
            None => Err(SynthesisError::AssignmentMissing),
        }
    }
}
