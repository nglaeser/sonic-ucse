//! Our protocol allows the verification of multiple proofs and even
//! of individual proofs to batch the pairing operations such that
//! only a smaller, fixed number of pairings must occur for an entire
//! batch of proofs. This is possible because G2 elements are fixed
//! in our protocol and never appear in proofs; everything can be
//! combined probabilistically.
//!
//! This submodule contains the `Batch` abstraction for creating a
//! context for batch verification.

use crate::protocol::SonicProof;
use crate::srs::SRS;
use crate::usig::*;
use crate::util::multiexp;
use crate::Statement;
use pairing::{CurveAffine, CurveProjective, Engine, Field};
use starsig::{Signature, VerificationKey};

// One of the primary functions of the `Batch` abstraction is handling
// Kate commitment openings:
//
// e(P', [\alpha(x - z)] H) = e(P, H) e([-v] G, [\alpha] H)
// ==> e(P', [\alpha x] H) e([-z] P', [\alpha] H) = e(P, H) e([-v] G, [\alpha] H)
//
// Many of these can be opened simultaneously by sampling random `r` and
// accumulating...
//
// e([r] P', [\alpha x] H)
// e([-rz] P', [\alpha] H)
// e([r] P, -H)
// e([rv] G, [\alpha] H)
//
// ... and checking that the result is the identity in the target group.
// This is checking pcV (?)
type Proof<E> = SonicProof<<E as Engine>::G1Affine, <E as Engine>::Fr>;
pub struct Batch<E: Engine> {
    alpha_x: Vec<(E::G1Affine, E::Fr)>,
    alpha_x_precomp: <E::G2Affine as CurveAffine>::Prepared,

    alpha: Vec<(E::G1Affine, E::Fr)>,
    alpha_precomp: <E::G2Affine as CurveAffine>::Prepared,

    neg_h: Vec<(E::G1Affine, E::Fr)>,
    neg_h_precomp: <E::G2Affine as CurveAffine>::Prepared,

    neg_x_n_minus_d: Vec<(E::G1Affine, E::Fr)>,
    neg_x_n_minus_d_precomp: <E::G2Affine as CurveAffine>::Prepared,

    // The value paired with [\alpha] H, accumulated in the field
    // to save group operations.
    value: E::Fr,
    g: E::G1Affine,

    // new (UC SE) proof elements
    c: Vec<jubjub_elgamal::Cypher>,
    pk_l: Vec<VerificationKey>,
    sigma: Vec<Signature>,
    pk_ot: Vec<lamport_sigs::PublicKey>,
    sigma_ot: Vec<Result<Vec<Vec<u8>>, &'static str>>,
    underlying_proof: Vec<Proof<E>>,
}

impl<E: Engine> Batch<E> {
    pub fn new(srs: &SRS<E>, n: usize) -> Self {
        Batch {
            alpha_x: vec![],
            alpha_x_precomp: srs.h_positive_x_alpha[1].prepare(),

            alpha: vec![],
            alpha_precomp: srs.h_positive_x_alpha[0].prepare(),

            neg_h: vec![],
            neg_h_precomp: {
                let mut tmp = srs.h_negative_x[0];
                tmp.negate();
                tmp.prepare()
            },

            neg_x_n_minus_d: vec![],
            neg_x_n_minus_d_precomp: {
                let mut tmp = srs.h_negative_x[srs.d - n];
                tmp.negate();
                tmp.prepare()
            },

            value: E::Fr::zero(),   // 0
            g: srs.g_positive_x[0], // g^x^0 = g

            c: vec![],
            pk_l: vec![],
            sigma: vec![],
            pk_ot: vec![],
            sigma_ot: vec![],
            underlying_proof: vec![],
        }
    }

    pub fn add_opening(&mut self, p: E::G1Affine, mut r: E::Fr, point: E::Fr) {
        self.alpha_x.push((p, r));
        r.mul_assign(&point);
        r.negate();
        self.alpha.push((p, r));
    }

    pub fn add_commitment(&mut self, p: E::G1Affine, r: E::Fr) {
        self.neg_h.push((p, r));
    }

    pub fn add_commitment_max_n(&mut self, p: E::G1Affine, r: E::Fr) {
        self.neg_x_n_minus_d.push((p, r));
    }

    pub fn add_opening_value(&mut self, mut r: E::Fr, point: E::Fr) {
        r.mul_assign(&point);
        self.value.add_assign(&r);
    }

    pub fn add_pk(&mut self, pk: VerificationKey) {
        self.pk_l.push(pk);
    }

    pub fn add_signature(&mut self, sig: Signature) {
        self.sigma.push(sig);
    }

    pub fn add_ot_pk(&mut self, pk: lamport_sigs::PublicKey) {
        self.pk_ot.push(pk);
    }

    pub fn add_ot_signature(&mut self, sig: Result<Vec<Vec<u8>>, &'static str>) {
        self.sigma_ot.push(sig);
    }

    pub fn add_ctext(&mut self, ctext: jubjub_elgamal::Cypher) {
        self.c.push(ctext);
    }

    // TODO NG use generic type instead of SonicProof
    pub fn add_underlying_proof(&mut self, proof: Proof<E>) {
        self.underlying_proof.push(proof);
    }

    pub fn check_all(mut self, x: &dyn Statement) -> bool {
        //// check sigma and sigma_ot first, before the sonic proof
        // verify all the sigmas
        {
            use crate::util::to_be_bytes;
            let usig = Starsig;
            for ((pk, pk_ot), sigma) in self
                .pk_l
                .iter()
                .zip(self.pk_ot.iter())
                .zip(self.sigma.iter())
            {
                let message_bytes: Vec<u8> = pk_ot.to_bytes();
                if !usig.verify(*pk, &message_bytes, *sigma).is_ok() {
                    return false;
                }
            }
            for (((((pk, underlying_proof), c), pk_l), sigma), sigma_ot) in self
                .pk_ot
                .iter()
                .zip(self.underlying_proof.iter())
                .zip(self.c.iter())
                .zip(self.pk_l.iter())
                .zip(self.sigma.iter())
                .zip(self.sigma_ot.iter())
            {
                let message: &[u8] = &to_be_bytes(underlying_proof, x, c, pk_l, *sigma);
                let sigma_ot_valid = match &sigma_ot {
                    Ok(sig) => pk.verify_signature(sig, &message[..]),
                    Err(_) => false,
                };
                if !sigma_ot_valid {
                    return false;
                }
            }
        }

        //// check the sonic proof
        // type(alpha): Vec<(E::G1Affine, E::Fr)> (line 55)
        self.alpha.push((self.g, self.value));
        // alpha = [(g, 0)]

        //
        let alpha_x = multiexp(
            self.alpha_x.iter().map(|x| &x.0),
            self.alpha_x.iter().map(|x| &x.1),
        )
        .into_affine()
        .prepare();

        let alpha = multiexp(
            self.alpha.iter().map(|x| &x.0),
            self.alpha.iter().map(|x| &x.1),
        )
        .into_affine()
        .prepare();

        let neg_h = multiexp(
            self.neg_h.iter().map(|x| &x.0),
            self.neg_h.iter().map(|x| &x.1),
        )
        .into_affine()
        .prepare();

        // -x^{max-d}, aka -x^{-d+max}
        let neg_x_n_minus_d = multiexp(
            self.neg_x_n_minus_d.iter().map(|x| &x.0),
            self.neg_x_n_minus_d.iter().map(|x| &x.1),
        )
        .into_affine()
        .prepare();

        E::final_exponentiation(&E::miller_loop(&[
            (&alpha_x, &self.alpha_x_precomp),
            (&alpha, &self.alpha_precomp),
            (&neg_h, &self.neg_h_precomp),
            (&neg_x_n_minus_d, &self.neg_x_n_minus_d_precomp),
        ]))
        .unwrap()
            == E::Fqk::one()
    }
}
