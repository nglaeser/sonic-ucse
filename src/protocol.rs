use crate::batch::Batch;
use crate::srs::SRS;
use crate::synthesis::{Backend, SynthesisDriver};
use crate::usig::*;
use crate::util::*;
use crate::{Circuit, Coeff, Scalarable, Statement, SynthesisError, Variable};
use dusk_pki::{PublicKey, SecretKey};
use jubjub_schnorr::Signature;
use lamport_sigs;
use merlin::Transcript;
use pairing::{CurveAffine, CurveProjective, Engine, Field};
use ring::digest::SHA256;
use std::marker::PhantomData;
// use ring::digest::{Algorithm, SHA512};
// static DIGEST_256: &Algorithm = &SHA256; // TODO NG decide which SHA to use

#[derive(Clone)]
pub struct SxyAdvice<E: Engine> {
    s: E::G1Affine,
    opening: E::G1Affine,
    szy: E::Fr,
}

#[derive(Clone)]
pub struct SonicProof<A, F> {
    r: A,
    t: A,
    rz: F,
    rzy: F,
    z_opening: A,
    zy_opening: A,
}
impl<A: CurveAffine, F: pairing::PrimeField> SonicProof<A, F> {
    pub fn dummy() -> Self {
        SonicProof {
            r: A::one(),
            rz: F::zero(),
            rzy: F::zero(),
            t: A::one(),
            z_opening: A::one(),
            zy_opening: A::one(),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let r_bytes = &self.r.into_uncompressed();
        let t_bytes = &self.t.into_uncompressed();

        let rz_repr = &self.rz.into_repr();
        let rz_bytes: Vec<u8> = rz_repr
            .as_ref()
            .into_iter()
            .flat_map(|x| [(*x).to_be_bytes()].concat())
            .collect();

        let rzy_repr = &self.rzy.into_repr();
        let rzy_bytes: Vec<u8> = rzy_repr
            .as_ref()
            .into_iter()
            .flat_map(|x| [(*x).to_be_bytes()].concat())
            .collect();

        let z_opening_bytes = &self.z_opening.into_uncompressed();
        let zy_opening_bytes = &self.zy_opening.into_uncompressed();

        [
            r_bytes.as_ref(),
            t_bytes.as_ref(),
            &rz_bytes,
            &rzy_bytes,
            z_opening_bytes.as_ref(),
            zy_opening_bytes.as_ref(),
        ]
        .concat()
    }
}

#[derive(Clone)]
pub struct Proof<E: Engine> {
    r: E::G1Affine,
    t: E::G1Affine,
    rz: E::Fr,
    rzy: E::Fr,
    z_opening: E::G1Affine,
    zy_opening: E::G1Affine,
    c: jubjub_elgamal::Cypher,
    pk_l: PublicKey,
    sigma: Signature,
    pk_ot: lamport_sigs::PublicKey,
    sigma_ot: Result<Vec<Vec<u8>>, &'static str>,
}

pub struct MultiVerifier<E: Engine, C: Circuit<E>, S: SynthesisDriver> {
    circuit: C,
    batch: Batch<E>,
    k_map: Vec<usize>,
    n: usize,
    q: usize,
    _marker: PhantomData<(E, S)>,
}

impl<E: Engine, C: Circuit<E> + Statement, S: SynthesisDriver> MultiVerifier<E, C, S> {
    pub fn new(circuit: C, srs: &SRS<E>) -> Result<Self, SynthesisError> {
        struct Preprocess<E: Engine> {
            k_map: Vec<usize>,
            n: usize,
            q: usize,
            _marker: PhantomData<E>,
        }

        impl<'a, E: Engine> Backend<E> for &'a mut Preprocess<E> {
            type LinearConstraintIndex = ();

            fn get_for_q(&self, _q: usize) -> Self::LinearConstraintIndex {
                ()
            }

            fn new_k_power(&mut self, index: usize) {
                self.k_map.push(index);
            }

            fn new_multiplication_gate(&mut self) {
                self.n += 1;
            }

            fn new_linear_constraint(&mut self) {
                self.q += 1;
                ()
            }
        }

        let mut preprocess = Preprocess {
            k_map: vec![],
            n: 0,
            q: 0,
            _marker: PhantomData,
        };

        S::synthesize(&mut preprocess, &circuit)?;

        Ok(MultiVerifier {
            circuit,
            batch: Batch::new(srs, preprocess.n),
            k_map: preprocess.k_map,
            n: preprocess.n,
            q: preprocess.q,
            _marker: PhantomData,
        })
    }

    pub fn add_aggregate(&mut self, proofs: &[(Proof<E>, SxyAdvice<E>)], aggregate: &Aggregate<E>) {
        let mut transcript = Transcript::new(&[]);
        let mut y_values: Vec<E::Fr> = Vec::with_capacity(proofs.len());
        for &(ref proof, ref sxyadvice) in proofs {
            {
                let mut transcript = Transcript::new(&[]);
                transcript.commit_point(&proof.r);
                y_values.push(transcript.get_challenge_scalar());
            }

            transcript.commit_point(&sxyadvice.s);
        }

        let z: E::Fr = transcript.get_challenge_scalar();

        transcript.commit_point(&aggregate.c);

        let w: E::Fr = transcript.get_challenge_scalar();

        let szw = {
            let mut tmp = SxEval::new(w, self.n);
            S::synthesize(&mut tmp, &self.circuit).unwrap(); // TODO

            tmp.finalize(z)
        };

        {
            // TODO: like everything else doing this, this isn't really random
            let random: E::Fr;
            let mut transcript = transcript.clone();
            random = transcript.get_challenge_scalar();

            self.batch.add_opening(aggregate.opening, random, w);
            self.batch.add_commitment(aggregate.c, random);
            self.batch.add_opening_value(szw, random);
        }

        for ((opening, value), &y) in aggregate.c_openings.iter().zip(y_values.iter()) {
            let random: E::Fr;
            let mut transcript = transcript.clone();
            random = transcript.get_challenge_scalar();

            self.batch.add_opening(*opening, random, y);
            self.batch.add_commitment(aggregate.c, random);
            self.batch.add_opening_value(*value, random);
        }

        let random: E::Fr;
        {
            let mut transcript = transcript.clone();
            random = transcript.get_challenge_scalar();
        }

        let mut expected_value = E::Fr::zero();
        for ((_, advice), c_opening) in proofs.iter().zip(aggregate.c_openings.iter()) {
            let mut r: E::Fr = transcript.get_challenge_scalar();

            // expected value of the later opening
            {
                let mut tmp = c_opening.1;
                tmp.mul_assign(&r);
                expected_value.add_assign(&tmp);
            }

            r.mul_assign(&random);

            self.batch.add_commitment(advice.s, r);
        }

        self.batch.add_opening_value(expected_value, random);
        self.batch.add_opening(aggregate.s_opening, random, z);
    }

    pub fn add_proof_with_advice(
        &mut self,
        proof: &Proof<E>,
        inputs: &[E::Fr],
        advice: &SxyAdvice<E>,
    ) {
        let mut z = None;

        self.add_proof(proof, inputs, |_z, _y| {
            z = Some(_z);
            Some(advice.szy)
        });

        let z = z.unwrap();

        // We need to open up SxyAdvice.s at z using SxyAdvice.opening
        let mut transcript = Transcript::new(&[]);
        transcript.commit_point(&advice.opening);
        transcript.commit_point(&advice.s);
        transcript.commit_scalar(&advice.szy);
        let random: E::Fr = transcript.get_challenge_scalar();

        self.batch.add_opening(advice.opening, random, z);
        self.batch.add_commitment(advice.s, random);
        self.batch.add_opening_value(advice.szy, random);
    }

    // add proofs to check (see zkV3) to batcher
    // UCSE: also add the extra fields to Batch, and check everything in
    // Batch.check_all
    pub fn add_proof<F>(&mut self, proof: &Proof<E>, inputs: &[E::Fr], sxy: F)
    where
        F: FnOnce(E::Fr, E::Fr) -> Option<E::Fr>,
    {
        ////// parse the proof
        //// ---additional fields for UCSE---
        self.batch.add_ctext(proof.c.clone());
        self.batch.add_pk(proof.pk_l);
        self.batch.add_signature(proof.sigma);
        self.batch.add_ot_pk(proof.pk_ot.clone()); // TODO clone()?
        self.batch.add_ot_signature(proof.sigma_ot.clone());
        let sonic_proof = SonicProof {
            r: proof.r,
            rz: proof.rz,
            rzy: proof.rzy,
            t: proof.t,
            z_opening: proof.z_opening,
            zy_opening: proof.zy_opening,
        };
        self.batch.add_underlying_proof(sonic_proof.clone());

        //// --- Sonic proof ---
        let mut transcript = Transcript::new(&[]);

        // zkP1
        transcript.commit_point(&proof.r);

        // zkV1
        let y: E::Fr = transcript.get_challenge_scalar();

        // zkP2
        transcript.commit_point(&proof.t);

        // zkV2
        let z: E::Fr = transcript.get_challenge_scalar();

        // zkP3
        transcript.commit_scalar(&proof.rz); // a?
        transcript.commit_scalar(&proof.rzy); // b?

        let r1: E::Fr = transcript.get_challenge_scalar();

        transcript.commit_point(&proof.z_opening); // W_a, W_t
        transcript.commit_point(&proof.zy_opening); // W_b
                                                    // --- (end parse Sonic proof) ---

        // zkV3
        // ----
        // proof.rz:         a
        // proof.rzy:        b
        // proof.zy_opening: W_b
        // proof.z_opening:  W_a, W_t
        // proof.r:          R
        // proof.t:          T
        // ----

        //* b, W_b <- Open(R, yz, r(X,1))
        // First, the easy one. Let's open up proof.r at zy, using proof.zy_opening
        // as the evidence and proof.rzy as the opening.
        {
            let random = transcript.get_challenge_scalar();
            let mut zy = z;
            zy.mul_assign(&y);
            //* check pcV(bp, srs, n, R, yz, (b, W_b))
            self.batch.add_opening(proof.zy_opening, random, zy); // W_b, zy
            self.batch.add_commitment_max_n(proof.r, random); // R
            self.batch.add_opening_value(proof.rzy, random); // b
        }

        //// compute t(z,y) = Open(T,z,t(X,y)) ?
        // or t := a(b+s)-k(y) ?
        // = r(z,1)(r(zy,1)+s(z,y))-k(y)
        // Now we need to compute t(z, y) with what we have. Let's compute k(y).
        let mut ky = E::Fr::zero();
        for (exp, input) in self
            .k_map
            .iter()
            .zip(Some(E::Fr::one()).iter().chain(inputs.iter()))
        {
            let mut term = y.pow(&[(*exp + self.n) as u64]);
            term.mul_assign(input);
            ky.add_assign(&term);
        }

        //* s = s(z,y), sc <- scP(info, s(X,Y), (z,y))
        // Compute s(z, y)
        let szy = sxy(z, y).unwrap_or_else(|| {
            let mut tmp = SxEval::new(y, self.n);
            S::synthesize(&mut tmp, &self.circuit).unwrap(); // TODO

            tmp.finalize(z)

            // let mut tmp = SyEval::new(z, self.n, self.q);
            // S::synthesize(&mut tmp, &self.circuit).unwrap(); // TODO

            // tmp.finalize(y)
        });

        //* t <- a(b+s)-k(y)
        // Finally, compute t(z, y)
        let mut tzy = proof.rzy; // b
        tzy.add_assign(&szy); // +s
        tzy.mul_assign(&proof.rz); // *a
        tzy.sub_assign(&ky); // -k(y)

        // We open these both at the same time by keeping their commitments
        // linearly independent (using r1).
        {
            let mut random = transcript.get_challenge_scalar();

            //* t, W_t <- Open(T, z, t(X,y))
            //* check pcV(bp, srs, n, T, z, (t, W_t))
            self.batch.add_opening(proof.z_opening, random, z); // both r,t are opened at z
            self.batch.add_opening_value(tzy, random); // t
            self.batch.add_commitment(proof.t, random); // T

            // r = r*r1
            random.mul_assign(&r1);

            //* a, W_a <- Open(R, z, r(X,1))
            //* check pcV(bp, srs, n, R, z, (a, W_a))
            self.batch.add_opening_value(proof.rz, random); // a
            self.batch.add_commitment_max_n(proof.r, random); // R
        }
    }

    // zkV3
    // self: MultiVerifier
    pub fn check_all(self) -> bool {
        // check all the proofs added to the batcher (either via `add_proof`
        // or `add_proof_with_advice`)
        // check scV(info, s(X,Y), (z,y), (s,sc))
        // check pcV(bp, srs, n, R, z, (a, W_a))
        // check pcV(bp, srs, n, R, yz, (b, W_b))
        // check pcV(bp, srs, n, T, z, (t, W_t))
        // return 1 if all checks pass, else return 0

        // because this is the last line, the fn returns the output of this call
        self.batch.check_all(&self.circuit) // batch.rs:97
    }
}

#[derive(Clone)]
pub struct Aggregate<E: Engine> {
    // Commitment to s(z, Y)
    c: E::G1Affine,
    // We have to open each of the S commitments to a random point `z`
    s_opening: E::G1Affine,
    // We have to open C to each constituent `y`
    c_openings: Vec<(E::G1Affine, E::Fr)>,
    // Then we have to finally open C
    opening: E::G1Affine,
}

pub fn create_aggregate<E: Engine, C: Circuit<E>, S: SynthesisDriver>(
    circuit: &C,
    inputs: &[(Proof<E>, SxyAdvice<E>)],
    srs: &SRS<E>,
) -> Aggregate<E> {
    // TODO: precompute this?
    let (n, q) = {
        struct CountN {
            n: usize,
            q: usize,
        }

        impl<'a, E: Engine> Backend<E> for &'a mut CountN {
            type LinearConstraintIndex = ();

            fn get_for_q(&self, _q: usize) -> Self::LinearConstraintIndex {
                ()
            }

            fn new_multiplication_gate(&mut self) {
                self.n += 1;
            }

            fn new_linear_constraint(&mut self) {
                self.q += 1;
                ()
            }
        }

        let mut tmp = CountN { n: 0, q: 0 };
        S::synthesize(&mut tmp, circuit).unwrap(); // TODO

        (tmp.n, tmp.q)
    };

    let mut transcript = Transcript::new(&[]);
    let mut y_values: Vec<E::Fr> = Vec::with_capacity(inputs.len());
    for &(ref proof, ref sxyadvice) in inputs {
        {
            let mut transcript = Transcript::new(&[]);
            transcript.commit_point(&proof.r);
            y_values.push(transcript.get_challenge_scalar());
        }

        transcript.commit_point(&sxyadvice.s);
    }

    let z: E::Fr = transcript.get_challenge_scalar();

    // Compute s(z, Y)
    let (s_poly_negative, s_poly_positive) = {
        let mut tmp = SyEval::new(z, n, q);
        S::synthesize(&mut tmp, circuit).unwrap(); // TODO

        tmp.poly()
    };

    // Compute C = g^{s(z, x)}
    let c = multiexp(
        srs.g_positive_x_alpha[0..(n + q)]
            .iter()
            .chain_ext(srs.g_negative_x_alpha[0..n].iter()),
        s_poly_positive.iter().chain_ext(s_poly_negative.iter()),
    )
    .into_affine();

    transcript.commit_point(&c);

    // Open C at w
    let w: E::Fr = transcript.get_challenge_scalar();

    let value = compute_value::<E>(&w, &s_poly_positive, &s_poly_negative);

    let opening = {
        let mut value = value;
        value.negate();

        let poly = kate_divison(
            s_poly_negative
                .iter()
                .rev()
                .chain_ext(Some(value).iter())
                .chain_ext(s_poly_positive.iter()),
            w,
        );

        let negative_poly = poly[0..n].iter().rev();
        let positive_poly = poly[n..].iter();
        multiexp(
            srs.g_negative_x[1..(negative_poly.len() + 1)]
                .iter()
                .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
            negative_poly.chain_ext(positive_poly),
        )
        .into_affine()
    };

    // Let's open up C to every y.
    fn compute_value<E: Engine>(
        y: &E::Fr,
        poly_positive: &[E::Fr],
        poly_negative: &[E::Fr],
    ) -> E::Fr {
        let mut value = E::Fr::zero();

        let yinv = y.inverse().unwrap(); // TODO
        let mut tmp = yinv;
        for &coeff in poly_negative {
            let mut coeff = coeff;
            coeff.mul_assign(&tmp);
            value.add_assign(&coeff);
            tmp.mul_assign(&yinv);
        }

        let mut tmp = *y;
        for &coeff in poly_positive {
            let mut coeff = coeff;
            coeff.mul_assign(&tmp);
            value.add_assign(&coeff);
            tmp.mul_assign(&y);
        }

        value
    }

    let mut c_openings = vec![];
    for y in &y_values {
        let value = compute_value::<E>(y, &s_poly_positive, &s_poly_negative);

        let opening = {
            let mut value = value;
            value.negate();

            let poly = kate_divison(
                s_poly_negative
                    .iter()
                    .rev()
                    .chain_ext(Some(value).iter())
                    .chain_ext(s_poly_positive.iter()),
                *y,
            );

            let negative_poly = poly[0..n].iter().rev();
            let positive_poly = poly[n..].iter();
            multiexp(
                srs.g_negative_x[1..(negative_poly.len() + 1)]
                    .iter()
                    .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
                negative_poly.chain_ext(positive_poly),
            )
            .into_affine()
        };

        c_openings.push((opening, value));
    }

    // Okay, great. Now we need to open up each S at the same point z to the same value.
    // Since we're opening up all the S's at the same point, we create a bunch of random
    // challenges instead and open up a random linear combination.

    let mut poly_negative = vec![E::Fr::zero(); n];
    let mut poly_positive = vec![E::Fr::zero(); 2 * n];
    let mut expected_value = E::Fr::zero();

    for (y, c_opening) in y_values.iter().zip(c_openings.iter()) {
        // Compute s(X, y_i)
        let (s_poly_negative, s_poly_positive) = {
            let mut tmp = SxEval::new(*y, n);
            S::synthesize(&mut tmp, circuit).unwrap(); // TODO

            tmp.poly()
        };

        let mut value = c_opening.1;
        let r: E::Fr = transcript.get_challenge_scalar();
        value.mul_assign(&r);
        expected_value.add_assign(&value);

        for (mut coeff, target) in s_poly_negative.into_iter().zip(poly_negative.iter_mut()) {
            coeff.mul_assign(&r);
            target.add_assign(&coeff);
        }

        for (mut coeff, target) in s_poly_positive.into_iter().zip(poly_positive.iter_mut()) {
            coeff.mul_assign(&r);
            target.add_assign(&coeff);
        }
    }

    let s_opening = {
        let mut value = expected_value;
        value.negate();

        let poly = kate_divison(
            poly_negative
                .iter()
                .rev()
                .chain_ext(Some(value).iter())
                .chain_ext(poly_positive.iter()),
            z,
        );

        let negative_poly = poly[0..n].iter().rev();
        let positive_poly = poly[n..].iter();
        multiexp(
            srs.g_negative_x[1..(negative_poly.len() + 1)]
                .iter()
                .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
            negative_poly.chain_ext(positive_poly),
        )
        .into_affine()
    };

    Aggregate {
        // Commitment to s(z, Y)
        c,
        // We have to open each of the S commitments to a random point `z`
        s_opening,
        // We have to open C to each constituent `y`
        c_openings,
        // Then we have to finally open C
        opening,
    }
}

pub fn create_advice<E: Engine, C: Circuit<E>, S: SynthesisDriver>(
    circuit: &C,
    proof: &Proof<E>,
    srs: &SRS<E>,
) -> SxyAdvice<E> {
    // annoying, but we need n to compute s(z, y), and this isn't
    // precomputed anywhere yet
    let n = {
        struct CountN {
            n: usize,
        }

        impl<'a, E: Engine> Backend<E> for &'a mut CountN {
            type LinearConstraintIndex = ();

            fn new_linear_constraint(&mut self) -> Self::LinearConstraintIndex {
                ()
            }

            fn get_for_q(&self, _q: usize) -> Self::LinearConstraintIndex {
                ()
            }

            fn new_multiplication_gate(&mut self) {
                self.n += 1;
            }
        }

        let mut tmp = CountN { n: 0 };
        S::synthesize(&mut tmp, circuit).unwrap(); // TODO

        tmp.n
    };

    let z: E::Fr;
    let y: E::Fr;
    {
        let mut transcript = Transcript::new(&[]);
        transcript.commit_point(&proof.r);
        y = transcript.get_challenge_scalar();
        transcript.commit_point(&proof.t);
        z = transcript.get_challenge_scalar();
    }
    let z_inv = z.inverse().unwrap(); // TODO

    let (s_poly_negative, s_poly_positive) = {
        let mut tmp = SxEval::new(y, n);
        S::synthesize(&mut tmp, circuit).unwrap(); // TODO

        tmp.poly()
    };

    // Compute S commitment
    let s = multiexp(
        srs.g_positive_x_alpha[0..(2 * n)]
            .iter()
            .chain_ext(srs.g_negative_x_alpha[0..(n)].iter()),
        s_poly_positive.iter().chain_ext(s_poly_negative.iter()),
    )
    .into_affine();

    // Compute s(z, y)
    let mut szy = E::Fr::zero();
    {
        let mut tmp = z;
        for &p in &s_poly_positive {
            let mut p = p;
            p.mul_assign(&tmp);
            szy.add_assign(&p);
            tmp.mul_assign(&z);
        }
        let mut tmp = z_inv;
        for &p in &s_poly_negative {
            let mut p = p;
            p.mul_assign(&tmp);
            szy.add_assign(&p);
            tmp.mul_assign(&z_inv);
        }
    }

    // Compute kate opening
    let opening = {
        let mut open = szy;
        open.negate();

        let poly = kate_divison(
            s_poly_negative
                .iter()
                .rev()
                .chain_ext(Some(open).iter())
                .chain_ext(s_poly_positive.iter()),
            z,
        );

        let negative_poly = poly[0..n].iter().rev();
        let positive_poly = poly[n..].iter();
        multiexp(
            srs.g_negative_x[1..(negative_poly.len() + 1)]
                .iter()
                .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
            negative_poly.chain_ext(positive_poly),
        )
        .into_affine()
    };

    SxyAdvice { s, szy, opening }
}

pub fn create_proof<E: Engine, C: Statement + Scalarable + Circuit<E>, S: SynthesisDriver>(
    circuit: &C, // contains witness
    srs: &SRS<E>,
) -> Result<Proof<E>, SynthesisError> // where 
// <E as Engine>::G1Affine: UncompressedEncoding,
// <E as Engine>::Fr: PrimeField
{
    struct Wires<E: Engine> {
        a: Vec<E::Fr>,
        b: Vec<E::Fr>,
        c: Vec<E::Fr>,
    }

    impl<'a, E: Engine> Backend<E> for &'a mut Wires<E> {
        type LinearConstraintIndex = ();

        fn new_linear_constraint(&mut self) -> Self::LinearConstraintIndex {
            ()
        }

        fn get_for_q(&self, _q: usize) -> Self::LinearConstraintIndex {
            ()
        }

        fn new_multiplication_gate(&mut self) {
            self.a.push(E::Fr::zero());
            self.b.push(E::Fr::zero());
            self.c.push(E::Fr::zero());
        }

        fn get_var(&self, variable: Variable) -> Option<E::Fr> {
            Some(match variable {
                Variable::A(index) => self.a[index - 1],
                Variable::B(index) => self.b[index - 1],
                Variable::C(index) => self.c[index - 1],
            })
        }

        fn set_var<F>(&mut self, variable: Variable, value: F) -> Result<(), SynthesisError>
        where
            F: FnOnce() -> Result<E::Fr, SynthesisError>,
        {
            let value = value()?;

            match variable {
                Variable::A(index) => {
                    self.a[index - 1] = value;
                }
                Variable::B(index) => {
                    self.b[index - 1] = value;
                }
                Variable::C(index) => {
                    self.c[index - 1] = value;
                }
            }

            Ok(())
        }
    }

    let mut wires = Wires {
        a: vec![],
        b: vec![],
        c: vec![],
    };

    // wires: Backend<E> where E: Engine
    // circuit: Circuit<E>
    // runs circuit.synthesize(&mut synthesizer: Synthesizer) (synthesis.rs:46)
    S::synthesize(&mut wires, circuit)?;

    let n = wires.a.len();

    let mut transcript = Transcript::new(&[]);

    // zkP1
    let r = multiexp(
        srs.g_positive_x_alpha[(srs.d - 3 * n - 1)..].iter(),
        wires
            .c
            .iter()
            .rev()
            .chain_ext(wires.b.iter().rev())
            .chain_ext(Some(E::Fr::zero()).iter())
            .chain_ext(wires.a.iter()),
    )
    .into_affine();

    transcript.commit_point(&r);

    // zkV1
    let y: E::Fr = transcript.get_challenge_scalar();

    //
    let mut rx1 = wires.b;
    rx1.extend(wires.c);
    rx1.reverse();
    rx1.push(E::Fr::zero());
    rx1.extend(wires.a);

    let mut rxy = rx1.clone();
    let y_inv = y.inverse().unwrap(); // TODO
    let mut tmp = y.pow(&[n as u64]);

    for rxy in rxy.iter_mut().rev() {
        rxy.mul_assign(&tmp);
        tmp.mul_assign(&y_inv);
    }

    let (s_poly_negative, s_poly_positive) = {
        let mut tmp = SxEval::new(y, n);
        S::synthesize(&mut tmp, circuit).unwrap(); // TODO

        tmp.poly()
    };

    let mut rxy_prime = rxy.clone();
    {
        rxy_prime.resize(4 * n + 1, E::Fr::zero());
        // Add s(x, y)
        for (r, s) in rxy_prime[0..(2 * n)].iter_mut().rev().zip(s_poly_negative) {
            r.add_assign(&s);
        }
        for (r, s) in rxy_prime[(2 * n + 1)..].iter_mut().zip(s_poly_positive) {
            r.add_assign(&s);
        }
    }

    let mut txy = multiply_polynomials::<E>(rx1.clone(), rxy_prime);
    txy[4 * n] = E::Fr::zero(); // -k(y)

    let t = multiexp(
        srs.g_positive_x_alpha[0..(3 * n)]
            .iter()
            .chain_ext(srs.g_negative_x_alpha[0..(4 * n)].iter()),
        txy[(4 * n + 1)..]
            .iter()
            .chain_ext(txy[0..4 * n].iter().rev()),
    )
    .into_affine();

    // zkP2
    transcript.commit_point(&t);

    // zkV2
    let z: E::Fr = transcript.get_challenge_scalar();
    let z_inv = z.inverse().unwrap(); // TODO

    // zkP3
    // TODO: use the faster way to evaluate the polynomials
    let mut rz = E::Fr::zero();
    {
        let mut tmp = z.pow(&[n as u64]);

        for coeff in rx1.iter().rev() {
            let mut coeff = *coeff;
            coeff.mul_assign(&tmp);
            rz.add_assign(&coeff);
            tmp.mul_assign(&z_inv);
        }
    }

    let mut rzy = E::Fr::zero();
    {
        let mut tmp = z.pow(&[n as u64]);

        for mut coeff in rxy.into_iter().rev() {
            coeff.mul_assign(&tmp);
            rzy.add_assign(&coeff);
            tmp.mul_assign(&z_inv);
        }
    }

    transcript.commit_scalar(&rz);
    transcript.commit_scalar(&rzy);

    let r1: E::Fr = transcript.get_challenge_scalar();

    let zy_opening = {
        // r(X, 1) - r(z, y)
        rx1[2 * n].sub_assign(&rzy);

        let mut point = y;
        point.mul_assign(&z);
        let poly = kate_divison(rx1.iter(), point);

        let negative_poly = poly[0..2 * n].iter().rev();
        let positive_poly = poly[2 * n..].iter();
        multiexp(
            srs.g_negative_x[1..(negative_poly.len() + 1)]
                .iter()
                .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
            negative_poly.chain_ext(positive_poly),
        )
        .into_affine()
    };

    let z_opening = {
        rx1[2 * n].add_assign(&rzy); // restore

        for (t, &r) in txy[2 * n..].iter_mut().zip(rx1.iter()) {
            let mut r = r;
            r.mul_assign(&r1);
            t.add_assign(&r);
        }

        let mut val = E::Fr::zero();
        {
            assert_eq!(txy.len(), 3 * n + 1 + 4 * n);
            let mut tmp = z.pow(&[(3 * n) as u64]);

            for coeff in txy.iter().rev() {
                let mut coeff = *coeff;
                coeff.mul_assign(&tmp);
                val.add_assign(&coeff);
                tmp.mul_assign(&z_inv);
            }
        }

        txy[4 * n].sub_assign(&val);

        let poly = kate_divison(txy.iter(), z);

        let negative_poly = poly[0..4 * n].iter().rev();
        let positive_poly = poly[4 * n..].iter();
        multiexp(
            srs.g_negative_x[1..(negative_poly.len() + 1)]
                .iter()
                .chain_ext(srs.g_positive_x[0..positive_poly.len()].iter()),
            negative_poly.chain_ext(positive_poly),
        )
        .into_affine()
    };

    // US keys
    let usig = Schnorr;
    let (sk_l, pk_l): (SecretKey, PublicKey) = usig.kgen();
    let mut sk_ot: lamport_sigs::PrivateKey = lamport_sigs::PrivateKey::new(&SHA256);
    let pk_ot: lamport_sigs::PublicKey = sk_ot.public_key();

    // \Sigma.Sign(sk_l, pk_OT)
    // let pk_ot_message: Vec<u8> = pk_ot.to_bytes();
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    pk_ot.hash(&mut hasher);
    let pk_ot_hash = hasher.finish(); // outputs a u64

    let sigma: Signature = usig.sign(sk_l, pk_ot_hash);

    // encrypt the witness (circuit C)
    use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
    let message = GENERATOR_EXTENDED * circuit.to_scalar();
    // let message = curv::BigInt::from(0);
    let rand = JubJubScalar::random(&mut rand::thread_rng());
    let c: jubjub_elgamal::Cypher = srs.pk.encrypt(message, rand);

    let sonic_proof = SonicProof {
        r,
        rz,
        rzy,
        t,
        z_opening,
        zy_opening,
    };
    let message2: Vec<u8> = to_be_bytes(&sonic_proof, circuit, &c, &pk_l, sigma);
    let sigma_ot = sk_ot.sign(&message2[..]);

    Ok(Proof {
        c,
        r,
        rz,
        rzy,
        t,
        z_opening,
        zy_opening, // sonic proof (\pi_\Pi)
        pk_l,
        sigma,
        pk_ot,
        sigma_ot,
    })

    // zkV3 is in verification algorithm instead
}

/*
s(X, Y) =   \sum\limits_{i=1}^N \sum\limits_{q=1}^Q Y^{q+N} u_{i,q} X^{-i}
          + \sum\limits_{i=1}^N \sum\limits_{q=1}^Q Y^{q+N} v_{i,q} X^{i}
          + \sum\limits_{i=1}^N \sum\limits_{q=1}^Q Y^{q+N} w_{i,q} X^{i+N}
          - \sum\limits_{i=1}^N Y^i X^{i+N}
          - \sum\limits_{i=1}^N Y^{-i} X^{i+N}
*/
struct SyEval<E: Engine> {
    max_n: usize,
    current_q: usize,

    // x^{-1}, ..., x^{-N}
    a: Vec<E::Fr>,

    // x^1, ..., x^{N}
    b: Vec<E::Fr>,

    // x^{N+1}, ..., x^{2*N}
    c: Vec<E::Fr>,

    // coeffs for y^1, ..., y^{N+Q}
    positive_coeffs: Vec<E::Fr>,

    // coeffs for y^{-1}, y^{-2}, ..., y^{-N}
    negative_coeffs: Vec<E::Fr>,
}

impl<E: Engine> SyEval<E> {
    fn new(x: E::Fr, n: usize, q: usize) -> Self {
        let xinv = x.inverse().unwrap();
        let mut tmp = E::Fr::one();
        let mut a = vec![E::Fr::zero(); n];
        for a in &mut a {
            tmp.mul_assign(&xinv); // tmp = x^{-i}
            *a = tmp;
        }

        let mut tmp = E::Fr::one();
        let mut b = vec![E::Fr::zero(); n];
        for b in &mut b {
            tmp.mul_assign(&x); // tmp = x^{i}
            *b = tmp;
        }

        let mut positive_coeffs = vec![E::Fr::zero(); n + q];
        let mut negative_coeffs = vec![E::Fr::zero(); n];

        let mut c = vec![E::Fr::zero(); n];
        for ((c, positive_coeff), negative_coeff) in c
            .iter_mut()
            .zip(&mut positive_coeffs)
            .zip(&mut negative_coeffs)
        {
            tmp.mul_assign(&x); // tmp = x^{i+N}
            *c = tmp;

            // - \sum\limits_{i=1}^N Y^i X^{i+N}
            let mut tmp = tmp;
            tmp.negate();
            *positive_coeff = tmp;

            // - \sum\limits_{i=1}^N Y^{-i} X^{i+N}
            *negative_coeff = tmp;
        }

        SyEval {
            a,
            b,
            c,
            positive_coeffs,
            negative_coeffs,
            current_q: 0,
            max_n: n,
        }
    }

    fn poly(self) -> (Vec<E::Fr>, Vec<E::Fr>) {
        (self.negative_coeffs, self.positive_coeffs)
    }

    fn _finalize(self, y: E::Fr) -> E::Fr {
        let mut acc = E::Fr::zero();

        let mut tmp = y;
        for mut coeff in self.positive_coeffs {
            coeff.mul_assign(&tmp);
            acc.add_assign(&coeff);
            tmp.mul_assign(&y);
        }
        let yinv = y.inverse().unwrap(); // TODO
        let mut tmp = yinv;
        for mut coeff in self.negative_coeffs {
            coeff.mul_assign(&tmp);
            acc.add_assign(&coeff);
            tmp.mul_assign(&yinv);
        }

        acc
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SyEval<E> {
    type LinearConstraintIndex = usize;

    fn new_linear_constraint(&mut self) -> usize {
        self.current_q += 1;
        self.current_q
    }

    fn get_for_q(&self, q: usize) -> Self::LinearConstraintIndex {
        q
    }

    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>, q: &usize) {
        match var {
            Variable::A(index) => {
                let index = index - 1;
                // Y^{q+N} += X^{-i} * coeff
                let mut tmp = self.a[index];
                coeff.multiply(&mut tmp);
                let yindex = *q + self.max_n;
                self.positive_coeffs[yindex - 1].add_assign(&tmp);
            }
            Variable::B(index) => {
                let index = index - 1;
                // Y^{q+N} += X^{i} * coeff
                let mut tmp = self.b[index];
                coeff.multiply(&mut tmp);
                let yindex = *q + self.max_n;
                self.positive_coeffs[yindex - 1].add_assign(&tmp);
            }
            Variable::C(index) => {
                let index = index - 1;
                // Y^{q+N} += X^{i+N} * coeff
                let mut tmp = self.c[index];
                coeff.multiply(&mut tmp);
                let yindex = *q + self.max_n;
                self.positive_coeffs[yindex - 1].add_assign(&tmp);
            }
        };
    }
}

/*
s(X, Y) =   \sum\limits_{i=1}^N u_i(Y) X^{-i}
          + \sum\limits_{i=1}^N v_i(Y) X^{i}
          + \sum\limits_{i=1}^N w_i(Y) X^{i+N}

where

    u_i(Y) =        \sum\limits_{q=1}^Q Y^{q+N} u_{i,q}
    v_i(Y) =        \sum\limits_{q=1}^Q Y^{q+N} v_{i,q}
    w_i(Y) = -Y^i + -Y^{-i} + \sum\limits_{q=1}^Q Y^{q+N} w_{i,q}

*/
#[derive(Clone)]
struct SxEval<E: Engine> {
    y: E::Fr,

    // current value of y^{q+N}
    yqn: E::Fr,

    // x^{-i} (\sum\limits_{q=1}^Q y^{q+N} u_{q,i})
    u: Vec<E::Fr>,
    // x^{i} (\sum\limits_{q=1}^Q y^{q+N} v_{q,i})
    v: Vec<E::Fr>,
    // x^{i+N} (-y^i -y^{-i} + \sum\limits_{q=1}^Q y^{q+N} w_{q,i})
    w: Vec<E::Fr>,

    max_n: usize,
}

impl<E: Engine> SxEval<E> {
    fn new(y: E::Fr, n: usize) -> Self {
        let y_inv = y.inverse().unwrap(); // TODO

        let yqn = y.pow(&[n as u64]);

        let u = vec![E::Fr::zero(); n];
        let v = vec![E::Fr::zero(); n];
        let mut w = vec![E::Fr::zero(); n];

        let mut tmp1 = y;
        let mut tmp2 = y_inv;
        for w in &mut w {
            let mut new = tmp1;
            new.add_assign(&tmp2);
            new.negate();
            *w = new;
            tmp1.mul_assign(&y);
            tmp2.mul_assign(&y_inv);
        }

        SxEval {
            y,
            yqn,
            u,
            v,
            w,

            max_n: n,
        }
    }

    fn poly(mut self) -> (Vec<E::Fr>, Vec<E::Fr>) {
        self.v.extend(self.w);

        (self.u, self.v)
    }

    fn finalize(self, x: E::Fr) -> E::Fr {
        let x_inv = x.inverse().unwrap(); // TODO

        let mut tmp = x_inv;

        let mut acc = E::Fr::zero();
        for mut u in self.u {
            u.mul_assign(&tmp);
            acc.add_assign(&u);
            tmp.mul_assign(&x_inv);
        }

        let mut tmp = x;
        for mut v in self.v {
            v.mul_assign(&tmp);
            acc.add_assign(&v);
            tmp.mul_assign(&x);
        }
        for mut w in self.w {
            w.mul_assign(&tmp);
            acc.add_assign(&w);
            tmp.mul_assign(&x);
        }

        acc
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SxEval<E> {
    type LinearConstraintIndex = E::Fr;

    fn new_linear_constraint(&mut self) -> E::Fr {
        self.yqn.mul_assign(&self.y);
        self.yqn
    }

    fn get_for_q(&self, q: usize) -> Self::LinearConstraintIndex {
        self.y.pow(&[(self.max_n + q) as u64])
    }

    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>, y: &E::Fr) {
        let acc = match var {
            Variable::A(index) => &mut self.u[index - 1],
            Variable::B(index) => &mut self.v[index - 1],
            Variable::C(index) => &mut self.w[index - 1],
        };

        match coeff {
            Coeff::Zero => {}
            Coeff::One => {
                acc.add_assign(&y);
            }
            Coeff::NegativeOne => {
                acc.sub_assign(&y);
            }
            Coeff::Full(mut val) => {
                val.mul_assign(&y);
                acc.add_assign(&val);
            }
        }
    }
}

#[test]
#[ignore]
fn my_fun_circuit_test() {
    use super::*;
    use crate::synthesis::*;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;

    struct MyCircuit;

    impl<E: Engine> Circuit<E> for MyCircuit {
        fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
            let (a, b, _) = cs.multiply(|| {
                Ok((
                    E::Fr::from_str("10").unwrap(),
                    E::Fr::from_str("20").unwrap(),
                    E::Fr::from_str("200").unwrap(),
                ))
            })?;

            cs.enforce_zero(LinearCombination::from(a) + a - b);

            //let multiplier = cs.alloc_input(|| Ok(E::Fr::from_str("20").unwrap()))?;

            //cs.enforce_zero(LinearCombination::from(b) - multiplier);

            Ok(())
        }
    }
    impl Statement for MyCircuit {
        fn get_statement(&self) -> &[u8] {
            b""
        }
    }
    impl Scalarable for MyCircuit {
        fn to_scalar(&self) -> dusk_jubjub::JubJubScalar {
            dusk_jubjub::JubJubScalar::zero()
        }
    }

    let srs = SRS::<Bls12>::new(
        20,
        Fr::from_str("22222").unwrap(),
        Fr::from_str("33333333").unwrap(),
    );
    let proof = create_proof::<Bls12, _, Permutation3>(&MyCircuit, &srs).unwrap();

    use std::time::Instant;
    let start = Instant::now();
    let mut batch = MultiVerifier::<Bls12, _, Permutation3>::new(MyCircuit, &srs).unwrap();

    for _ in 0..1 {
        batch.add_proof(&proof, &[/*Fr::from_str("20").unwrap()*/], |_, _| None);
    }

    assert!(batch.check_all());

    let elapsed = start.elapsed();
    println!("time to verify: {:?}", elapsed);
}
