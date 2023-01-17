use dusk_jubjub;
use pairing::{Engine, Field};
use std::ops::{Add, Neg, Sub};

pub mod batch;
pub mod circuits;
pub mod dlog;
pub mod kupke;
pub mod protocol;
pub mod schnorrots;
pub mod srs;
pub mod synthesis;
pub mod usig;
pub mod util;

pub fn usage() {
    println!("Usage: cargo run --example [example name] -- [pedersen | sha256] [preimage bitsize] [samples]");
}
pub fn parse_config(args: &[String]) -> Result<(&str, usize, usize), &'static str> {
    // default values
    let mut circuit_name = "pedersen";
    let mut preimage_bits_num = 48;
    let mut samples_num = 5;
    if args.len() != 1 && args.len() != 4 {
        return Err("improper number of arguments");
    }
    if args.len() == 4 {
        circuit_name = &args[1];
        let preimage_bits = &args[2];
        preimage_bits_num = match circuit_name {
            "pedersen" =>
                match preimage_bits.parse() {
                    Ok(48) => { 48 },
                    Ok(384) => { 384 },
                    Ok(_) => {
                        return Err("Pedersen preimage bitsize must be 48 or 384");
                    },
                    Err(_) => {
                        return Err("second argument must be an integer");
                    }
                },
            "sha256" =>
                match preimage_bits.parse() {
                    Ok(512) => { 512 },
                    Ok(1024) => { 1024 },
                    Ok(2048) => { 2048 },
                    Ok(_) => {
                        return Err("SHA256 preimage bitsize must be 512, 1024, or 2048");
                    },
                    Err(_) => {
                        return Err("second argument must be an integer");
                    }
                },
            _ => { return Err("invalid circuit name"); },
        };
        let samples = &args[3];
        samples_num = match samples.parse() {
            // options should be 5, 10
            Ok(n) => { n },
            Err(_) => {
                return Err("third argument must be an integer");
            }
        };
    }

    Ok((circuit_name, preimage_bits_num, samples_num))
}

#[derive(Copy, Clone, Debug)]
pub enum SynthesisError {
    AssignmentMissing,
    Violation,
}

pub trait BigIntable {
    fn to_big_int(&self) -> curv::BigInt;
}
pub trait Statement {
    // fn get_statement<T>(&self) -> T;
    fn get_statement_bytes(&self) -> &[u8];
}
pub trait Witness {
    fn get_witness_bytes(&self) -> Vec<Option<bool>>;
}
pub trait WitnessScalar {
    fn get_witness_scalar(&self) -> Vec<dusk_jubjub::JubJubScalar>;
}

pub trait Circuit<E: Engine> {
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}

pub trait ConstraintSystem<E: Engine> {
    const ONE: Variable;

    fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>;

    fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>;

    fn enforce_zero(&mut self, lc: LinearCombination<E>);

    fn multiply<F>(&mut self, values: F) -> Result<(Variable, Variable, Variable), SynthesisError>
    where
        F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>;

    // TODO: get rid of this
    fn get_value(&self, _var: Variable) -> Result<E::Fr, ()> {
        Err(())
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Variable {
    A(usize),
    B(usize),
    C(usize),
}

impl Variable {
    fn get_index(&self) -> usize {
        match *self {
            Variable::A(index) => index,
            Variable::B(index) => index,
            Variable::C(index) => index,
        }
    }
}

#[derive(Debug)]
pub enum Coeff<E: Engine> {
    Zero,
    One,
    NegativeOne,
    Full(E::Fr),
}

impl<E: Engine> Coeff<E> {
    pub fn multiply(&self, with: &mut E::Fr) {
        match self {
            Coeff::Zero => {
                *with = E::Fr::zero();
            }
            Coeff::One => {}
            Coeff::NegativeOne => {
                with.negate();
            }
            Coeff::Full(val) => {
                with.mul_assign(val);
            }
        }
    }
}

impl<E: Engine> Copy for Coeff<E> {}
impl<E: Engine> Clone for Coeff<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: Engine> Neg for Coeff<E> {
    type Output = Coeff<E>;

    fn neg(self) -> Self {
        match self {
            Coeff::Zero => Coeff::Zero,
            Coeff::One => Coeff::NegativeOne,
            Coeff::NegativeOne => Coeff::One,
            Coeff::Full(mut a) => {
                a.negate();
                Coeff::Full(a)
            }
        }
    }
}

/// This represents a linear combination of some variables, with coefficients
/// in the scalar field of a pairing-friendly elliptic curve group.
#[derive(Clone)]
pub struct LinearCombination<E: Engine>(Vec<(Variable, Coeff<E>)>);

impl<E: Engine> From<Variable> for LinearCombination<E> {
    fn from(var: Variable) -> LinearCombination<E> {
        LinearCombination::<E>::zero() + var
    }
}

impl<E: Engine> AsRef<[(Variable, Coeff<E>)]> for LinearCombination<E> {
    fn as_ref(&self) -> &[(Variable, Coeff<E>)] {
        &self.0
    }
}

impl<E: Engine> LinearCombination<E> {
    pub fn zero() -> LinearCombination<E> {
        LinearCombination(vec![])
    }
}

impl<E: Engine> Add<(Coeff<E>, Variable)> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, (coeff, var): (Coeff<E>, Variable)) -> LinearCombination<E> {
        self.0.push((var, coeff));

        self
    }
}

impl<E: Engine> Sub<(Coeff<E>, Variable)> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(self, (coeff, var): (Coeff<E>, Variable)) -> LinearCombination<E> {
        self + (-coeff, var)
    }
}

impl<E: Engine> Add<Variable> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(self, other: Variable) -> LinearCombination<E> {
        self + (Coeff::One, other)
    }
}

impl<E: Engine> Sub<Variable> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(self, other: Variable) -> LinearCombination<E> {
        self - (Coeff::One, other)
    }
}

impl<'a, E: Engine> Add<&'a LinearCombination<E>> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, other: &'a LinearCombination<E>) -> LinearCombination<E> {
        for s in &other.0 {
            self = self + (s.1, s.0);
        }

        self
    }
}

impl<'a, E: Engine> Sub<&'a LinearCombination<E>> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(mut self, other: &'a LinearCombination<E>) -> LinearCombination<E> {
        for s in &other.0 {
            self = self - (s.1, s.0);
        }

        self
    }
}
