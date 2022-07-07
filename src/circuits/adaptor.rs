extern crate bellman;
use crate::{
    Circuit, Coeff, ConstraintSystem, LinearCombination, Statement, SynthesisError, Variable,
    WitnessScalar,
};
use pairing::{Engine, Field};
use std::marker::PhantomData;

struct Adaptor<'a, E: Engine, CS: ConstraintSystem<E> + 'a> {
    cs: &'a mut CS,
    _marker: PhantomData<E>,
}

// implements bellman::ConstraintSystem<Scalar: PrimeField> trait for Adaptor struct
// defined above
// https://docs.rs/bellman/0.11.1/bellman/trait.ConstraintSystem.html
impl<'a, E: Engine, CS: ConstraintSystem<E> + 'a> bellman::ConstraintSystem<E>
    for Adaptor<'a, E, CS>
{
    type Root = Self;

    fn one() -> bellman::Variable {
        bellman::Variable::new_unchecked(bellman::Index::Input(1))
    }

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<bellman::Variable, bellman::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = self
            .cs
            .alloc(|| f().map_err(|_| SynthesisError::AssignmentMissing))
            .map_err(|_| bellman::SynthesisError::AssignmentMissing)?;

        Ok(match var {
            Variable::A(index) => bellman::Variable::new_unchecked(bellman::Index::Input(index)),
            Variable::B(index) => bellman::Variable::new_unchecked(bellman::Index::Aux(index)),
            _ => unreachable!(),
        })
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _: A,
        f: F,
    ) -> Result<bellman::Variable, bellman::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = self
            .cs
            .alloc_input(|| f().map_err(|_| SynthesisError::AssignmentMissing))
            .map_err(|_| bellman::SynthesisError::AssignmentMissing)?;

        Ok(match var {
            Variable::A(index) => bellman::Variable::new_unchecked(bellman::Index::Input(index)),
            Variable::B(index) => bellman::Variable::new_unchecked(bellman::Index::Aux(index)),
            _ => unreachable!(),
        })
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
        LB: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
        LC: FnOnce(bellman::LinearCombination<E>) -> bellman::LinearCombination<E>,
    {
        fn convert<E: Engine>(lc: bellman::LinearCombination<E>) -> LinearCombination<E> {
            let mut ret = LinearCombination::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let var = match v.get_unchecked() {
                    bellman::Index::Input(i) => Variable::A(i),
                    bellman::Index::Aux(i) => Variable::B(i),
                };

                ret = ret + (Coeff::Full(coeff), var);
            }

            ret
        }

        fn eval<E: Engine, CS: ConstraintSystem<E>>(
            lc: &LinearCombination<E>,
            cs: &CS,
        ) -> Option<E::Fr> {
            let mut ret = E::Fr::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let mut tmp = match cs.get_value(v) {
                    Ok(tmp) => tmp,
                    Err(_) => return None,
                };
                coeff.multiply(&mut tmp);
                ret.add_assign(&tmp);
            }

            Some(ret)
        }

        let a_lc = convert(a(bellman::LinearCombination::zero()));
        let a_value = eval(&a_lc, &*self.cs);
        let b_lc = convert(b(bellman::LinearCombination::zero()));
        let b_value = eval(&b_lc, &*self.cs);
        let c_lc = convert(c(bellman::LinearCombination::zero()));
        let c_value = eval(&c_lc, &*self.cs);

        let (a, b, c) = self
            .cs
            .multiply(|| Ok((a_value.unwrap(), b_value.unwrap(), c_value.unwrap())))
            .unwrap();

        self.cs.enforce_zero(a_lc - a);
        self.cs.enforce_zero(b_lc - b);
        self.cs.enforce_zero(c_lc - c);
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

pub struct AdaptorCircuit<T>(pub T);

// implement sonic_ucse::Circuit trait (lib.rs:16) for AdaptorCircuit struct defined above
impl<'a, E: Engine, C: bellman::Circuit<E> + Clone> Circuit<E> for AdaptorCircuit<C> {
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut adaptor = Adaptor {
            cs: cs,
            _marker: PhantomData,
        };

        match self.0.clone().synthesize(&mut adaptor) {
            Err(_) => return Err(SynthesisError::AssignmentMissing),
            Ok(_) => {}
        };

        Ok(())
    }
}
impl<C: WitnessScalar> WitnessScalar for AdaptorCircuit<C> {
    fn get_witness_scalar(&self) -> dusk_jubjub::JubJubScalar {
        self.0.get_witness_scalar()
    }
}
impl<C: Statement> Statement for AdaptorCircuit<C> {
    // fn get_statement(&self) -> T {
    //     self.0.get_statement()
    // }
    fn get_statement_bytes(&self) -> &[u8] {
        self.0.get_statement_bytes()
    }
}
