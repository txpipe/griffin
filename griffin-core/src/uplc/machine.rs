use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::rc::Rc;

use crate::uplc::ast::{Constant, NamedDeBruijn, Term, Type};

pub mod cost_model;
mod discharge;
mod error;
pub mod eval_result;
pub mod runtime;
pub mod value;

use cost_model::{ExBudget, StepKind};
pub use error::Error;
use crate::pallas_primitives::conway::Language;

use self::{
    cost_model::CostModel,
    runtime::BuiltinRuntime,
    value::{Env, Value},
};

enum MachineState {
    Return(Context, Value),
    Compute(Context, Env, Term<NamedDeBruijn>),
    Done(Term<NamedDeBruijn>),
}

#[derive(Clone)]
enum Context {
    FrameAwaitArg(Value, Box<Context>),
    FrameAwaitFunTerm(Env, Term<NamedDeBruijn>, Box<Context>),
    FrameAwaitFunValue(Value, Box<Context>),
    FrameForce(Box<Context>),
    FrameConstr(
        Env,
        usize,
        Vec<Term<NamedDeBruijn>>,
        Vec<Value>,
        Box<Context>,
    ),
    FrameCases(Env, Vec<Term<NamedDeBruijn>>, Box<Context>),
    NoFrame,
}

pub struct Machine {
    costs: CostModel,
    pub ex_budget: ExBudget,
    slippage: u32,
    unbudgeted_steps: [u32; 10],
    pub logs: Vec<String>,
    version: Language,
}

impl Machine {
    pub fn new(
        version: Language,
        costs: CostModel,
        initial_budget: ExBudget,
        slippage: u32,
    ) -> Machine {
        Machine {
            costs,
            ex_budget: initial_budget,
            slippage,
            unbudgeted_steps: [0; 10],
            logs: vec![],
            version,
        }
    }

    pub fn run(&mut self, term: Term<NamedDeBruijn>) -> Result<Term<NamedDeBruijn>, Error> {
        use MachineState::*;

        let startup_budget = self.costs.machine_costs.get(StepKind::StartUp);

        self.spend_budget(startup_budget)?;

        let mut state = Compute(Context::NoFrame, Rc::new(vec![]), term);

        loop {
            state = match state {
                Compute(context, env, t) => self.compute(context, env, t)?,
                Return(context, value) => self.return_compute(context, value)?,
                Done(t) => {
                    return Ok(t);
                }
            };
        }
    }

    fn compute(
        &mut self,
        context: Context,
        env: Env,
        term: Term<NamedDeBruijn>,
    ) -> Result<MachineState, Error> {
        match term {
            Term::Var(name) => {
                self.step_and_maybe_spend(StepKind::Var)?;

                let val = self.lookup_var(name.as_ref(), &env)?;

                Ok(MachineState::Return(context, val))
            }
            Term::Delay(body) => {
                self.step_and_maybe_spend(StepKind::Delay)?;

                Ok(MachineState::Return(context, Value::Delay(body, env)))
            }
            Term::Lambda {
                parameter_name,
                body,
            } => {
                self.step_and_maybe_spend(StepKind::Lambda)?;

                Ok(MachineState::Return(
                    context,
                    Value::Lambda {
                        parameter_name,
                        body,
                        env,
                    },
                ))
            }
            Term::Apply { function, argument } => {
                self.step_and_maybe_spend(StepKind::Apply)?;

                Ok(MachineState::Compute(
                    Context::FrameAwaitFunTerm(
                        env.clone(),
                        argument.as_ref().clone(),
                        context.into(),
                    ),
                    env,
                    function.as_ref().clone(),
                ))
            }
            Term::Constant(x) => {
                self.step_and_maybe_spend(StepKind::Constant)?;

                Ok(MachineState::Return(context, Value::Con(x)))
            }
            Term::Force(body) => {
                self.step_and_maybe_spend(StepKind::Force)?;

                Ok(MachineState::Compute(
                    Context::FrameForce(context.into()),
                    env,
                    body.as_ref().clone(),
                ))
            }
            Term::Error => Err(Error::EvaluationFailure),
            Term::Builtin(fun) => {
                self.step_and_maybe_spend(StepKind::Builtin)?;

                let runtime: BuiltinRuntime = fun.into();

                Ok(MachineState::Return(
                    context,
                    Value::Builtin { fun, runtime },
                ))
            }
            Term::Constr { tag, mut fields } => {
                self.step_and_maybe_spend(StepKind::Constr)?;

                fields.reverse();

                if !fields.is_empty() {
                    let popped_field = fields.pop().unwrap();

                    Ok(MachineState::Compute(
                        Context::FrameConstr(env.clone(), tag, fields, vec![], context.into()),
                        env,
                        popped_field,
                    ))
                } else {
                    Ok(MachineState::Return(
                        context,
                        Value::Constr {
                            tag,
                            fields: vec![],
                        },
                    ))
                }
            }
            Term::Case { constr, branches } => {
                self.step_and_maybe_spend(StepKind::Case)?;

                Ok(MachineState::Compute(
                    Context::FrameCases(env.clone(), branches, context.into()),
                    env,
                    constr.as_ref().clone(),
                ))
            }
        }
    }

    fn return_compute(&mut self, context: Context, value: Value) -> Result<MachineState, Error> {
        match context {
            Context::NoFrame => {
                if self.unbudgeted_steps[9] > 0 {
                    self.spend_unbudgeted_steps()?;
                }

                let term = discharge::value_as_term(value);

                Ok(MachineState::Done(term))
            }
            Context::FrameForce(ctx) => self.force_evaluate(*ctx, value),
            Context::FrameAwaitFunTerm(arg_env, arg, ctx) => Ok(MachineState::Compute(
                Context::FrameAwaitArg(value, ctx),
                arg_env,
                arg,
            )),
            Context::FrameAwaitArg(fun, ctx) => self.apply_evaluate(*ctx, fun, value),
            Context::FrameAwaitFunValue(arg, ctx) => self.apply_evaluate(*ctx, value, arg),
            Context::FrameConstr(env, tag, mut fields, mut resolved_fields, ctx) => {
                resolved_fields.push(value);

                if !fields.is_empty() {
                    let popped_field = fields.pop().unwrap();

                    Ok(MachineState::Compute(
                        Context::FrameConstr(env.clone(), tag, fields, resolved_fields, ctx),
                        env,
                        popped_field,
                    ))
                } else {
                    Ok(MachineState::Return(
                        *ctx,
                        Value::Constr {
                            tag,
                            fields: resolved_fields,
                        },
                    ))
                }
            }
            Context::FrameCases(env, branches, ctx) => match value {
                Value::Constr { tag, fields } => match branches.get(tag) {
                    Some(t) => Ok(MachineState::Compute(
                        transfer_arg_stack(fields, *ctx),
                        env,
                        t.clone(),
                    )),
                    None => Err(Error::MissingCaseBranch(
                        branches,
                        Value::Constr { tag, fields },
                    )),
                },
                v => Err(Error::NonConstrScrutinized(v)),
            },
        }
    }

    fn force_evaluate(&mut self, context: Context, value: Value) -> Result<MachineState, Error> {
        match value {
            Value::Delay(body, env) => {
                Ok(MachineState::Compute(context, env, body.as_ref().clone()))
            }
            Value::Builtin { fun, mut runtime } => {
                if runtime.needs_force() {
                    runtime.consume_force();

                    let res = if runtime.is_ready() {
                        self.eval_builtin_app(runtime)?
                    } else {
                        Value::Builtin { fun, runtime }
                    };

                    Ok(MachineState::Return(context, res))
                } else {
                    let term = discharge::value_as_term(Value::Builtin { fun, runtime });

                    Err(Error::BuiltinTermArgumentExpected(term))
                }
            }
            rest => Err(Error::NonPolymorphicInstantiation(rest)),
        }
    }

    fn apply_evaluate(
        &mut self,
        context: Context,
        function: Value,
        argument: Value,
    ) -> Result<MachineState, Error> {
        match function {
            Value::Lambda { body, mut env, .. } => {
                let e = Rc::make_mut(&mut env);

                e.push(argument);

                Ok(MachineState::Compute(
                    context,
                    Rc::new(e.clone()),
                    body.as_ref().clone(),
                ))
            }
            Value::Builtin { fun, runtime } => {
                if runtime.is_arrow() && !runtime.needs_force() {
                    let mut runtime = runtime;

                    runtime.push(argument)?;

                    let res = if runtime.is_ready() {
                        self.eval_builtin_app(runtime)?
                    } else {
                        Value::Builtin { fun, runtime }
                    };

                    Ok(MachineState::Return(context, res))
                } else {
                    let term = discharge::value_as_term(Value::Builtin { fun, runtime });

                    Err(Error::UnexpectedBuiltinTermArgument(term))
                }
            }
            rest => Err(Error::NonFunctionalApplication(rest, argument)),
        }
    }

    fn eval_builtin_app(&mut self, runtime: BuiltinRuntime) -> Result<Value, Error> {
        let cost = runtime.to_ex_budget(&self.costs.builtin_costs);

        self.spend_budget(cost)?;

        runtime.call(&self.version, &mut self.logs)
    }

    fn lookup_var(&mut self, name: &NamedDeBruijn, env: &[Value]) -> Result<Value, Error> {
        env.get::<usize>(env.len() - usize::from(name.index))
            .cloned()
            .ok_or_else(|| Error::OpenTermEvaluated(Term::Var(name.clone().into())))
    }

    fn step_and_maybe_spend(&mut self, step: StepKind) -> Result<(), Error> {
        let index = step as u8;
        self.unbudgeted_steps[index as usize] += 1;
        self.unbudgeted_steps[9] += 1;

        if self.unbudgeted_steps[9] >= self.slippage {
            self.spend_unbudgeted_steps()?;
        }

        Ok(())
    }

    fn spend_unbudgeted_steps(&mut self) -> Result<(), Error> {
        for i in 0..self.unbudgeted_steps.len() - 1 {
            let mut unspent_step_budget =
                self.costs.machine_costs.get(StepKind::try_from(i as u8)?);

            unspent_step_budget.occurrences(self.unbudgeted_steps[i] as i64);

            self.spend_budget(unspent_step_budget)?;

            self.unbudgeted_steps[i] = 0;
        }

        self.unbudgeted_steps[9] = 0;

        Ok(())
    }

    fn spend_budget(&mut self, spend_budget: ExBudget) -> Result<(), Error> {
        self.ex_budget.mem -= spend_budget.mem;
        self.ex_budget.cpu -= spend_budget.cpu;

        if self.ex_budget.mem < 0 || self.ex_budget.cpu < 0 {
            Err(Error::OutOfExError(self.ex_budget))
        } else {
            Ok(())
        }
    }
}

fn transfer_arg_stack(mut args: Vec<Value>, ctx: Context) -> Context {
    if args.is_empty() {
        ctx
    } else {
        let popped_field = args.pop().unwrap();

        transfer_arg_stack(args, Context::FrameAwaitFunValue(popped_field, ctx.into()))
    }
}

impl From<&Constant> for Type {
    fn from(constant: &Constant) -> Self {
        match constant {
            Constant::Integer(_) => Type::Integer,
            Constant::ByteString(_) => Type::ByteString,
            Constant::String(_) => Type::String,
            Constant::Unit => Type::Unit,
            Constant::Bool(_) => Type::Bool,
            Constant::ProtoList(t, _) => Type::List(Rc::new(t.clone())),
            Constant::ProtoPair(t1, t2, _, _) => {
                Type::Pair(Rc::new(t1.clone()), Rc::new(t2.clone()))
            }
            Constant::Data(_) => Type::Data,
            Constant::Bls12_381G1Element(_) => Type::Bls12_381G1Element,
            Constant::Bls12_381G2Element(_) => Type::Bls12_381G2Element,
            Constant::Bls12_381MlResult(_) => Type::Bls12_381MlResult,
        }
    }
}