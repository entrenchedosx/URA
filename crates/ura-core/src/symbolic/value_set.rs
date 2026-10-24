//! Finite SSA value overapproximations, with explicit top/bottom and a hard
//! convergence bound. Finite facts never claim every listed value is reachable.
use crate::ir::{
    self,
    ssa::{SsaFunction, Use, Value},
    Constant, Operation, Type,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const SET_LIMIT: usize = 16;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Domain {
    Bottom,
    Finite { values: BTreeSet<ir::Address> },
    Top,
}
impl Domain {
    fn join(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bottom, b) | (b, Self::Bottom) => b.clone(),
            (Self::Finite { values: a }, Self::Finite { values: b }) => {
                let values: BTreeSet<_> = a.union(b).copied().collect();
                if values.len() > SET_LIMIT {
                    Self::Top
                } else {
                    Self::Finite { values }
                }
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub value: Value,
    pub ty: Type,
    pub domain: Domain,
    pub known_zero: ir::Address,
    pub known_one: ir::Address,
    pub unsigned_min: Option<ir::Address>,
    pub unsigned_max: Option<ir::Address>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub facts: Vec<Fact>,
    pub rounds: usize,
    pub converged: bool,
    pub scope: String,
}
pub fn analyze(f: &SsaFunction, control: &dyn crate::AnalysisControl) -> Analysis {
    let mut values = BTreeMap::new();
    for (variable, _) in f.variables.iter().enumerate() {
        values.insert(
            Value {
                variable,
                version: 0,
            },
            Domain::Top,
        );
    }
    for block in &f.blocks {
        for phi in &block.phis {
            values.insert(phi.output, Domain::Bottom);
        }
        for s in &block.statements {
            if let Some(v) = s.output {
                values.insert(v, Domain::Bottom);
            }
        }
    }
    let mut rounds = 0;
    let mut converged = false;
    let mut work = 0;
    'rounds: while rounds < 32 && !control.is_cancelled() {
        rounds += 1;
        let mut changed = false;
        for block in &f.blocks {
            for phi in &block.phis {
                if control.is_cancelled() || work >= 200_000 {
                    break 'rounds;
                }
                work += 1;
                let mut domain = Domain::Bottom;
                for value in phi.incoming.values().chain(phi.initial.iter()) {
                    domain = domain.join(values.get(value).unwrap_or(&Domain::Top));
                }
                changed |= update(&mut values, phi.output, domain);
            }
            for statement in &block.statements {
                if control.is_cancelled() || work >= 200_000 {
                    break 'rounds;
                }
                work += 1;
                if let Some(output) = statement.output {
                    let args: Vec<_> = statement.args.iter().map(|u| get(*u, &values)).collect();
                    let types: Vec<_> = statement
                        .args
                        .iter()
                        .map(|u| match u {
                            Use::Constant(c) => c.ty,
                            Use::Value(v) => f.variables[v.variable].ty,
                        })
                        .collect();
                    let domain = transfer(
                        &statement.op,
                        f.variables[output.variable].ty,
                        &args,
                        &types,
                        control,
                        &mut work,
                    );
                    changed |= update(&mut values, output, domain);
                }
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        for domain in values.values_mut() {
            *domain = Domain::Top;
        }
    }
    let facts = values
        .into_iter()
        .map(|(value, domain)| {
            let ty = f.variables[value.variable].ty;
            let mask = ir::mask(ty.width().unwrap_or(64));
            let (mut one, mut possible) = (mask, 0);
            let (mut min, mut max) = (None, None);
            if let Domain::Finite { values } = &domain {
                for address in values {
                    one &= address.0;
                    possible |= address.0;
                }
                min = values.first().copied();
                max = values.last().copied();
            } else {
                one = 0;
                possible = mask;
            }
            Fact {
                value,
                ty,
                domain,
                known_zero: ir::Address(!possible & mask),
                known_one: ir::Address(one),
                unsigned_min: min,
                unsigned_max: max,
            }
        })
        .collect();
    Analysis { facts, rounds, converged, scope: "path-insensitive finite overapproximation; all entry inputs arbitrary; no reachability/exact-set claim; nonconvergence widens every fact to top".into() }
}
fn update(values: &mut BTreeMap<Value, Domain>, value: Value, domain: Domain) -> bool {
    let joined = values.get(&value).unwrap_or(&Domain::Bottom).join(&domain);
    if values.get(&value) == Some(&joined) {
        false
    } else {
        values.insert(value, joined);
        true
    }
}
fn get(u: Use, values: &BTreeMap<Value, Domain>) -> Domain {
    match u {
        Use::Constant(c) => Domain::Finite {
            values: BTreeSet::from([c.value]),
        },
        Use::Value(v) => values.get(&v).cloned().unwrap_or(Domain::Top),
    }
}
fn transfer(
    op: &Operation,
    ty: Type,
    args: &[Domain],
    types: &[Type],
    control: &dyn crate::AnalysisControl,
    work: &mut usize,
) -> Domain {
    if *op == Operation::Select && args.len() == 3 {
        return match &args[0] {
            Domain::Bottom => Domain::Bottom,
            Domain::Finite { values } if values.iter().all(|v| v.0 == 0) => args[2].clone(),
            Domain::Finite { values } if values.iter().all(|v| v.0 == 1) => args[1].clone(),
            _ => args[1].join(&args[2]),
        };
    }
    if args.contains(&Domain::Bottom) {
        return Domain::Bottom;
    }
    if args.is_empty() || args.contains(&Domain::Top) || ty == Type::Memory {
        return Domain::Top;
    }
    let mut combinations = vec![Vec::new()];
    for (domain, ty) in args.iter().zip(types) {
        let Domain::Finite { values } = domain else {
            return Domain::Top;
        };
        if combinations.len() * values.len() > 256 {
            return Domain::Top;
        }
        combinations = combinations
            .into_iter()
            .flat_map(|prefix| {
                values.iter().map(move |v| {
                    let mut p = prefix.clone();
                    p.push(Constant { ty: *ty, value: *v });
                    p
                })
            })
            .collect();
    }
    let mut values = BTreeSet::new();
    for args in combinations {
        *work += 1;
        if control.is_cancelled() || *work >= 200_000 {
            return Domain::Top;
        }
        let Some(value) = ir::evaluate::pure(op, ty, &args) else {
            return Domain::Top;
        };
        values.insert(value.value);
        if values.len() > SET_LIMIT {
            return Domain::Top;
        }
    }
    Domain::Finite { values }
}
