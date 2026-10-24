//! Optional solver-backed overlap checks. The persistent memory array remains
//! authoritative even when alias classification is unknown.
use super::{
    expr::{Arena, Id, Sort},
    solver::{Backend, Limits, Outcome, Query, Status},
};
use crate::{ir::Operation, AnalysisControl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Classification {
    Same,
    Disjoint,
    PotentialAlias,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub classification: Classification,
    pub reason: String,
    pub queries: Vec<(Vec<Id>, Outcome)>,
    pub expressions: Arena,
}
pub fn classify(
    mut arena: Arena,
    left: (Id, u16),
    right: (Id, u16),
    assumptions: &[Id],
    limits: Limits,
    backend: &dyn Backend,
    control: &dyn AnalysisControl,
) -> Result<Evidence, String> {
    arena.rebuild()?;
    limits.validate()?;
    if assumptions.len() > 128 || !(1..=8).contains(&left.1) || !(1..=8).contains(&right.1) {
        return Err("alias query bounds".into());
    }
    let Sort::Bits(width @ (32 | 64)) = arena.sort(left.0)? else {
        return Err("alias pointer width".into());
    };
    if arena.sort(right.0)? != Sort::Bits(width) {
        return Err("alias pointer width mismatch".into());
    }
    let mut queries = Vec::new();
    let mut ask = |arena: &Arena, extra: Option<Id>| {
        let mut assertions = assumptions.to_vec();
        assertions.extend(extra);
        let outcome = backend.query(
            Query {
                arena: arena.clone(),
                assertions: assertions.clone(),
                observables: BTreeMap::new(),
                limits: limits.clone(),
            },
            control,
        );
        let status = outcome.status;
        queries.push((assertions, outcome));
        status
    };
    let mut result = Classification::Unknown;
    let mut reason = "infeasible, unsupported or unresolved assumptions";
    if ask(&arena, None) == Status::Sat {
        let mut ends = Vec::new();
        let mut wraps = Vec::new();
        for (address, bytes) in [left, right] {
            let increment = arena.constant(width, u64::from(bytes - 1))?;
            let end = arena.pure(Operation::Add, width, vec![address, increment])?;
            wraps.push(arena.pure(Operation::UnsignedLess, 1, vec![end, address])?);
            ends.push(end);
        }
        let wrap = arena.pure(Operation::Or, 1, wraps)?;
        if ask(&arena, Some(wrap)) == Status::Unsat {
            let same = arena.pure(Operation::Equal, 1, vec![left.0, right.0])?;
            let different = arena.condition(same, false)?;
            if left.1 == right.1 && ask(&arena, Some(different)) == Status::Unsat {
                result = Classification::Same;
                reason = "same start and byte length under satisfiable assumptions";
            } else {
                let before = arena.pure(Operation::UnsignedLess, 1, vec![ends[0], right.0])?;
                let after = arena.pure(Operation::UnsignedLess, 1, vec![ends[1], left.0])?;
                let disjoint = arena.pure(Operation::Or, 1, vec![before, after])?;
                let overlap = arena.condition(disjoint, false)?;
                match (ask(&arena, Some(overlap)), ask(&arena, Some(disjoint))) {
                    (Status::Unsat, Status::Sat) => {
                        result = Classification::Disjoint;
                        reason = "byte ranges cannot overlap under satisfiable assumptions";
                    }
                    (Status::Sat, _) => {
                        result = Classification::PotentialAlias;
                        reason = "overlap is feasible; stores must retain alias dependencies";
                    }
                    _ => reason = "solver could not classify range overlap",
                }
            }
        } else {
            reason = "pointer-width wraparound is possible or unresolved";
        }
    }
    Ok(Evidence {
        classification: result,
        reason: reason.into(),
        queries,
        expressions: arena,
    })
}
