use super::*;
use crate::analysis::AnalysisControl;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Bundle {
    pub raw: Function,
    pub ssa: ssa::SsaFunction,
    pub dataflow: dataflow::Dataflow,
}
pub fn analyze(
    binary: &crate::LoadedBinary,
    analysis: &crate::ProgramAnalysis,
    address: u64,
    control: &dyn AnalysisControl,
) -> Result<Bundle, String> {
    let raw = lift_function(binary, analysis, address, control)?;
    if control.is_cancelled() {
        return Err("IR analysis cancelled".into());
    }
    let ssa = ssa::construct_with_control(&raw, control)?;
    if control.is_cancelled() {
        return Err("IR analysis cancelled".into());
    }
    let dataflow = dataflow::analyze_with_control(&ssa, control)?;
    Ok(Bundle { raw, ssa, dataflow })
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "operation", rename_all = "camelCase")]
pub enum Detail {
    Block,
    Raw(Statement),
    RawTerminator(Terminator),
    Phi(ssa::Phi),
    Ssa(ssa::SsaStatement),
    SsaTerminator(ssa::SsaTerminator),
}
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub block: Address,
    pub source: Address,
    pub text: String,
    pub unsupported: bool,
    pub detail: Detail,
}
pub fn type_name(ty: Type) -> String {
    match ty {
        Type::Bits(w) => format!("u{w}"),
        Type::Address(w) => format!("addr{w}"),
        Type::Memory => "memory".into(),
    }
}
fn constant(c: Constant) -> String {
    format!("{}:{}", c.value, type_name(c.ty))
}
fn raw_operand(f: &Function, o: Operand) -> String {
    match o {
        Operand::Constant(c) => constant(c),
        Operand::Variable(v) => format!("{}:{}", f.variables[v].name, type_name(f.variables[v].ty)),
    }
}
fn ssa_value(f: &Function, v: ssa::Value) -> String {
    format!(
        "{}.{}:{}",
        f.variables[v.variable].name,
        v.version,
        type_name(f.variables[v.variable].ty)
    )
}
fn use_value(f: &Function, u: ssa::Use) -> String {
    match u {
        ssa::Use::Value(v) => ssa_value(f, v),
        ssa::Use::Constant(c) => constant(c),
    }
}
impl Bundle {
    pub fn row_variables(&self, rows: &[Row]) -> BTreeMap<usize, Variable> {
        let mut ids = std::collections::BTreeSet::new();
        let mut operand = |o: Operand| {
            if let Operand::Variable(v) = o {
                ids.insert(v);
            }
        };
        for row in rows {
            match &row.detail {
                Detail::Block => {}
                Detail::Raw(s) => {
                    for a in &s.args {
                        operand(*a);
                    }
                    if let Some(v) = s.output {
                        operand(Operand::Variable(v));
                    }
                }
                Detail::RawTerminator(t) => {
                    for a in t.state.iter().chain(t.value.iter()) {
                        operand(*a);
                    }
                }
                Detail::Phi(p) => {
                    for v in p
                        .incoming
                        .values()
                        .copied()
                        .chain(p.initial)
                        .chain(std::iter::once(p.output))
                    {
                        operand(Operand::Variable(v.variable));
                    }
                }
                Detail::Ssa(s) => {
                    for a in &s.args {
                        if let ssa::Use::Value(v) = a {
                            operand(Operand::Variable(v.variable));
                        }
                    }
                    if let Some(v) = s.output {
                        operand(Operand::Variable(v.variable));
                    }
                }
                Detail::SsaTerminator(t) => {
                    for a in t.state.iter().chain(t.value.iter()) {
                        if let ssa::Use::Value(v) = a {
                            operand(Operand::Variable(v.variable));
                        }
                    }
                }
            }
        }
        ids.into_iter()
            .map(|v| (v, self.raw.variables[v].clone()))
            .collect()
    }
    pub fn row_count(&self, ssa: bool) -> usize {
        if ssa {
            self.ssa
                .blocks
                .iter()
                .map(|b| 2 + b.phis.len() + b.statements.len())
                .sum()
        } else {
            self.raw.blocks.iter().map(|b| 2 + b.statements.len()).sum()
        }
    }
    /// Only formats/clones the requested rows; a headless page does not duplicate
    /// the full function or its variable catalogue.
    pub fn rows(&self, representation_ssa: bool, offset: usize, limit: usize) -> Vec<Row> {
        let mut rows = Vec::new();
        let mut cursor = 0usize;
        let mut add = |block: Address,
                       source: Address,
                       unsupported: bool,
                       render: &mut dyn FnMut() -> (String, Detail)| {
            if cursor >= offset && rows.len() < limit {
                let (text, detail) = render();
                rows.push(Row {
                    block,
                    source,
                    text,
                    unsupported,
                    detail,
                });
            }
            cursor += 1;
        };
        if representation_ssa {
            for block in &self.ssa.blocks {
                let b = block.address;
                add(b, b, false, &mut || (format!("block {b}:"), Detail::Block));
                for phi in &block.phis {
                    add(b, b, false, &mut || {
                        (
                            format!(
                                "{} = phi({})",
                                ssa_value(&self.raw, phi.output),
                                phi.incoming
                                    .iter()
                                    .map(|(p, v)| format!("{p}: {}", ssa_value(&self.raw, *v)))
                                    .chain(
                                        phi.initial
                                            .map(|v| format!("entry: {}", ssa_value(&self.raw, v)))
                                    )
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            Detail::Phi(phi.clone()),
                        )
                    });
                }
                for s in &block.statements {
                    add(
                        b,
                        s.source,
                        matches!(s.op, Operation::Barrier { .. }),
                        &mut || {
                            (
                                format!(
                                    "{}{:?}({})",
                                    s.output
                                        .map(|v| format!("{} = ", ssa_value(&self.raw, v)))
                                        .unwrap_or_default(),
                                    s.op,
                                    s.args
                                        .iter()
                                        .map(|a| use_value(&self.raw, *a))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                                Detail::Ssa(s.clone()),
                            )
                        },
                    );
                }
                let t = &block.terminator;
                add(
                    b,
                    t.flow.source,
                    t.flow.kind == FlowKind::Unresolved,
                    &mut || {
                        (
                            format!(
                                "{:?} {} -> {:?}; exits {:?}",
                                t.flow.kind,
                                t.value.map(|v| use_value(&self.raw, v)).unwrap_or_default(),
                                t.flow.successors,
                                t.flow.exits
                            ),
                            Detail::SsaTerminator(t.clone()),
                        )
                    },
                );
            }
        } else {
            for block in &self.raw.blocks {
                let b = block.address;
                add(b, b, false, &mut || (format!("block {b}:"), Detail::Block));
                for s in &block.statements {
                    add(
                        b,
                        s.source,
                        matches!(s.op, Operation::Barrier { .. }),
                        &mut || {
                            (
                                format!(
                                    "{}{:?}({})",
                                    s.output
                                        .map(|v| format!(
                                            "{}:{} = ",
                                            self.raw.variables[v].name,
                                            type_name(self.raw.variables[v].ty)
                                        ))
                                        .unwrap_or_default(),
                                    s.op,
                                    s.args
                                        .iter()
                                        .map(|a| raw_operand(&self.raw, *a))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                                Detail::Raw(s.clone()),
                            )
                        },
                    );
                }
                let t = &block.terminator;
                add(b, t.source, t.kind == FlowKind::Unresolved, &mut || {
                    (
                        format!(
                            "{:?} {} -> {:?}; exits {:?}",
                            t.kind,
                            t.value
                                .map(|v| raw_operand(&self.raw, v))
                                .unwrap_or_default(),
                            t.successors,
                            t.exits
                        ),
                        Detail::RawTerminator(t.clone()),
                    )
                });
            }
        }
        rows
    }
}
