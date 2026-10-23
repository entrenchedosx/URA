//! Bounded, conservative stack provenance from shared SSA. Only exact copies
//! and constant offsets from the incoming SP establish physical stack slots.
use super::{
    signature::CallingConvention,
    stack::{StackAccess, StackFrame, StackSlot},
    types::{Confidence, TypeRef},
};
use crate::{
    ir::{
        self,
        ssa::{SsaFunction, Use, Value},
        Operation, VariableKind,
    },
    processor::Processor,
    AnalysisControl,
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Affine {
    Stack(i64),
    Constant(i64),
}
struct Solver<'a> {
    f: &'a SsaFunction,
    sp: usize,
    defs: BTreeMap<Value, (Option<Operation>, Vec<Use>)>,
    cache: BTreeMap<Value, Option<Affine>>,
    visiting: BTreeSet<Value>,
    budget: usize,
    partial: bool,
}
impl Solver<'_> {
    fn get(&mut self, u: Use, depth: usize) -> Option<Affine> {
        let v = match u {
            Use::Constant(c) => {
                let w = c.ty.width()?;
                return Some(Affine::Constant(
                    ((c.value.0 << (64 - w)) as i64) >> (64 - w),
                ));
            }
            Use::Value(v) => v,
        };
        if v.version == 0 {
            return (v.variable == self.sp).then_some(Affine::Stack(0));
        }
        if let Some(result) = self.cache.get(&v) {
            return *result;
        }
        if depth > 64 || self.budget == 0 {
            self.partial = true;
            return None;
        }
        if !self.visiting.insert(v) {
            return None;
        }
        self.budget -= 1;
        let result = (|| {
            let (op, args) = self.defs.get(&v)?.clone();
            if matches!(
                op,
                Some(Operation::Copy | Operation::ToAddress | Operation::ToBits)
            ) {
                return self.get(*args.first()?, depth + 1);
            }
            if matches!(op, Some(Operation::Add | Operation::Sub)) && args.len() == 2 {
                let a = self.get(args[0], depth + 1)?;
                let b = self.get(args[1], depth + 1)?;
                let sub = op == Some(Operation::Sub);
                return match (a, b) {
                    (Affine::Stack(a), Affine::Constant(b)) => if sub {
                        a.checked_sub(b)
                    } else {
                        a.checked_add(b)
                    }
                    .filter(|n| n.unsigned_abs() <= 1 << 30)
                    .map(Affine::Stack),
                    (Affine::Constant(a), Affine::Stack(b)) if !sub => a
                        .checked_add(b)
                        .filter(|n| n.unsigned_abs() <= 1 << 30)
                        .map(Affine::Stack),
                    (Affine::Constant(a), Affine::Constant(b)) => if sub {
                        a.checked_sub(b)
                    } else {
                        a.checked_add(b)
                    }
                    .map(Affine::Constant),
                    _ => None,
                };
            }
            if op.is_none() {
                let mut values = args.into_iter();
                let first = self.get(values.next()?, depth + 1)?;
                for value in values {
                    if self.get(value, depth + 1) != Some(first) {
                        return None;
                    }
                }
                return Some(first);
            }
            None
        })();
        self.visiting.remove(&v);
        self.cache.insert(v, result);
        result
    }
    fn incoming(&self, mut u: Use) -> Option<String> {
        for _ in 0..64 {
            let Use::Value(v) = u else { return None };
            let var = &self.f.variables[v.variable];
            if v.version == 0 {
                return (var.kind == VariableKind::Register).then(|| var.name.clone());
            }
            let (op, args) = self.defs.get(&v)?;
            if *op != Some(Operation::Copy) {
                return None;
            }
            u = *args.first()?;
        }
        None
    }
}
pub(super) fn recover(
    binary: &crate::LoadedBinary,
    analysis: &crate::ProgramAnalysis,
    address: u64,
    p: Processor,
    control: &dyn AnalysisControl,
) -> Result<StackFrame, String> {
    let raw = ir::lift_function(binary, analysis, address, control)?;
    let ssa = ir::ssa::construct_with_control(&raw, control)?;
    let sp = ssa
        .variables
        .iter()
        .position(|v| v.name == p.stack())
        .ok_or("processor stack root missing")?;
    let mut defs = BTreeMap::new();
    for block in &ssa.blocks {
        for phi in &block.phis {
            defs.insert(
                phi.output,
                (
                    None,
                    phi.incoming
                        .values()
                        .copied()
                        .chain(phi.initial)
                        .map(Use::Value)
                        .collect(),
                ),
            );
        }
        for s in &block.statements {
            if let Some(out) = s.output {
                defs.insert(out, (Some(s.op.clone()), s.args.clone()));
            }
        }
    }
    let mut solver = Solver {
        f: &ssa,
        sp,
        defs,
        cache: BTreeMap::new(),
        visiting: BTreeSet::new(),
        budget: 100000,
        partial: false,
    };
    let convention = match p {
        Processor::Aarch64 => CallingConvention::Aapcs64,
        Processor::Arm | Processor::Thumb => CallingConvention::Aapcs32,
        Processor::Riscv32 => CallingConvention::Riscv32,
        _ => CallingConvention::Riscv64,
    };
    let mut accesses: BTreeMap<i64, Vec<StackAccess>> = BTreeMap::new();
    let mut count = 0;
    let mut unknown = 0;
    let mut extent = 0;
    let mut uses_fp = false;
    for block in &ssa.blocks {
        if control.is_cancelled() {
            return Err("stack recovery cancelled".into());
        }
        for s in &block.statements {
            if let Some(out) = s.output {
                if out.variable == sp {
                    if let Some(Affine::Stack(n)) = solver.get(Use::Value(out), 0) {
                        if n < 0 {
                            extent = extent.max(n.unsigned_abs());
                        }
                    }
                }
                if matches!(
                    ssa.variables[out.variable].name.as_str(),
                    "x29" | "r11" | "s0"
                ) && matches!(solver.get(Use::Value(out), 0), Some(Affine::Stack(_)))
                {
                    uses_fp = true;
                }
            }
            if !matches!(s.op, Operation::Load | Operation::Store) {
                continue;
            }
            if count >= 20000 {
                solver.partial = true;
                break;
            }
            count += 1;
            let Some(Affine::Stack(offset)) = s.args.get(1).and_then(|u| solver.get(*u, 0)) else {
                unknown += 1;
                continue;
            };
            let read = s.op == Operation::Load;
            let width = if read {
                s.output.and_then(|v| ssa.variables[v.variable].ty.width())
            } else {
                s.args.get(2).and_then(|u| match u {
                    Use::Value(v) => ssa.variables[v.variable].ty.width(),
                    Use::Constant(c) => c.ty.width(),
                })
            }
            .ok_or("stack memory width missing")?;
            let source = if read {
                None
            } else {
                s.args.get(2).and_then(|u| solver.incoming(*u))
            };
            accesses.entry(offset).or_default().push(StackAccess {
                instruction: s.source.0,
                mnemonic: if read { "load" } else { "store" }.into(),
                offset,
                width,
                read,
                write: !read,
                base_register: p.stack().into(),
                displacement: offset,
                source_register: source,
                confidence: Confidence::High,
            });
        }
    }
    let mut slots = vec![];
    for (offset, mut a) in accesses {
        if slots.len() >= 2048 {
            solver.partial = true;
            break;
        }
        a.sort_by_key(|v| v.instruction);
        let width = a.iter().map(|v| v.width).max().unwrap();
        let saved = a
            .iter()
            .filter(|v| offset < 0 && v.write && v.width == u16::from(p.bits()))
            .filter_map(|v| v.source_register.as_ref())
            .find(|n| {
                convention
                    .callee_saved(u16::from(p.bits()))
                    .contains(&n.as_str())
                    || Some(n.as_str()) == p.link()
            })
            .cloned();
        let reads = a.iter().filter(|v| v.read).count();
        let writes = a.len() - reads;
        let kind = if saved.is_some() {
            "savedRegister"
        } else if offset >= 0 && reads > 0 && writes == 0 {
            "incomingArgument"
        } else if offset >= 0 {
            "aboveEntryStackAccess"
        } else {
            "spillOrLocal"
        };
        slots.push(StackSlot {
            offset,
            width,
            name: saved
                .as_ref()
                .map(|n| format!("saved_{n}"))
                .unwrap_or_else(|| {
                    format!(
                        "stack_{}{:x}",
                        if offset < 0 { "minus_" } else { "plus_" },
                        offset.unsigned_abs()
                    )
                }),
            kind: kind.into(),
            ty: TypeRef::Int {
                bits: width,
                signed: None,
            },
            user_name: None,
            user_type: None,
            reads,
            writes,
            first_instruction: a[0].instruction,
            last_instruction: a.last().unwrap().instruction,
            saved_register: saved,
            overlaps: vec![],
            confidence: Confidence::High,
            accesses: a,
        });
    }
    for i in 0..slots.len() {
        if control.is_cancelled() {
            return Err("stack recovery cancelled".into());
        }
        for j in i + 1..slots.len() {
            if slots[i].offset < slots[j].offset + i64::from(slots[j].width / 8)
                && slots[j].offset < slots[i].offset + i64::from(slots[i].width / 8)
            {
                let (a, b) = (slots[i].offset, slots[j].offset);
                slots[i].overlaps.push(b);
                slots[j].overlaps.push(a);
            }
        }
    }
    let saved_registers = slots
        .iter()
        .filter_map(|v| v.saved_register.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let local_bytes = slots
        .iter()
        .filter(|s| s.offset < 0)
        .map(|s| s.offset.unsigned_abs())
        .max()
        .unwrap_or(0);
    let incoming_argument_bytes = slots
        .iter()
        .filter(|s| s.kind == "incomingArgument" && s.reads > 0 && s.writes == 0)
        .map(|s| s.offset as u64 + u64::from(s.width / 8))
        .max()
        .unwrap_or(0);
    Ok(StackFrame{function:address,address_width:u16::from(p.bits()),uses_frame_pointer:uses_fp,frame_size:extent,alignment:1,return_address_offset:0,return_address_register:p.link().map(str::to_owned),saved_registers,local_bytes,incoming_argument_bytes,slots,unknown_access_candidates:unknown,truncated:solver.partial,notes:vec!["Physical slots proven by bounded SSA copies/constant offsets from incoming SP; unresolved indices and cyclic/conflicting joins stay unknown. Alignment is not inferred.".into(),"Return address begins in the link register. Saved-register labels prove an incoming-value store, not restoration or source-local identity. Calls use the declared scalar ABI; general alias analysis and aggregate/vector arguments remain incomplete.".into()]})
}
