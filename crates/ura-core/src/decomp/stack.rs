//! Evidence-based stack-frame reconstruction from decoded instruction semantics.
//!
//! Slots are physical stack locations with observed accesses. They are not
//! presented as source variables, and any unresolved control-flow stack delta
//! lowers confidence instead of being guessed.
use super::signature::{CallingConvention, FunctionSignature};
use super::types::{Confidence, TypeRef};
use crate::{DecodedInstruction, LoadedBinary, ProgramAnalysis};
use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_STACK_ACCESSES: usize = 20_000;
const MAX_STACK_SLOTS: usize = 2_048;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackAccess {
    pub instruction: u64,
    pub mnemonic: String,
    pub offset: i64,
    pub width: u16,
    pub read: bool,
    pub write: bool,
    pub base_register: String,
    pub displacement: i64,
    pub source_register: Option<String>,
    pub confidence: Confidence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackSlot {
    pub offset: i64,
    pub width: u16,
    pub name: String,
    pub kind: String,
    pub ty: TypeRef,
    pub user_name: Option<String>,
    pub user_type: Option<TypeRef>,
    pub reads: usize,
    pub writes: usize,
    pub accesses: Vec<StackAccess>,
    pub first_instruction: u64,
    pub last_instruction: u64,
    pub saved_register: Option<String>,
    pub overlaps: Vec<i64>,
    pub confidence: Confidence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackFrame {
    pub function: u64,
    pub address_width: u16,
    pub uses_frame_pointer: bool,
    pub frame_size: u64,
    pub alignment: u64,
    pub return_address_offset: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_address_register: Option<String>,
    pub saved_registers: Vec<String>,
    pub local_bytes: u64,
    pub incoming_argument_bytes: u64,
    pub slots: Vec<StackSlot>,
    pub unknown_access_candidates: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}
impl StackFrame {
    pub fn negative_slots(&self) -> impl Iterator<Item = &StackSlot> {
        self.slots.iter().filter(|slot| slot.offset < 0)
    }
    pub fn argument_slots(&self) -> impl Iterator<Item = &StackSlot> {
        self.slots.iter().filter(|slot| {
            slot.offset
                >= if self.return_address_register.is_some() {
                    0
                } else {
                    self.return_address_offset + i64::from(self.address_width / 8)
                }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Known(i64),
    Unknown,
}
impl Flow {
    fn value(self) -> Option<i64> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }
    fn from_option(value: Option<i64>) -> Self {
        value.map_or(Self::Unknown, Self::Known)
    }
    fn join(self, other: Self) -> Self {
        if self == other {
            self
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StackState {
    sp: Flow,
    fp: Flow,
}
impl StackState {
    fn join(self, other: Self) -> Self {
        Self {
            sp: self.sp.join(other.sp),
            fp: self.fp.join(other.fp),
        }
    }
}

struct Decoded {
    instruction: Instruction,
    info: iced_x86::InstructionInfo,
}

pub fn recover(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    function: u64,
    signature: Option<&FunctionSignature>,
) -> Result<StackFrame, String> {
    recover_with_control(binary, analysis, function, signature, &())
}

/// Controlled counterpart of `recover`. The dataflow lattice only loses
/// information at joins, including the implicit entry edge, so loops converge.
pub fn recover_with_control(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    function: u64,
    signature: Option<&FunctionSignature>,
    control: &dyn crate::AnalysisControl,
) -> Result<StackFrame, String> {
    let check = || {
        if control.is_cancelled() {
            Err("stack recovery cancelled".to_string())
        } else {
            Ok(())
        }
    };
    check()?;
    let function = analysis
        .function_by_start(function)
        .ok_or_else(|| format!("function {function:#x} was not discovered"))?;
    let bits = binary.analysis().bitness;
    if let Ok(p) = crate::processor::Processor::for_analysis(binary.analysis()) {
        if !p.x86() {
            return super::stack_risc::recover(binary, analysis, function.address, p, control);
        }
    }
    if !matches!(bits, 32 | 64)
        || !matches!(binary.analysis().architecture.name(), "x86" | "x86-64")
    {
        return Ok(StackFrame {
            function: function.address,
            address_width: bits as u16,
            uses_frame_pointer: false,
            frame_size: 0,
            alignment: 1,
            return_address_offset: 0,
            return_address_register: None,
            saved_registers: vec![],
            local_bytes: 0,
            incoming_argument_bytes: 0,
            slots: vec![],
            unknown_access_candidates: 0,
            truncated: false,
            notes: vec![format!(
                "stack recovery supports x86/x64; {} is unsupported",
                binary.analysis().architecture.name()
            )],
        });
    }
    if function.blocks.len() > 2_048 || function.instruction_count > 50_000 {
        return Err("function is too large for bounded stack reconstruction".into());
    }
    let mut decoded = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    for block in &function.blocks {
        check()?;
        let Some(block) = analysis.blocks.get(block) else {
            continue;
        };
        for address in &block.instructions {
            check()?;
            let Some(entry) = analysis.instructions.get(address) else {
                continue;
            };
            let Some(bytes) = binary.bytes_at_address(*address, entry.length as usize) else {
                continue;
            };
            let mut decoder = Decoder::with_ip(bits as u32, bytes, *address, DecoderOptions::NONE);
            if !decoder.can_decode() {
                continue;
            }
            let instruction = decoder.decode();
            if instruction.is_invalid() || instruction.len() != bytes.len() {
                continue;
            }
            let info = factory.info(&instruction).clone();
            decoded.insert(*address, Decoded { instruction, info });
        }
    }
    let entry = function.address;
    let mut states: BTreeMap<u64, Option<StackState>> =
        function.blocks.iter().map(|b| (*b, None)).collect();
    states.insert(
        entry,
        Some(StackState {
            sp: Flow::Known(0),
            fp: Flow::Unknown,
        }),
    );
    let mut queue = VecDeque::from([entry]);
    let mut frame_size = 0;
    let mut saw_frame_pointer = false;
    while let Some(address) = queue.pop_front() {
        check()?;
        let Some(block) = analysis.blocks.get(&address) else {
            continue;
        };
        let Some(mut state) = states.get(&address).copied().flatten() else {
            continue;
        };
        for instruction in &block.instructions {
            check()?;
            if let Some(decoded) = decoded.get(instruction) {
                transfer(decoded, bits, &mut state);
                saw_frame_pointer |= state.fp.value().is_some();
                if let Some(value) = state.sp.value() {
                    if value < 0 {
                        frame_size = frame_size.max(value.unsigned_abs());
                    }
                }
            } else {
                state = StackState {
                    sp: Flow::Unknown,
                    fp: Flow::Unknown,
                };
            }
        }
        for edge in &block.successors {
            let Some(previous) = states.get(&edge.target).copied() else {
                continue;
            };
            let next = previous.map_or(state, |previous| previous.join(state));
            if previous != Some(next) {
                states.insert(edge.target, Some(next));
                queue.push_back(edge.target);
            }
        }
    }

    let mut accesses = BTreeMap::new();
    let mut access_count = 0usize;
    let mut unknown_access_candidates = 0usize;
    let mut truncated = false;
    for block_address in &function.blocks {
        check()?;
        let Some(block) = analysis.blocks.get(block_address) else {
            continue;
        };
        let Some(mut state) = states.get(block_address).copied().flatten() else {
            continue;
        };
        for address in &block.instructions {
            check()?;
            let Some(decoded) = decoded.get(address) else {
                state = StackState {
                    sp: Flow::Unknown,
                    fp: Flow::Unknown,
                };
                continue;
            };
            let instruction = &decoded.instruction;
            let mnemonic = instruction.mnemonic();
            if mnemonic == Mnemonic::Call {
                transfer(decoded, bits, &mut state);
                continue;
            }
            // Record the implicit stack access of PUSH/POP before the transfer.
            // Explicit memory operands are handled below as well.
            if matches!(mnemonic, Mnemonic::Push | Mnemonic::Pop) {
                let increment = i64::from(instruction.stack_pointer_increment());
                let width = increment.unsigned_abs().saturating_mul(8) as u16;
                let offset = state.sp.value().and_then(|value| {
                    if mnemonic == Mnemonic::Push {
                        value.checked_add(increment)
                    } else {
                        Some(value)
                    }
                });
                if let Some(offset) = offset {
                    if matches!(width, 16 | 32 | 64) {
                        if access_count < MAX_STACK_ACCESSES {
                            push_access(
                                &mut accesses,
                                StackAccess {
                                    instruction: *address,
                                    mnemonic: format!("{mnemonic:?}").to_lowercase(),
                                    offset,
                                    width,
                                    read: mnemonic == Mnemonic::Pop,
                                    write: mnemonic == Mnemonic::Push,
                                    base_register: stack_pointer(bits).into(),
                                    displacement: 0,
                                    source_register: (mnemonic == Mnemonic::Push
                                        && instruction.op0_kind() == OpKind::Register)
                                        .then(|| register_name(instruction.op0_register())),
                                    confidence: Confidence::High,
                                },
                                false,
                            );
                            access_count += 1;
                        } else {
                            truncated = true;
                        }
                    }
                } else {
                    unknown_access_candidates += 1;
                }
            }
            for memory in decoded.info.used_memory() {
                if memory.access() == OpAccess::NoMemAccess {
                    continue;
                }
                // PUSH/POP implicit accesses were recorded above. Their explicit
                // memory operands need separate handling (POP uses post-increment SP).
                if matches!(mnemonic, Mnemonic::Push | Mnemonic::Pop)
                    && instruction.op0_kind() != OpKind::Memory
                {
                    continue;
                }
                if (mnemonic == Mnemonic::Push && memory.access() != OpAccess::Read)
                    || (mnemonic == Mnemonic::Pop && memory.access() != OpAccess::Write)
                {
                    continue;
                }
                let base = full_register(memory.base(), bits);
                if base != stack_pointer(bits) && base != frame_pointer(bits) {
                    continue;
                }
                let width = memory.memory_size().size() as u16 * 8;
                if !matches!(width, 8 | 16 | 32 | 64) {
                    continue;
                }
                if memory.index() != Register::None
                    || memory.base().size() != usize::from(bits / 8)
                    || (bits == 32 && memory.segment() != Register::SS)
                    || (bits == 64 && matches!(memory.segment(), Register::FS | Register::GS))
                {
                    unknown_access_candidates += 1;
                    continue;
                }
                let displacement = signed_displacement(memory.displacement(), bits);
                let delta = if base == stack_pointer(bits) {
                    let value = state.sp.value();
                    if mnemonic == Mnemonic::Pop {
                        value.and_then(|v| {
                            v.checked_add(i64::from(instruction.stack_pointer_increment()))
                        })
                    } else {
                        value
                    }
                } else {
                    state.fp.value()
                };
                let offset = delta.and_then(|v| v.checked_add(displacement));
                let Some(offset) =
                    offset.filter(|offset| (-0x100_000..=0x100_000).contains(offset))
                else {
                    unknown_access_candidates += 1;
                    continue;
                };
                if access_count >= MAX_STACK_ACCESSES {
                    truncated = true;
                    continue;
                }
                let access = memory.access();
                push_access(
                    &mut accesses,
                    StackAccess {
                        instruction: *address,
                        mnemonic: format!("{mnemonic:?}").to_lowercase(),
                        offset,
                        width,
                        read: matches!(
                            access,
                            OpAccess::Read
                                | OpAccess::CondRead
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        ),
                        write: matches!(
                            access,
                            OpAccess::Write
                                | OpAccess::CondWrite
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        ),
                        base_register: register_name(memory.base()),
                        displacement,
                        source_register: if matches!(
                            access,
                            OpAccess::Write
                                | OpAccess::ReadWrite
                                | OpAccess::CondWrite
                                | OpAccess::ReadCondWrite
                        ) {
                            inferred_written_register(instruction)
                        } else {
                            None
                        },
                        confidence: Confidence::Medium,
                    },
                    false,
                );
                access_count += 1;
            }
            transfer(decoded, bits, &mut state);
        }
    }
    let callee_saved: BTreeSet<String> = signature
        .map(|s| s.convention)
        .unwrap_or(CallingConvention::Unknown)
        .callee_saved(bits as u16)
        .iter()
        .map(|name| name.to_string())
        .collect();
    let mut entry_saves = BTreeSet::new();
    let mut written = BTreeSet::new();
    if let Some(entry_block) = analysis.blocks.get(&entry) {
        for address in &entry_block.instructions {
            check()?;
            let Some(decoded) = decoded.get(address) else {
                break;
            };
            let instruction = &decoded.instruction;
            let source = match instruction.mnemonic() {
                Mnemonic::Push if instruction.op0_kind() == OpKind::Register => {
                    Some(instruction.op0_register())
                }
                Mnemonic::Mov
                    if instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_kind() == OpKind::Register =>
                {
                    Some(instruction.op1_register())
                }
                _ => None,
            };
            if let Some(source) = source {
                let name = register_name(source);
                if source.size() == usize::from(bits / 8)
                    && callee_saved.contains(&name)
                    && !written.contains(&name)
                {
                    entry_saves.insert((*address, name));
                }
            }
            for register in decoded.info.used_registers() {
                if matches!(
                    register.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    written.insert(full_register(register.register(), bits));
                }
            }
        }
    }
    let mut slots = Vec::new();
    for (offset, mut access_list) in accesses {
        check()?;
        if slots.len() >= MAX_STACK_SLOTS {
            truncated = true;
            break;
        }
        access_list.sort_by_key(|access| access.instruction);
        let width = access_list
            .iter()
            .map(|access| access.width)
            .max()
            .unwrap_or(8);
        let saved = access_list.iter().find_map(|access| {
            let register = access.source_register.as_ref()?;
            (offset < 0 && entry_saves.contains(&(access.instruction, register.clone())))
                .then(|| register.clone())
        });
        let kind = if offset >= i64::from(bits / 8) {
            if signature.is_some_and(|s| s.convention == CallingConvention::Win64) && offset < 0x28
            {
                "shadowSpace"
            } else {
                "incomingArgument"
            }
        } else if offset == 0 {
            "returnAddress"
        } else if saved.is_some() {
            "savedRegister"
        } else if access_list
            .iter()
            .any(|access| access.write && access.source_register.is_some())
        {
            "spillOrLocal"
        } else {
            "localCandidate"
        };
        let reads = access_list.iter().filter(|access| access.read).count();
        let writes = access_list.iter().filter(|access| access.write).count();
        let name = saved
            .as_ref()
            .map(|r| format!("saved_{r}"))
            .unwrap_or_else(|| {
                if offset < 0 {
                    format!("local_{:x}", offset.unsigned_abs())
                } else {
                    format!("arg_{offset:x}")
                }
            });
        let confidence = if access_list.iter().all(|a| a.confidence == Confidence::High) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        slots.push(StackSlot {
            offset,
            width,
            name,
            kind: kind.into(),
            ty: TypeRef::Int {
                bits: width,
                signed: None,
            },
            user_name: None,
            user_type: None,
            reads,
            writes,
            first_instruction: access_list[0].instruction,
            last_instruction: access_list
                .last()
                .map(|a| a.instruction)
                .unwrap_or_default(),
            saved_register: saved,
            overlaps: vec![],
            confidence,
            accesses: access_list,
        });
    }
    slots.sort_by_key(|slot| slot.offset);
    for i in 0..slots.len() {
        check()?;
        for j in (i + 1)..slots.len() {
            let left_end = slots[i].offset + i64::from(slots[i].width.div_ceil(8));
            let right_end = slots[j].offset + i64::from(slots[j].width.div_ceil(8));
            if slots[i].offset < right_end && slots[j].offset < left_end {
                let (left, right) = (slots[i].offset, slots[j].offset);
                slots[i].overlaps.push(right);
                slots[j].overlaps.push(left);
            }
        }
    }
    let local_bytes = slots
        .iter()
        .filter(|slot| slot.offset < 0)
        .map(|slot| slot.offset.unsigned_abs())
        .max()
        .unwrap_or(0);
    let incoming_start = if signature.is_some_and(|s| s.convention == CallingConvention::Win64) {
        0x28
    } else {
        i64::from(bits / 8)
    };
    let incoming_argument_bytes = slots
        .iter()
        .filter(|slot| slot.kind == "incomingArgument")
        .map(|slot| (slot.offset - incoming_start) as u64 + u64::from(slot.width).div_ceil(8))
        .max()
        .unwrap_or(0);
    let saved_registers = slots
        .iter()
        .filter_map(|slot| slot.saved_register.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut notes = vec![
        "Stack slots are physical locations with instruction provenance, not source variables.".into(),
        "x64 calls assume ABI stack preservation. x86 calls invalidate the stack delta because callee cleanup is unknown; frame-pointer relations are retained.".into(),
        "Frame size is the maximum proven stack decrement; alignment is unknown unless established independently.".into(),
        "Saved-register labels require an entry-block store of the native-width incoming register before it is overwritten; restoration is not proved.".into(),
    ];
    if unknown_access_candidates > 0 {
        notes.push(format!("{unknown_access_candidates} stack access(es) had an unresolved delta, index, segment or address width"));
    }
    check()?;
    Ok(StackFrame {
        function: function.address,
        address_width: bits as u16,
        uses_frame_pointer: saw_frame_pointer,
        frame_size,
        alignment: 1,
        return_address_offset: 0,
        return_address_register: None,
        saved_registers,
        local_bytes,
        incoming_argument_bytes,
        slots,
        unknown_access_candidates,
        truncated,
        notes,
    })
}

fn transfer(decoded: &Decoded, bits: u8, state: &mut StackState) {
    let instruction = &decoded.instruction;
    let mnemonic = instruction.mnemonic();
    if mnemonic == Mnemonic::Call {
        if bits == 32 {
            state.sp = Flow::Unknown;
        }
        return;
    }
    if mnemonic == Mnemonic::Ret {
        return;
    }
    let old = *state;
    let mut handled_sp = false;
    let mut handled_fp = false;
    if matches!(mnemonic, Mnemonic::Push | Mnemonic::Pop) {
        state.sp = Flow::from_option(
            old.sp
                .value()
                .and_then(|v| v.checked_add(i64::from(instruction.stack_pointer_increment()))),
        );
        handled_sp = true;
        if mnemonic == Mnemonic::Pop && instruction.op0_kind() == OpKind::Register {
            let dest = full_register(instruction.op0_register(), bits);
            if dest == stack_pointer(bits) {
                state.sp = Flow::Unknown;
            }
            if dest == frame_pointer(bits) {
                state.fp = Flow::Unknown;
                handled_fp = true;
            }
        }
    } else if mnemonic == Mnemonic::Leave {
        state.sp = Flow::from_option(
            old.fp
                .value()
                .and_then(|v| v.checked_add(i64::from(bits / 8))),
        );
        state.fp = Flow::Unknown;
        handled_sp = true;
        handled_fp = true;
    } else if matches!(mnemonic, Mnemonic::Mov | Mnemonic::Lea)
        && instruction.op0_kind() == OpKind::Register
    {
        let destination = instruction.op0_register();
        let name = full_register(destination, bits);
        let value = (destination.size() == usize::from(bits / 8))
            .then(|| instruction_pointer_value(instruction, old.sp.value(), old.fp.value(), bits))
            .flatten();
        if name == stack_pointer(bits) {
            state.sp = Flow::from_option(value);
            handled_sp = true;
        }
        if name == frame_pointer(bits) {
            state.fp = Flow::from_option(value);
            handled_fp = true;
        }
    } else if matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub)
        && instruction.op0_kind() == OpKind::Register
        && immediate_kind(instruction.op1_kind())
    {
        let destination = instruction.op0_register();
        let name = full_register(destination, bits);
        if name == stack_pointer(bits) || name == frame_pointer(bits) {
            let old_value = if name == stack_pointer(bits) {
                old.sp
            } else {
                old.fp
            };
            let immediate = signed_displacement(instruction.immediate(1), bits);
            let value = (destination.size() == usize::from(bits / 8))
                .then(|| {
                    old_value.value().and_then(|v| {
                        if mnemonic == Mnemonic::Add {
                            v.checked_add(immediate)
                        } else {
                            v.checked_sub(immediate)
                        }
                    })
                })
                .flatten();
            if name == stack_pointer(bits) {
                state.sp = Flow::from_option(value);
                handled_sp = true;
            } else {
                state.fp = Flow::from_option(value);
                handled_fp = true;
            }
        }
    }
    // Unsupported writes (including partial-register writes, XCHG and POP SP)
    // invalidate the corresponding affine relation rather than retaining it.
    for register in decoded.info.used_registers() {
        if !matches!(
            register.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        ) {
            continue;
        }
        let name = full_register(register.register(), bits);
        if name == stack_pointer(bits) && !handled_sp {
            state.sp = Flow::Unknown;
        }
        if name == frame_pointer(bits) && !handled_fp {
            state.fp = Flow::Unknown;
        }
    }
}

fn signed_displacement(value: u64, bits: u8) -> i64 {
    if bits == 32 {
        value as u32 as i32 as i64
    } else {
        value as i64
    }
}

fn push_access(
    accesses: &mut BTreeMap<i64, Vec<StackAccess>>,
    access: StackAccess,
    truncated: bool,
) {
    if truncated {
        return;
    }
    accesses.entry(access.offset).or_default().push(access);
}

fn stack_pointer(bits: u8) -> &'static str {
    if bits == 64 {
        "rsp"
    } else {
        "esp"
    }
}
fn frame_pointer(bits: u8) -> &'static str {
    if bits == 64 {
        "rbp"
    } else {
        "ebp"
    }
}
fn register_name(register: Register) -> String {
    format!("{register:?}").to_ascii_lowercase()
}
fn full_register(register: Register, bits: u8) -> String {
    register_name(if bits == 32 {
        register.full_register32()
    } else {
        register.full_register()
    })
}
fn immediate_kind(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}
fn inferred_written_register(instruction: &Instruction) -> Option<String> {
    for operand in 1..instruction.op_count() {
        if instruction.op_kind(operand) == OpKind::Register {
            let register = instruction.op_register(operand);
            if register != Register::None {
                return Some(register_name(register));
            }
        }
    }
    None
}
fn instruction_pointer_value(
    instruction: &Instruction,
    current: Option<i64>,
    rbp_delta: Option<i64>,
    bits: u8,
) -> Option<i64> {
    match instruction.mnemonic() {
        Mnemonic::Mov
            if instruction.op1_kind() == OpKind::Register
                && instruction.op1_register().size() == usize::from(bits / 8) =>
        {
            let source = full_register(instruction.op1_register(), bits);
            if source == "rsp" || source == "esp" {
                current
            } else if source == "rbp" || source == "ebp" {
                rbp_delta
            } else {
                None
            }
        }
        Mnemonic::Lea if instruction.op1_kind() == OpKind::Memory => {
            if instruction.memory_index() != Register::None
                || instruction.memory_base().size() != usize::from(bits / 8)
            {
                return None;
            }
            let base = full_register(instruction.memory_base(), bits);
            let displacement = signed_displacement(instruction.memory_displacement64(), bits);
            if base == "rsp" || base == "esp" {
                current.and_then(|value| value.checked_add(displacement))
            } else if base == "rbp" || base == "ebp" {
                rbp_delta.and_then(|value| value.checked_add(displacement))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Attach persisted user names/types without changing physical offsets or access
/// evidence. Unknown overrides are retained verbatim.
pub fn apply_overrides(
    frame: &mut StackFrame,
    overrides: &BTreeMap<String, (Option<String>, Option<TypeRef>)>,
) {
    for slot in &mut frame.slots {
        let key = slot.offset.to_string();
        if let Some((name, ty)) = overrides.get(&key) {
            slot.user_name = name.clone();
            slot.user_type = ty.clone();
        }
    }
}

#[allow(dead_code)]
fn decoded_fallback(_entry: &DecodedInstruction) {}
