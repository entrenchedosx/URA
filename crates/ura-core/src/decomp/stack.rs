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
            slot.offset >= self.return_address_offset + i64::from(self.address_width / 8)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Unvisited,
    Known(i64),
    Unknown,
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
    let function = analysis
        .function_by_start(function)
        .ok_or_else(|| format!("function {function:#x} was not discovered"))?;
    let bits = binary.analysis().bitness;
    if !matches!(bits, 32 | 64)
        || binary.analysis().architecture.name() != "x86"
            && binary.analysis().architecture.name() != "x86-64"
    {
        return Ok(StackFrame {
            function: function.address,
            address_width: bits as u16,
            uses_frame_pointer: false,
            frame_size: 0,
            alignment: 1,
            return_address_offset: 0,
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
    let mut decoded: BTreeMap<u64, Decoded> = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    for block in &function.blocks {
        let Some(block) = analysis.blocks.get(block) else {
            continue;
        };
        for address in &block.instructions {
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
            if instruction.len() != bytes.len() {
                continue;
            }
            let info = factory.info(&instruction).clone();
            decoded.insert(*address, Decoded { instruction, info });
        }
    }

    let entry = function.address;
    let mut delta: BTreeMap<u64, Flow> = function
        .blocks
        .iter()
        .map(|block| (*block, Flow::Unvisited))
        .collect();
    delta.insert(entry, Flow::Known(0));
    let mut queue = VecDeque::from([entry]);
    let mut rbp_delta: Option<i64> = None;
    let mut rbp_conflict = false;
    while let Some(block_address) = queue.pop_front() {
        let Some(block) = analysis.blocks.get(&block_address) else {
            continue;
        };
        let start = delta[&block_address];
        let Flow::Known(start) = start else {
            continue;
        };
        let mut current = Some(start);
        for address in &block.instructions {
            let Some(decoded) = decoded.get(address) else {
                current = None;
                continue;
            };
            let instruction = &decoded.instruction;
            let mnemonic = instruction.mnemonic();
            if mnemonic == Mnemonic::Call {
                continue;
            }
            if matches!(mnemonic, Mnemonic::Push | Mnemonic::Pop) {
                current =
                    current.map(|value| value + i64::from(instruction.stack_pointer_increment()));
            } else if mnemonic == Mnemonic::Leave {
                current = rbp_delta.map(|value| value + i64::from(bits / 8));
            } else if matches!(mnemonic, Mnemonic::Mov | Mnemonic::Lea) {
                let destination = instruction.op0_kind();
                if destination == OpKind::Register {
                    let register = full_register(instruction.op0_register());
                    if register == stack_pointer(bits) {
                        if let Some(value) =
                            instruction_pointer_value(instruction, current, rbp_delta)
                        {
                            current = Some(value);
                        } else {
                            current = None;
                        }
                    } else if register == frame_pointer(bits) {
                        if let Some(value) =
                            instruction_pointer_value(instruction, current, rbp_delta)
                        {
                            match rbp_delta {
                                None => rbp_delta = Some(value),
                                Some(existing) if existing != value => rbp_conflict = true,
                                Some(_) => {}
                            }
                        }
                    }
                }
            } else if matches!(mnemonic, Mnemonic::Sub | Mnemonic::Add) {
                if instruction.op0_kind() == OpKind::Register
                    && full_register(instruction.op0_register()) == stack_pointer(bits)
                    && immediate_kind(instruction.op1_kind())
                {
                    let immediate = instruction.immediate(1) as i64;
                    current = current.map(|value| {
                        if mnemonic == Mnemonic::Sub {
                            value - immediate
                        } else {
                            value + immediate
                        }
                    });
                }
            } else if matches!(mnemonic, Mnemonic::And | Mnemonic::Xor | Mnemonic::Or)
                && instruction.op0_kind() == OpKind::Register
                && full_register(instruction.op0_register()) == stack_pointer(bits)
            {
                // Explicit stack realignment destroys the linear delta until a
                // future frame setup; do not invent an offset.
                current = None;
            } else if mnemonic == Mnemonic::Enter {
                current = current
                    .map(|value| value - instruction.immediate(0) as i64 - i64::from(bits / 8));
            }
        }
        let outgoing = current;
        for edge in &block.successors {
            let next = match outgoing {
                Some(value) => Flow::Known(value),
                None => Flow::Unknown,
            };
            let changed = match (delta.get(&edge.target), next) {
                (Some(Flow::Unvisited), _) => true,
                (Some(Flow::Known(existing)), Flow::Known(value)) => *existing != value,
                (Some(Flow::Known(_)), Flow::Unknown) => true,
                (Some(Flow::Unknown), _) | (None, _) => false,
                (Some(Flow::Known(_)), Flow::Unvisited) => true,
            };
            if changed {
                delta.insert(edge.target, next);
                queue.push_back(edge.target);
            }
        }
    }

    let mut accesses: BTreeMap<i64, Vec<StackAccess>> = BTreeMap::new();
    let mut access_count = 0usize;
    let mut unknown_access_candidates = 0usize;
    for block in &function.blocks {
        let Some(block) = analysis.blocks.get(block) else {
            continue;
        };
        let mut current = match delta[&block.address] {
            Flow::Known(value) => Some(value),
            Flow::Unvisited => continue,
            Flow::Unknown => None,
        };
        for address in &block.instructions {
            let Some(decoded) = decoded.get(address) else {
                current = None;
                continue;
            };
            let instruction = &decoded.instruction;
            let mnemonic = instruction.mnemonic();
            if mnemonic == Mnemonic::Call {
                continue;
            }
            if mnemonic == Mnemonic::Push {
                if let (Some(delta), Ok(width)) = (current, memory_bits(instruction)) {
                    let offset = delta + i64::from(instruction.stack_pointer_increment());
                    let source = (instruction.op0_kind() == OpKind::Register)
                        .then(|| register_name(instruction.op0_register()));
                    push_access(
                        &mut accesses,
                        StackAccess {
                            instruction: *address,
                            mnemonic: "push".into(),
                            offset,
                            width,
                            read: false,
                            write: true,
                            base_register: stack_pointer(bits).into(),
                            displacement: 0,
                            source_register: source,
                            confidence: Confidence::High,
                        },
                        false,
                    );
                    access_count += 1;
                }
                current =
                    current.map(|value| value + i64::from(instruction.stack_pointer_increment()));
                continue;
            }
            if mnemonic == Mnemonic::Pop {
                if let (Some(delta), Ok(width)) = (current, memory_bits(instruction)) {
                    push_access(
                        &mut accesses,
                        StackAccess {
                            instruction: *address,
                            mnemonic: "pop".into(),
                            offset: delta,
                            width,
                            read: true,
                            write: false,
                            base_register: stack_pointer(bits).into(),
                            displacement: 0,
                            source_register: None,
                            confidence: Confidence::High,
                        },
                        false,
                    );
                    access_count += 1;
                }
                current =
                    current.map(|value| value + i64::from(instruction.stack_pointer_increment()));
                continue;
            }
            for memory in decoded.info.used_memory() {
                if memory.access() == OpAccess::NoMemAccess {
                    continue;
                }
                let base = full_register(memory.base());
                let base_name = register_name(memory.base());
                let width = memory.memory_size().size() as u16 * 8;
                if !matches!(width, 8 | 16 | 32 | 64) {
                    continue;
                }
                let displacement = memory.displacement() as i64;
                let canonical = if base == stack_pointer(bits) {
                    current.map(|delta| delta + displacement)
                } else if base == frame_pointer(bits) {
                    rbp_delta.map(|delta| delta + displacement)
                } else {
                    None
                };
                let Some(offset) = canonical else {
                    unknown_access_candidates += 1;
                    continue;
                };
                if !(-0x100_000..=0x100_000).contains(&offset) {
                    unknown_access_candidates += 1;
                    continue;
                }
                let access = memory.access();
                let read = matches!(
                    access,
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                );
                let write = matches!(
                    access,
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                );
                let source_register = if write {
                    inferred_written_register(instruction)
                } else {
                    None
                };
                push_access(
                    &mut accesses,
                    StackAccess {
                        instruction: *address,
                        mnemonic: format!("{:?}", instruction.mnemonic()).to_lowercase(),
                        offset,
                        width,
                        read,
                        write,
                        base_register: base_name,
                        displacement,
                        source_register,
                        confidence: if base == frame_pointer(bits) && rbp_delta.is_some() {
                            Confidence::High
                        } else if current.is_some() {
                            Confidence::Medium
                        } else {
                            Confidence::Low
                        },
                    },
                    access_count >= MAX_STACK_ACCESSES,
                );
                access_count += 1;
            }
            if mnemonic == Mnemonic::Leave {
                current = rbp_delta.map(|value| value + i64::from(bits / 8));
            } else if matches!(mnemonic, Mnemonic::Mov | Mnemonic::Lea)
                && instruction.op0_kind() == OpKind::Register
            {
                let register = full_register(instruction.op0_register());
                if register == stack_pointer(bits) {
                    current =
                        instruction_pointer_value(instruction, current, rbp_delta).or(current);
                } else if register == frame_pointer(bits) {
                    if let Some(value) = instruction_pointer_value(instruction, current, rbp_delta)
                    {
                        rbp_delta = Some(value);
                    }
                }
            } else if matches!(mnemonic, Mnemonic::Sub | Mnemonic::Add)
                && instruction.op0_kind() == OpKind::Register
                && full_register(instruction.op0_register()) == stack_pointer(bits)
                && immediate_kind(instruction.op1_kind())
            {
                let immediate = instruction.immediate(1) as i64;
                current = current.map(|value| {
                    if mnemonic == Mnemonic::Sub {
                        value - immediate
                    } else {
                        value + immediate
                    }
                });
            } else if matches!(mnemonic, Mnemonic::And | Mnemonic::Xor | Mnemonic::Or)
                && instruction.op0_kind() == OpKind::Register
                && full_register(instruction.op0_register()) == stack_pointer(bits)
            {
                current = None;
            }
        }
    }

    let return_address_offset = 0i64;
    let callee_saved: BTreeSet<String> = signature
        .map(|signature| {
            signature
                .convention
                .callee_saved(bits as u16)
                .iter()
                .map(|name| name.to_string())
                .collect()
        })
        .unwrap_or_else(|| {
            CallingConvention::Unknown
                .callee_saved(bits as u16)
                .iter()
                .map(|name| name.to_string())
                .collect()
        });
    let mut slots = Vec::new();
    for (offset, mut access_list) in accesses {
        if slots.len() >= MAX_STACK_SLOTS {
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
            (offset < 0 && callee_saved.contains(register)).then(|| register.clone())
        });
        let kind = if offset >= return_address_offset + i64::from(bits / 8) {
            "incomingArgument"
        } else if offset == return_address_offset {
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
            .clone()
            .map(|register| format!("saved_{register}"))
            .unwrap_or_else(|| {
                if offset < 0 {
                    format!("local_{:x}", -offset)
                } else {
                    format!("arg_{offset:x}")
                }
            });
        let confidence = if access_list
            .iter()
            .all(|access| access.confidence == Confidence::High)
        {
            Confidence::High
        } else if access_list
            .iter()
            .any(|access| access.confidence == Confidence::Low)
        {
            Confidence::Low
        } else {
            Confidence::Medium
        };
        slots.push(StackSlot {
            offset,
            width,
            name,
            kind: kind.into(),
            ty: match kind {
                "incomingArgument" => TypeRef::pointer_to(
                    TypeRef::unknown(None, "pointee type is not inferred"),
                    bits as u16,
                ),
                _ => TypeRef::Int {
                    bits: width,
                    signed: None,
                },
            },
            user_name: None,
            user_type: None,
            reads,
            writes,
            first_instruction: access_list[0].instruction,
            last_instruction: access_list
                .last()
                .map(|access| access.instruction)
                .unwrap_or_default(),
            saved_register: saved,
            overlaps: vec![],
            accesses: access_list,
            confidence,
        });
    }
    slots.sort_by_key(|slot| slot.offset);
    for i in 0..slots.len() {
        for j in (i + 1)..slots.len() {
            let left = &slots[i];
            let right = &slots[j];
            let left_end = left.offset + i64::from(left.width / 8).max(1);
            let right_end = right.offset + i64::from(right.width / 8).max(1);
            if left.offset < right_end && right.offset < left_end {
                let (left_offset, right_offset) = (left.offset, right.offset);
                slots[i].overlaps.push(right_offset);
                slots[j].overlaps.push(left_offset);
            }
        }
    }
    let frame_size = delta
        .values()
        .filter_map(|flow| match flow {
            Flow::Known(value) if *value < 0 => Some((-value) as u64),
            _ => None,
        })
        .max()
        .unwrap_or_else(|| {
            slots
                .iter()
                .filter(|slot| slot.offset < 0)
                .map(|slot| (-slot.offset) as u64 + u64::from(slot.width / 8))
                .max()
                .unwrap_or(0)
        });
    let local_bytes = slots
        .iter()
        .filter(|slot| slot.offset < 0)
        .map(|slot| (-slot.offset) as u64 + u64::from(slot.width / 8))
        .max()
        .unwrap_or(0);
    let incoming_argument_bytes = slots
        .iter()
        .filter(|slot| slot.kind == "incomingArgument")
        .map(|slot| (slot.offset - i64::from(bits / 8)) as u64 + u64::from(slot.width / 8))
        .max()
        .unwrap_or(0);
    let saved_registers = slots
        .iter()
        .filter_map(|slot| slot.saved_register.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut notes = vec![
        "Stack slots are physical locations with instruction provenance, not source variables."
            .into(),
        "Call instructions are assumed to preserve the caller's stack pointer across return."
            .into(),
    ];
    if rbp_conflict {
        notes.push(
            "conflicting frame-pointer definitions; rbp-relative confidence is reduced".into(),
        );
    }
    if unknown_access_candidates > 0 {
        notes.push(format!(
            "{unknown_access_candidates} memory access(es) had no resolvable stack delta or base register"
        ));
    }
    let truncated = access_count >= MAX_STACK_ACCESSES || slots.len() >= MAX_STACK_SLOTS;
    Ok(StackFrame {
        function: function.address,
        address_width: bits as u16,
        uses_frame_pointer: rbp_delta.is_some() && !rbp_conflict,
        frame_size,
        alignment: if bits == 64 { 16 } else { 4 },
        return_address_offset,
        saved_registers,
        local_bytes,
        incoming_argument_bytes,
        slots,
        unknown_access_candidates,
        truncated,
        notes,
    })
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
fn full_register(register: Register) -> String {
    register_name(register.full_register())
}
fn memory_bits(instruction: &Instruction) -> Result<u16, ()> {
    let width = instruction.memory_size().size() as u16 * 8;
    matches!(width, 8 | 16 | 32 | 64).then_some(width).ok_or(())
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
) -> Option<i64> {
    match instruction.mnemonic() {
        Mnemonic::Mov if instruction.op1_kind() == OpKind::Register => {
            let source = full_register(instruction.op1_register());
            if source == "rsp" || source == "esp" {
                current
            } else if source == "rbp" || source == "ebp" {
                rbp_delta
            } else {
                None
            }
        }
        Mnemonic::Lea if instruction.op1_kind() == OpKind::Memory => {
            if instruction.memory_index() != Register::None {
                return None;
            }
            let base = full_register(instruction.memory_base());
            let displacement = instruction.memory_displacement64() as i64;
            if base == "rsp" || base == "esp" {
                current.map(|value| value + displacement)
            } else if base == "rbp" || base == "ebp" {
                rbp_delta.map(|value| value + displacement)
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
