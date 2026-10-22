//! Deliberately bounded Intel text frontend to iced-x86's mature encoder.
//! Memory operands, labels, directives and relocation/trampolines are rejected.
use super::{Address, PatchDocument, PatchError, PatchResult, Preview};
use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction, IntelFormatter, OpKind,
    Register,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionPreview {
    pub schema_version: u32,
    pub patch: Preview,
    pub address: String,
    pub original_instructions: Vec<String>,
    pub replacement_instructions: Vec<String>,
    pub padding_bytes: usize,
    pub verification: String,
}

fn literal(text: &str) -> PatchResult<u64> {
    let text = text.trim();
    let negative = text.starts_with('-');
    let text = if negative { &text[1..] } else { text };
    let (digits, radix) = if let Some(t) = text.strip_prefix("0d") {
        (t, 10)
    } else {
        (text.strip_prefix("0x").unwrap_or(text), 16)
    };
    let value = u64::from_str_radix(digits, radix).map_err(|_| {
        PatchError("use hexadecimal integer operands (or explicit 0d decimal)".into())
    })?;
    if negative && value > 1u64 << 63 {
        return Err(PatchError(
            "negative literal exceeds signed 64-bit range".into(),
        ));
    }
    Ok(if negative {
        0u64.wrapping_sub(value)
    } else {
        value
    })
}
fn register(text: &str) -> Option<Register> {
    Register::values().find(|r| r.is_gpr() && format!("{r:?}").eq_ignore_ascii_case(text))
}
fn err(e: iced_x86::IcedError) -> PatchError {
    PatchError(e.to_string())
}
fn branch_code(mnemonic: &str, bits: u32, short: bool) -> Option<Code> {
    use Code::*;
    let pair = match (mnemonic, short) {
        ("jmp", true) => (Jmp_rel8_32, Jmp_rel8_64),
        ("jmp", false) => (Jmp_rel32_32, Jmp_rel32_64),
        ("call", false) => (Call_rel32_32, Call_rel32_64),
        ("jo", true) => (Jo_rel8_32, Jo_rel8_64),
        ("jo", false) => (Jo_rel32_32, Jo_rel32_64),
        ("jno", true) => (Jno_rel8_32, Jno_rel8_64),
        ("jno", false) => (Jno_rel32_32, Jno_rel32_64),
        ("jb" | "jc" | "jnae", true) => (Jb_rel8_32, Jb_rel8_64),
        ("jb" | "jc" | "jnae", false) => (Jb_rel32_32, Jb_rel32_64),
        ("jae" | "jnb" | "jnc", true) => (Jae_rel8_32, Jae_rel8_64),
        ("jae" | "jnb" | "jnc", false) => (Jae_rel32_32, Jae_rel32_64),
        ("je" | "jz", true) => (Je_rel8_32, Je_rel8_64),
        ("je" | "jz", false) => (Je_rel32_32, Je_rel32_64),
        ("jne" | "jnz", true) => (Jne_rel8_32, Jne_rel8_64),
        ("jne" | "jnz", false) => (Jne_rel32_32, Jne_rel32_64),
        ("jbe" | "jna", true) => (Jbe_rel8_32, Jbe_rel8_64),
        ("jbe" | "jna", false) => (Jbe_rel32_32, Jbe_rel32_64),
        ("ja" | "jnbe", true) => (Ja_rel8_32, Ja_rel8_64),
        ("ja" | "jnbe", false) => (Ja_rel32_32, Ja_rel32_64),
        ("js", true) => (Js_rel8_32, Js_rel8_64),
        ("js", false) => (Js_rel32_32, Js_rel32_64),
        ("jns", true) => (Jns_rel8_32, Jns_rel8_64),
        ("jns", false) => (Jns_rel32_32, Jns_rel32_64),
        ("jp" | "jpe", true) => (Jp_rel8_32, Jp_rel8_64),
        ("jp" | "jpe", false) => (Jp_rel32_32, Jp_rel32_64),
        ("jnp" | "jpo", true) => (Jnp_rel8_32, Jnp_rel8_64),
        ("jnp" | "jpo", false) => (Jnp_rel32_32, Jnp_rel32_64),
        ("jl" | "jnge", true) => (Jl_rel8_32, Jl_rel8_64),
        ("jl" | "jnge", false) => (Jl_rel32_32, Jl_rel32_64),
        ("jge" | "jnl", true) => (Jge_rel8_32, Jge_rel8_64),
        ("jge" | "jnl", false) => (Jge_rel32_32, Jge_rel32_64),
        ("jle" | "jng", true) => (Jle_rel8_32, Jle_rel8_64),
        ("jle" | "jng", false) => (Jle_rel32_32, Jle_rel32_64),
        ("jg" | "jnle", true) => (Jg_rel8_32, Jg_rel8_64),
        ("jg" | "jnle", false) => (Jg_rel32_32, Jg_rel32_64),
        _ => return None,
    };
    Some(if bits == 32 { pair.0 } else { pair.1 })
}
fn reg_code(m: &str, width: usize, immediate: bool) -> Option<Code> {
    use Code::*;
    let codes = match (m, immediate) {
        ("mov", false) => [Mov_r8_rm8, Mov_r16_rm16, Mov_r32_rm32, Mov_r64_rm64],
        ("mov", true) => [Mov_r8_imm8, Mov_r16_imm16, Mov_r32_imm32, Mov_r64_imm64],
        ("add", false) => [Add_r8_rm8, Add_r16_rm16, Add_r32_rm32, Add_r64_rm64],
        ("sub", false) => [Sub_r8_rm8, Sub_r16_rm16, Sub_r32_rm32, Sub_r64_rm64],
        ("xor", false) => [Xor_r8_rm8, Xor_r16_rm16, Xor_r32_rm32, Xor_r64_rm64],
        ("and", false) => [And_r8_rm8, And_r16_rm16, And_r32_rm32, And_r64_rm64],
        ("or", false) => [Or_r8_rm8, Or_r16_rm16, Or_r32_rm32, Or_r64_rm64],
        ("cmp", false) => [Cmp_r8_rm8, Cmp_r16_rm16, Cmp_r32_rm32, Cmp_r64_rm64],
        ("test", false) => [Test_rm8_r8, Test_rm16_r16, Test_rm32_r32, Test_rm64_r64],
        ("add", true) => [Add_rm8_imm8, Add_rm16_imm16, Add_rm32_imm32, Add_rm64_imm32],
        ("sub", true) => [Sub_rm8_imm8, Sub_rm16_imm16, Sub_rm32_imm32, Sub_rm64_imm32],
        ("cmp", true) => [Cmp_rm8_imm8, Cmp_rm16_imm16, Cmp_rm32_imm32, Cmp_rm64_imm32],
        _ => return None,
    };
    Some(
        codes[match width {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return None,
        }],
    )
}
fn encode_verified(instruction: &Instruction, bits: u32, ip: u64) -> PatchResult<Vec<u8>> {
    let mut encoder = Encoder::new(bits);
    encoder.encode(instruction, ip).map_err(err)?;
    let bytes = encoder.take_buffer();
    let mut decoder = Decoder::with_ip(bits, &bytes, ip, DecoderOptions::NONE);
    let decoded = decoder.decode();
    if decoded.is_invalid()
        || decoder.can_decode()
        || decoded.code() != instruction.code()
        || decoded.op_count() != instruction.op_count()
    {
        return Err(PatchError("encoder/decoder instruction mismatch".into()));
    }
    for operand in 0..decoded.op_count() {
        let kind = decoded.op_kind(operand);
        let matches = kind == instruction.op_kind(operand)
            && match kind {
                OpKind::Register => {
                    decoded.op_register(operand) == instruction.op_register(operand)
                }
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    decoded.near_branch_target() == instruction.near_branch_target()
                }
                _ => decoded.immediate(operand) == instruction.immediate(operand),
            };
        if !matches {
            return Err(PatchError("encoded operand differs after decoding".into()));
        }
    }
    Ok(bytes)
}
pub fn assemble(text: &str, bits: u32, origin: u64) -> PatchResult<Vec<u8>> {
    if !matches!(bits, 32 | 64)
        || text.len() > 16384
        || (bits == 32 && origin > u64::from(u32::MAX))
    {
        return Err(PatchError(
            "unsupported mode, origin or assembly input size".into(),
        ));
    }
    let lines: Vec<_> = text
        .split([';', '\n'])
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() || lines.len() > 64 {
        return Err(PatchError("enter 1..=64 supported instructions".into()));
    }
    let mut output = Vec::new();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        let mut pieces = lower.splitn(2, char::is_whitespace);
        let mnemonic = pieces.next().unwrap();
        let rest = pieces.next().unwrap_or("").trim();
        let operands: Vec<_> = if rest.is_empty() {
            vec![]
        } else {
            rest.split(',').map(str::trim).collect()
        };
        if operands.iter().any(|s| s.is_empty()) {
            return Err(PatchError("empty assembly operand".into()));
        }
        let ip = origin
            .checked_add(output.len() as u64)
            .ok_or_else(|| PatchError("assembly address overflow".into()))?;
        let instruction = if operands.is_empty() {
            Instruction::with(match mnemonic {
                "nop" => Code::Nopd,
                "ret" => {
                    if bits == 64 {
                        Code::Retnq
                    } else {
                        Code::Retnd
                    }
                }
                "int3" => Code::Int3,
                _ => return Err(PatchError("unsupported zero-operand instruction".into())),
            })
        } else if operands.len() == 1 && branch_code(mnemonic, bits, false).is_some() {
            let target = literal(operands[0])?;
            if bits == 32 && target > u64::from(u32::MAX) {
                return Err(PatchError("branch target exceeds 32-bit mode".into()));
            }
            let short = branch_code(mnemonic, bits, true)
                .and_then(|code| Instruction::with_branch(code, target).ok())
                .filter(|i| encode_verified(i, bits, ip).is_ok());
            short.unwrap_or(
                Instruction::with_branch(branch_code(mnemonic, bits, false).unwrap(), target)
                    .map_err(err)?,
            )
        } else if operands.len() == 2 {
            let first = register(operands[0]).ok_or_else(|| {
                PatchError("only general-register destinations are supported".into())
            })?;
            let width = first.size();
            if let Some(second) = register(operands[1]) {
                if second.size() != width {
                    return Err(PatchError("register widths differ".into()));
                }
                Instruction::with2(
                    reg_code(mnemonic, width, false)
                        .ok_or_else(|| PatchError("unsupported register operation".into()))?,
                    first,
                    second,
                )
                .map_err(err)?
            } else {
                let value = literal(operands[1])?;
                let code = reg_code(mnemonic, width, true)
                    .ok_or_else(|| PatchError("unsupported immediate operation".into()))?;
                if mnemonic == "mov" && width == 8 {
                    Instruction::with2(code, first, value).map_err(err)?
                } else {
                    let limit = if width == 8 {
                        u64::from(i32::MAX as u32)
                    } else {
                        (1u64 << (width * 8)) - 1
                    };
                    let signed_min = if width == 8 {
                        i64::from(i32::MIN)
                    } else {
                        -(1i64 << (width * 8 - 1))
                    };
                    if value > limit && (value as i64) >= 0 || (value as i64) < signed_min {
                        return Err(PatchError(
                            "immediate does not fit the encoded width/sign extension".into(),
                        ));
                    }
                    let immediate = if width < 4 {
                        (value & ((1u64 << (width * 8)) - 1)) as u32
                    } else {
                        value as u32
                    };
                    Instruction::with2(code, first, immediate).map_err(err)?
                }
            }
        } else {
            return Err(PatchError("unsupported assembly syntax; memory operands, labels and directives are not implemented".into()));
        };
        output.extend(encode_verified(&instruction, bits, ip)?);
        if bits == 32
            && origin
                .checked_add(output.len() as u64)
                .map_or(true, |end| end > 1u64 << 32)
        {
            return Err(PatchError(
                "assembled region crosses the 32-bit address boundary".into(),
            ));
        }
    }
    Ok(output)
}
fn listing(bytes: &[u8], bits: u32, address: u64) -> PatchResult<Vec<String>> {
    let mut decoder = Decoder::with_ip(bits, bytes, address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut lines = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() {
            return Err(PatchError(
                "instruction region is invalid or ends inside an instruction".into(),
            ));
        }
        let mut text = String::new();
        formatter.format(&i, &mut text);
        lines.push(format!("0x{:X}: {text}", i.ip()));
    }
    Ok(lines)
}
impl PatchDocument {
    pub fn preview_instruction(
        &self,
        address: Address,
        budget: usize,
        text: &str,
        nop_padding: bool,
        comment: &str,
    ) -> PatchResult<InstructionPreview> {
        if !self.instruction_supported {
            return Err(PatchError(
                "instruction assembly supports x86/x86-64 only".into(),
            ));
        }
        if budget > 256 {
            return Err(PatchError("instruction region exceeds 256 bytes".into()));
        }
        let offset = self.offset(address, budget)?;
        let origin = self.virtual_address(offset, budget).ok_or_else(|| {
            PatchError("instruction patch requires an unambiguous virtual origin".into())
        })?;
        let before = self.read(Address::FileOffset(offset), budget)?;
        let original_instructions = listing(&before, self.bitness, origin)?;
        let mut after = assemble(text, self.bitness, origin)?;
        if after.len() > budget || (after.len() < budget && !nop_padding) {
            return Err(PatchError("replacement size differs from the explicit region; enable NOP padding for shorter code".into()));
        }
        let padding_bytes = budget - after.len();
        after.resize(budget, 0x90);
        let replacement_instructions = listing(&after, self.bitness, origin)?;
        let mut patch = self.preview(Address::FileOffset(offset), &before, &after, comment)?;
        patch.kind = "instruction".into();
        Ok(InstructionPreview {schema_version:1,patch,address:format!("0x{origin:X}"),original_instructions,replacement_instructions,padding_bytes,verification:"iced-x86 encoder output decoded and checked against requested typed operands; execution not verified".into()})
    }
}
