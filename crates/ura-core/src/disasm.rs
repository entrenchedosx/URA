use crate::address::format_address;
use crate::binary::{Analysis, CpuArchitecture};
use crate::error::{Result, UraError};
use crate::MAX_INSTRUCTIONS;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionView {
    pub address: String,
    pub file_offset: Option<String>,
    pub bytes: String,
    pub length: usize,
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub flow: String,
    pub target: Option<String>,
    pub target_name: Option<String>,
    pub invalid: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisassemblyPage {
    pub start_address: String,
    pub end_address: String,
    pub section: String,
    pub architecture: String,
    pub instructions: Vec<InstructionView>,
    pub has_more: bool,
    pub warnings: Vec<String>,
}

pub struct DecodedBatch {
    pub instructions: Vec<InstructionView>,
    pub bytes_consumed: usize,
}

pub trait InstructionDecoder: Send + Sync {
    fn architecture_name(&self) -> &'static str;
    fn decode(
        &self,
        bytes: &[u8],
        start_address: u64,
        bitness: u8,
        file_offset: Option<u64>,
        count: usize,
    ) -> Result<DecodedBatch>;
}

pub struct X86Decoder;

impl InstructionDecoder for X86Decoder {
    fn architecture_name(&self) -> &'static str {
        "x86/x86-64"
    }

    fn decode(
        &self,
        bytes: &[u8],
        start_address: u64,
        bitness: u8,
        file_offset: Option<u64>,
        count: usize,
    ) -> Result<DecodedBatch> {
        if bitness != 32 && bitness != 64 {
            return Err(UraError::UnsupportedArchitecture(format!(
                "x86-{}",
                bitness
            )));
        }
        let mut decoder =
            Decoder::with_ip(bitness as u32, bytes, start_address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut instructions = Vec::with_capacity(count.min(512));

        while decoder.can_decode() && instructions.len() < count {
            let position = decoder.position();
            let instruction = decoder.decode();
            let length = instruction.len();
            if length == 0 {
                break;
            }
            let end = (position + length).min(bytes.len());
            let byte_slice = &bytes[position..end];
            let mut text = String::new();
            formatter.format(&instruction, &mut text);
            let mut mnemonic = String::new();
            formatter.format_mnemonic(&instruction, &mut mnemonic);
            let mut operands = String::new();
            for operand in 0..instruction.op_count() {
                if operand > 0 {
                    formatter.format_operand_separator(&instruction, &mut operands);
                }
                formatter
                    .format_operand(&instruction, &mut operands, operand)
                    .map_err(|err| UraError::Disassembly(err.to_string()))?;
            }
            let address = instruction.ip();
            instructions.push(InstructionView {
                address: format_address(address),
                file_offset: file_offset
                    .and_then(|offset| offset.checked_add(position as u64))
                    .map(format_address),
                bytes: byte_slice
                    .iter()
                    .map(|byte| format!("{:02X}", byte))
                    .collect::<Vec<_>>()
                    .join(" "),
                length,
                mnemonic,
                operands,
                text,
                flow: flow_name(instruction.flow_control()).to_string(),
                target: branch_target(&instruction).map(format_address),
                target_name: None,
                invalid: instruction.is_invalid(),
                privileged: instruction.is_privileged(),
            });
        }

        Ok(DecodedBatch {
            bytes_consumed: decoder.position(),
            instructions,
        })
    }
}

pub fn decoder_for(architecture: CpuArchitecture) -> Option<&'static dyn InstructionDecoder> {
    match architecture {
        CpuArchitecture::X86 | CpuArchitecture::X86_64 => Some(&X86Decoder),
        _ => None,
    }
}

pub fn disassemble(
    data: &[u8],
    analysis: &Analysis,
    address: u64,
    count: usize,
) -> Result<DisassemblyPage> {
    let count = count.clamp(1, MAX_INSTRUCTIONS);
    let section = analysis
        .code_section_containing_address(address)
        .ok_or_else(|| UraError::NoCodeAt(format_address(address)))?;
    let separator = section
        .file_offset
        .ok_or_else(|| UraError::UnmappedAddress(format_address(address)))?;
    let file_offset = analysis
        .address_to_file_offset(address)
        .ok_or_else(|| UraError::UnmappedAddress(format_address(address)))?;
    let available = section.file_size.saturating_sub(file_offset - separator);
    if available == 0 {
        return Err(UraError::UnmappedAddress(format_address(address)));
    }
    let byte_budget = (count.saturating_mul(15) as u64).min(available) as usize;
    let start = file_offset as usize;
    let end = (start + byte_budget).min(data.len());
    if start >= end {
        return Err(UraError::UnmappedAddress(format_address(address)));
    }
    let decoder = decoder_for(analysis.architecture).ok_or_else(|| {
        UraError::UnsupportedArchitecture(analysis.architecture.name().to_string())
    })?;
    let batch = decoder.decode(
        &data[start..end],
        address,
        analysis.bitness,
        Some(file_offset),
        count,
    )?;
    if batch.instructions.is_empty() {
        return Err(UraError::Disassembly(
            "decoder produced no instructions".to_string(),
        ));
    }
    let start_address = batch.instructions[0].address.clone();
    let end_address = address.saturating_add(batch.bytes_consumed as u64);
    let has_more = batch.bytes_consumed < available as usize;
    let invalid_count = batch
        .instructions
        .iter()
        .filter(|instruction| instruction.invalid)
        .count();
    let mut warnings = Vec::new();
    if invalid_count > 0 {
        warnings.push(format!(
            "{} invalid instruction{} encountered",
            invalid_count,
            if invalid_count == 1 { "" } else { "s" }
        ));
    }
    Ok(DisassemblyPage {
        start_address,
        end_address: format_address(end_address),
        section: section.name.clone(),
        architecture: decoder.architecture_name().to_string(),
        instructions: batch.instructions,
        has_more,
        warnings,
    })
}

fn flow_name(flow: FlowControl) -> &'static str {
    match flow {
        FlowControl::Next => "next",
        FlowControl::UnconditionalBranch => "jump",
        FlowControl::IndirectBranch => "indirect-jump",
        FlowControl::ConditionalBranch => "conditional-jump",
        FlowControl::Return => "return",
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "indirect-call",
        FlowControl::Interrupt => "interrupt",
        FlowControl::XbeginXabortXend => "transaction",
        FlowControl::Exception => "exception",
    }
}

fn branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            match instruction.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instruction.near_branch_target())
                }
                _ => None,
            }
        }
        _ => None,
    }
}
