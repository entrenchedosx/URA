//! Bounded import identity recovery. An import name is file evidence, not a
//! promise that a loaded library implements a particular prototype.
use std::collections::BTreeMap;

use object::endian::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData, PeFile};
use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget};
use serde::{Deserialize, Serialize};

use crate::ir::ssa::{SsaBlock, SsaStatement, Use};
use crate::ir::{Address, Constant, Operation, Type};
use crate::{AnalysisControl, LoadedBinary};

use super::abi::SignatureHints;
use super::api::{self, ApiFamily};
use super::signature::CallingConvention;

pub const MAX_BINDINGS: usize = 4_096;
const MAX_DESCRIPTORS: usize = 256;
const MAX_RELOCATIONS: usize = 8_192;
const MAX_SYMBOLS: usize = 8_192;
const MAX_THUNKS_PER_DESCRIPTOR: usize = 1_024;
const MAX_NAME_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportBinding {
    /// IAT/GOT slot, not executable code. Serialized without numeric precision loss.
    pub address: Address,
    pub library: Option<String>,
    pub name: String,
    pub ordinal: Option<u16>,
    pub method: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub bindings: Vec<ImportBinding>,
    pub truncated: bool,
}

pub fn bindings(binary: &LoadedBinary) -> Result<Vec<ImportBinding>, String> {
    let report = analyze_with_control(binary, &())?;
    if report.truncated {
        return Err(
            "import recovery exceeded a configured bound; use ImportReport for partial results"
                .into(),
        );
    }
    Ok(report.bindings)
}

pub fn analyze_with_control(
    binary: &LoadedBinary,
    control: &dyn AnalysisControl,
) -> Result<ImportReport, String> {
    check(control)?;
    let mut report = match binary.analysis().format.as_str() {
        "PE" => pe_bindings(binary.bytes(), control),
        "ELF" => elf_bindings(binary.bytes(), control),
        format => Err(format!("import tables are not handled for {format}")),
    }?;
    let mut slots = BTreeMap::new();
    for binding in &report.bindings {
        check(control)?;
        if let Some(previous) = slots.insert(binding.address, binding) {
            if previous != binding {
                return Err(format!(
                    "ambiguous import identities at {}",
                    binding.address
                ));
            }
        }
    }
    report.bindings = slots.into_values().cloned().collect();
    Ok(report)
}

fn check(control: &dyn AnalysisControl) -> Result<(), String> {
    if control.is_cancelled() {
        Err("import recovery cancelled".into())
    } else {
        Ok(())
    }
}

fn bounded_name(raw: &[u8], report: &mut ImportReport) -> Option<String> {
    if raw.len() > MAX_NAME_BYTES {
        report.truncated = true;
        return None;
    }
    match std::str::from_utf8(raw) {
        Ok(name) if !name.is_empty() => Some(name.to_owned()),
        _ => {
            report.truncated = true;
            None
        }
    }
}

fn pe_bindings(bytes: &[u8], control: &dyn AnalysisControl) -> Result<ImportReport, String> {
    let lfanew = u32::from_le_bytes(
        bytes
            .get(0x3c..0x40)
            .and_then(|raw| raw.try_into().ok())
            .ok_or("truncated PE header")?,
    ) as usize;
    let end = lfanew.checked_add(6).ok_or("PE header offset overflow")?;
    let header = bytes.get(lfanew..end).ok_or("truncated PE machine field")?;
    if &header[..4] != b"PE\0\0" {
        return Err("missing PE signature".into());
    }
    match u16::from_le_bytes([header[4], header[5]]) {
        0x14c => pe_slots::<object::pe::ImageNtHeaders32>(bytes, control),
        0x8664 => pe_slots::<object::pe::ImageNtHeaders64>(bytes, control),
        machine => Err(format!("unsupported PE machine type {machine:#06x}")),
    }
}

fn pe_slots<Pe: ImageNtHeaders>(
    bytes: &[u8],
    control: &dyn AnalysisControl,
) -> Result<ImportReport, String> {
    let file = PeFile::<Pe, &[u8]>::parse(bytes).map_err(|err| err.to_string())?;
    let mut report = ImportReport::default();
    let Some(table) = file.import_table().map_err(|err| err.to_string())? else {
        return Ok(report);
    };
    let mut descriptors = table.descriptors().map_err(|err| err.to_string())?;
    let image_base = file.nt_headers().optional_header().image_base();
    let thunk_size = std::mem::size_of::<Pe::ImageThunkData>() as u64;
    for _ in 0..MAX_DESCRIPTORS {
        check(control)?;
        let Some(descriptor) = descriptors.next().map_err(|err| err.to_string())? else {
            return Ok(report);
        };
        let library = bounded_name(
            table
                .name(descriptor.name.get(LE))
                .map_err(|err| err.to_string())?,
            &mut report,
        );
        let slot_rva = descriptor.first_thunk.get(LE);
        let original = descriptor.original_first_thunk.get(LE);
        let lookup = if original == 0 { slot_rva } else { original };
        let mut names = table.thunks(lookup).map_err(|err| err.to_string())?;
        // Validate slot storage independently; lookup entries may differ in a bound image.
        let mut slots = table.thunks(slot_rva).map_err(|err| err.to_string())?;
        let mut terminated = false;
        for index in 0..MAX_THUNKS_PER_DESCRIPTOR {
            check(control)?;
            let Some(thunk) = names.next::<Pe>().map_err(|err| err.to_string())? else {
                terminated = true;
                break;
            };
            if slots.next::<Pe>().map_err(|err| err.to_string())?.is_none() {
                return Err("PE import lookup and IAT lengths disagree".into());
            }
            let ordinal = thunk.is_ordinal().then(|| thunk.ordinal());
            let name = if let Some(ordinal) = ordinal {
                format!("#{ordinal}")
            } else {
                let (_, raw) = table
                    .hint_name(thunk.address())
                    .map_err(|err| err.to_string())?;
                let Some(name) = bounded_name(raw, &mut report) else {
                    continue;
                };
                name
            };
            let address = image_base
                .checked_add(u64::from(slot_rva))
                .and_then(|base| base.checked_add(index as u64 * thunk_size))
                .ok_or("PE import slot address overflow")?;
            if report.bindings.len() == MAX_BINDINGS {
                report.truncated = true;
                return Ok(report);
            }
            report.bindings.push(ImportBinding {
                address: Address(address),
                library: library.clone(),
                name,
                ordinal,
                method: "peImportAddressTable".into(),
            });
        }
        if !terminated {
            report.truncated = true;
        }
    }
    report.truncated = true;
    Ok(report)
}

fn elf_bindings(bytes: &[u8], control: &dyn AnalysisControl) -> Result<ImportReport, String> {
    let file = object::File::parse(bytes).map_err(|err| err.to_string())?;
    // Relocation numbers are architecture specific. Do not interpret ARM values
    // as x86 imports. PLT code and library/version ownership are not guessed.
    let supported = match file.architecture() {
        object::Architecture::I386 | object::Architecture::X86_64 => [6, 7],
        architecture => {
            return Err(format!(
                "unsupported ELF import architecture {architecture:?}"
            ))
        }
    };
    let mut report = ImportReport::default();
    let mut numbers = BTreeMap::new();
    for (examined, symbol) in file.dynamic_symbols().enumerate() {
        check(control)?;
        if examined == MAX_SYMBOLS {
            report.truncated = true;
            break;
        }
        if symbol.is_undefined() && symbol.index().0 != 0 {
            let name = match symbol.name_bytes() {
                Ok(raw) => bounded_name(raw, &mut report),
                Err(_) => {
                    report.truncated = true;
                    None
                }
            };
            if let Some(name) = name {
                numbers.insert(symbol.index().0, name);
            }
        }
    }
    let Some(relocations) = file.dynamic_relocations() else {
        return Ok(report);
    };
    let mut mapped = BTreeMap::new();
    for (examined, (target, relocation)) in relocations.enumerate() {
        check(control)?;
        if examined == MAX_RELOCATIONS || mapped.len() == MAX_BINDINGS {
            report.truncated = true;
            break;
        }
        let RelocationFlags::Elf { r_type } = relocation.flags() else {
            continue;
        };
        if !supported.contains(&r_type) {
            continue;
        }
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        if let Some(name) = numbers.get(&index.0) {
            if let Some(previous) = mapped.insert(target, name.clone()) {
                if previous != *name {
                    return Err(format!(
                        "ambiguous ELF import identities at {}",
                        Address(target)
                    ));
                }
            }
        }
    }
    report.bindings = mapped
        .into_iter()
        .map(|(address, name)| ImportBinding {
            address: Address(address),
            library: None,
            name,
            ordinal: None,
            method: "elfDynamicRelocation".into(),
        })
        .collect();
    Ok(report)
}

/// Only exact symbols in a deliberately small set of documented PE libraries
/// receive prototypes. ELF has no recovered symbol-to-library/version ownership
/// here, so its identities never automatically acquire curated signatures.
fn convention(binary: &LoadedBinary, binding: &ImportBinding) -> Option<CallingConvention> {
    if binary.analysis().format != "PE" || binding.ordinal.is_some() {
        return None;
    }
    let library = binding.library.as_ref()?.to_ascii_lowercase();
    let prototype = api::API_DATABASE
        .iter()
        .find(|api| api.name == binding.name)?;
    let trusted = match prototype.family {
        ApiFamily::C => matches!(library.as_str(), "msvcrt.dll" | "ucrtbase.dll"),
        ApiFamily::Win64 if matches!(prototype.name, "MessageBoxA" | "MessageBoxW") => {
            library == "user32.dll"
        }
        ApiFamily::Win64 => matches!(library.as_str(), "kernel32.dll" | "kernelbase.dll"),
    };
    if !trusted {
        return None;
    }
    Some(if binary.analysis().bitness == 64 {
        CallingConvention::Win64
    } else if prototype.family == ApiFamily::C {
        CallingConvention::Cdecl
    } else {
        CallingConvention::Stdcall
    })
}

pub fn hydrate(binary: &LoadedBinary, hints: &mut SignatureHints) -> (Vec<String>, usize) {
    hydrate_with_control(binary, hints, &())
        .unwrap_or_else(|error| (vec![format!("import recovery unavailable: {error}")], 0))
}

pub fn prototype(
    binary: &LoadedBinary,
    binding: &ImportBinding,
) -> Option<super::FunctionSignature> {
    let convention = convention(binary, binding)?;
    let mut signature =
        super::imported_signature(&binding.name, convention, binary.analysis().bitness as u16)?
            .ok()?;
    signature.function = binding.address.0;
    for evidence in &mut signature.evidence {
        evidence.address = Some(binding.address.0);
        evidence.detail = format!("{}!{} at {}: exact import identity and curated prototype; loaded implementation is not verified", binding.library.as_deref().unwrap_or("?"), binding.name, binding.address);
    }
    Some(signature)
}

pub fn hydrate_with_control(
    binary: &LoadedBinary,
    hints: &mut SignatureHints,
    control: &dyn AnalysisControl,
) -> Result<(Vec<String>, usize), String> {
    let report = analyze_with_control(binary, control)?;
    let mut notes = Vec::new();
    let mut count = 0;
    for binding in report.bindings {
        check(control)?;
        if hints.get(binding.address.0).is_some() {
            continue;
        }
        let Some(convention) = convention(binary, &binding) else {
            continue;
        };
        let Some(Ok(mut signature)) =
            super::imported_signature(&binding.name, convention, binary.analysis().bitness as u16)
        else {
            continue;
        };
        signature.function = binding.address.0;
        let detail = format!("{}!{} at {} was hydrated from import tables (curated prototype; library behavior is not verified)", binding.library.as_deref().unwrap_or("?"), binding.name, binding.address);
        for evidence in &mut signature.evidence {
            evidence.address = Some(binding.address.0);
            evidence.detail = detail.clone();
        }
        if notes.len() < 16 {
            notes.push(format!("call target {detail}"));
        }
        hints.insert(signature);
        count += 1;
    }
    if count > 16 {
        notes.push(format!(
            "{} additional imported prototype notes omitted",
            count - 16
        ));
    }
    if report.truncated {
        notes.push("import recovery hit a configured bound and is incomplete".into());
    }
    Ok((notes, count))
}

/// Follow only in-block copy/address casts to a load from a constant slot.
/// Loading an arbitrary constant address is not itself an import: callers must
/// also require a signature bound to that exact address.
pub fn slot_for_call(
    block: &SsaBlock,
    call: &SsaStatement,
    constants: &BTreeMap<crate::ir::ssa::Value, Constant>,
) -> Option<u64> {
    let mut current = *call.args.first()?;
    for _ in 0..8 {
        let Use::Value(value) = current else {
            return None;
        };
        let definition = block
            .statements
            .iter()
            .take_while(|statement| !std::ptr::eq(*statement, call))
            .find(|statement| statement.output == Some(value))?;
        match definition.op {
            Operation::Load => {
                let constant = match definition.args.get(1)? {
                    Use::Constant(constant) => *constant,
                    Use::Value(value) => *constants.get(value)?,
                };
                return matches!(constant.ty, Type::Address(_)).then_some(constant.value.0);
            }
            Operation::ToAddress | Operation::Copy => current = *definition.args.first()?,
            _ => return None,
        }
    }
    None
}
