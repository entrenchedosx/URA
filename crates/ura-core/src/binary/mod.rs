use crate::address::format_address;
use crate::error::{Result, UraError};
use crate::{
    disasm, hex, sha256_hex, strings, DisassemblyPage, HexPage, StringScanOptions,
    StringScanResult, MAX_EXPORTS, MAX_FILE_SIZE, MAX_IMPORTS, MAX_SYMBOLS,
};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod mapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuArchitecture {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Riscv32,
    Riscv64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    Other,
}

impl CpuArchitecture {
    pub fn name(self) -> &'static str {
        match self {
            CpuArchitecture::X86 => "x86",
            CpuArchitecture::X86_64 => "x86-64",
            CpuArchitecture::Arm => "arm",
            CpuArchitecture::Aarch64 => "arm64",
            CpuArchitecture::Riscv32 => "riscv32",
            CpuArchitecture::Riscv64 => "riscv64",
            CpuArchitecture::Mips => "mips",
            CpuArchitecture::Mips64 => "mips64",
            CpuArchitecture::PowerPc => "powerpc",
            CpuArchitecture::PowerPc64 => "powerpc64",
            CpuArchitecture::Other => "unknown",
        }
    }

    pub fn supports_disassembly(self) -> bool {
        matches!(
            self,
            CpuArchitecture::X86
                | CpuArchitecture::X86_64
                | CpuArchitecture::Aarch64
                | CpuArchitecture::Arm
                | CpuArchitecture::Riscv32
                | CpuArchitecture::Riscv64
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    pub fn name(self) -> &'static str {
        match self {
            Endianness::Little => "little",
            Endianness::Big => "big",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: Option<u64>,
    pub file_size: u64,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
    pub kind: String,
}

impl Section {
    pub fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.address && address < self.end_address()
    }

    pub fn contains_file_offset(&self, offset: u64) -> bool {
        match self.file_offset {
            Some(start) => offset >= start && offset < start.saturating_add(self.file_size),
            None => false,
        }
    }

    pub fn file_offset_for_address(&self, address: u64) -> Option<u64> {
        if !self.contains_address(address) {
            return None;
        }
        let delta = address - self.address;
        if delta >= self.file_size {
            return None;
        }
        self.file_offset.and_then(|start| start.checked_add(delta))
    }

    pub fn address_for_file_offset(&self, offset: u64) -> Option<u64> {
        if !self.contains_file_offset(offset) {
            return None;
        }
        let start = self.file_offset?;
        self.address.checked_add(offset - start)
    }

    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable { 'r' } else { '-' },
            if self.writable { 'w' } else { '-' },
            if self.executable { 'x' } else { '-' }
        )
    }

    pub fn view(&self) -> SectionView {
        SectionView {
            name: self.name.clone(),
            address: format_address(self.address),
            size: self.size,
            file_offset: self.file_offset.map(format_address),
            file_size: self.file_size,
            permissions: self.permissions(),
            executable: self.executable,
            readable: self.readable,
            writable: self.writable,
            kind: self.kind.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: Option<u64>,
    pub size: u64,
    pub kind: String,
    pub scope: String,
    pub section: Option<String>,
    pub defined: bool,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub library: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub format: String,
    pub architecture: CpuArchitecture,
    pub bitness: u8,
    pub endianness: Endianness,
    pub image_base: u64,
    pub entry_point: Option<u64>,
    pub object_kind: String,
    pub has_symbols: bool,
    pub has_debug_symbols: bool,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub warnings: Vec<String>,
}

impl Analysis {
    pub fn section_view_list(&self) -> Vec<SectionView> {
        self.sections.iter().map(Section::view).collect()
    }

    pub fn symbol_view_list(&self) -> Vec<SymbolView> {
        self.symbols
            .iter()
            .map(|symbol| SymbolView {
                name: symbol.name.clone(),
                address: symbol.address.map(format_address),
                size: symbol.size,
                kind: symbol.kind.clone(),
                scope: symbol.scope.clone(),
                section: symbol.section.clone(),
                defined: symbol.defined,
            })
            .collect()
    }

    pub fn import_view_list(&self) -> Vec<ImportView> {
        self.imports
            .iter()
            .map(|import| ImportView {
                library: import.library.clone(),
                name: import.name.clone(),
            })
            .collect()
    }

    pub fn export_view_list(&self) -> Vec<ExportView> {
        self.exports
            .iter()
            .map(|export| ExportView {
                name: export.name.clone(),
                address: format_address(export.address),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryView {
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub format: String,
    pub architecture: String,
    pub processor: serde_json::Value,
    pub bitness: u8,
    pub endianness: String,
    pub image_base: String,
    pub entry_point: Option<String>,
    pub object_kind: String,
    pub has_symbols: bool,
    pub has_debug_symbols: bool,
    pub symbol_count: usize,
    pub section_count: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionView {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub file_offset: Option<String>,
    pub file_size: u64,
    pub permissions: String,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolView {
    pub name: String,
    pub address: Option<String>,
    pub size: u64,
    pub kind: String,
    pub scope: String,
    pub section: Option<String>,
    pub defined: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportView {
    pub library: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportView {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryOpenResult {
    pub info: BinaryView,
    pub sections: Vec<SectionView>,
    pub symbols: Vec<SymbolView>,
    pub imports: Vec<ImportView>,
    pub exports: Vec<ExportView>,
}

pub struct LoadedBinary {
    path: PathBuf,
    file_name: String,
    bytes: Arc<Vec<u8>>,
    analysis: Analysis,
}

impl LoadedBinary {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Share immutable bytes with a sparse patch overlay without another file copy.
    pub fn shared_bytes(&self) -> Arc<Vec<u8>> {
        self.bytes.clone()
    }

    pub fn analysis(&self) -> &Analysis {
        &self.analysis
    }

    pub fn view(&self) -> BinaryView {
        BinaryView {
            path: self.path.to_string_lossy().to_string(),
            file_name: self.file_name.clone(),
            file_size: self.bytes.len() as u64,
            sha256: sha256_hex(&self.bytes),
            format: self.analysis.format.clone(),
            architecture: self.analysis.architecture.name().to_string(),
            processor: crate::processor::Processor::for_analysis(&self.analysis)
                .map(|p| p.metadata())
                .unwrap_or_else(|e| serde_json::json!({"supported":false,"diagnostic":e})),
            bitness: self.analysis.bitness,
            endianness: self.analysis.endianness.name().to_string(),
            image_base: format_address(self.analysis.image_base),
            entry_point: self.analysis.entry_point.map(format_address),
            object_kind: self.analysis.object_kind.clone(),
            has_symbols: self.analysis.has_symbols,
            has_debug_symbols: self.analysis.has_debug_symbols,
            symbol_count: self.analysis.symbols.len(),
            section_count: self.analysis.sections.len(),
            warnings: self.analysis.warnings.clone(),
        }
    }

    pub fn open_result(&self) -> BinaryOpenResult {
        BinaryOpenResult {
            info: self.view(),
            sections: self.analysis.section_view_list(),
            symbols: self.analysis.symbol_view_list(),
            imports: self.analysis.import_view_list(),
            exports: self.analysis.export_view_list(),
        }
    }

    pub fn disassemble(&self, address: u64, count: usize) -> Result<DisassemblyPage> {
        disasm::disassemble(&self.bytes, &self.analysis, address, count)
    }

    pub fn read_hex(&self, offset: u64, length: usize) -> Result<HexPage> {
        hex::read_hex_page(&self.bytes, &self.analysis, offset, length)
    }

    /// File-backed bytes for a virtual address range. Returns `None` when any
    /// part of the range is unmapped or only backed by zero-fill.
    pub fn bytes_at_address(&self, address: u64, length: usize) -> Option<&[u8]> {
        if length == 0 {
            return Some(&[]);
        }
        let section = self.analysis.section_containing_address(address)?;
        let offset = section.file_offset_for_address(address)? as usize;
        let available =
            (section.file_size as usize).saturating_sub((address - section.address) as usize);
        if length > available {
            return None;
        }
        self.bytes.get(offset..offset.checked_add(length)?)
    }

    pub fn extract_strings(&self, options: &StringScanOptions) -> Result<StringScanResult> {
        Ok(strings::extract_strings(
            &self.bytes,
            &self.analysis,
            options,
        ))
    }
}

pub fn analyze_path(path: &Path) -> Result<LoadedBinary> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    if size > MAX_FILE_SIZE {
        return Err(UraError::FileTooLarge {
            size,
            limit: MAX_FILE_SIZE,
        });
    }
    let bytes = std::fs::read(path)?;
    analyze_bytes(path, bytes)
}

/// Explicit raw loading. No virtual mapping is invented without a base.
pub fn analyze_raw_path(path: &Path, base: Option<u64>, bitness: u32) -> Result<LoadedBinary> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size > MAX_FILE_SIZE {
        return Err(UraError::FileTooLarge {
            size,
            limit: MAX_FILE_SIZE,
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes)?;
    analyze_raw_bytes(path, bytes, base, bitness)
}
pub fn analyze_raw_bytes(
    path: &Path,
    bytes: Vec<u8>,
    base: Option<u64>,
    bitness: u32,
) -> Result<LoadedBinary> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(UraError::InvalidRange);
    }
    if !matches!(bitness, 32 | 64)
        || base.is_some_and(|b| {
            b.checked_add(bytes.len() as u64)
                .map_or(true, |end| bitness == 32 && end > 1u64 << 32)
        })
    {
        return Err(UraError::InvalidAddress(
            "invalid raw mode/base range".into(),
        ));
    }
    let sections = base
        .map(|address| {
            vec![Section {
                name: "raw".into(),
                address,
                size: bytes.len() as u64,
                file_offset: Some(0),
                file_size: bytes.len() as u64,
                executable: true,
                readable: true,
                writable: true,
                kind: "raw".into(),
            }]
        })
        .unwrap_or_default();
    let analysis=Analysis {format:"raw".into(),architecture:if bitness==32 {CpuArchitecture::X86} else {CpuArchitecture::X86_64},bitness:bitness as u8,endianness:Endianness::Little,image_base:base.unwrap_or(0),entry_point:base,object_kind:"explicit raw image".into(),has_symbols:false,has_debug_symbols:false,sections,symbols:vec![],imports:vec![],exports:vec![],warnings:vec!["Raw image: processor mode/base are user-supplied; no loader metadata or execution is verified.".into()]};
    Ok(LoadedBinary {
        path: path.to_path_buf(),
        file_name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        bytes: Arc::new(bytes),
        analysis,
    })
}
pub fn analyze_bytes(path: &Path, bytes: Vec<u8>) -> Result<LoadedBinary> {
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(UraError::FileTooLarge {
            size: bytes.len() as u64,
            limit: MAX_FILE_SIZE,
        });
    }
    if bytes.is_empty() {
        return Err(UraError::Parse("file is empty".to_string()));
    }

    let file = object::File::parse(bytes.as_slice())?;
    let format = file.format();
    let format_name = match format {
        object::BinaryFormat::Pe => "PE",
        object::BinaryFormat::Elf => "ELF",
        object::BinaryFormat::MachO => "Mach-O",
        object::BinaryFormat::Coff => {
            return Err(UraError::UnsupportedFormat(
                "COFF relocatable objects are not supported in v0.1; load a linked PE, ELF or Mach-O image"
                    .to_string(),
            ))
        }
        object::BinaryFormat::Wasm => {
            return Err(UraError::UnsupportedFormat(
                "WebAssembly modules are not supported in v0.1".to_string(),
            ))
        }
        object::BinaryFormat::Xcoff => {
            return Err(UraError::UnsupportedFormat(
                "XCOFF images are not supported in v0.1".to_string(),
            ))
        }
        other => {
            return Err(UraError::UnsupportedFormat(format!(
                "{:?} images are not supported in v0.1",
                other
            )))
        }
    };

    let architecture = match file.architecture() {
        object::Architecture::I386 => CpuArchitecture::X86,
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => CpuArchitecture::X86_64,
        object::Architecture::Arm => CpuArchitecture::Arm,
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => {
            CpuArchitecture::Aarch64
        }
        object::Architecture::Riscv32 => CpuArchitecture::Riscv32,
        object::Architecture::Riscv64 => CpuArchitecture::Riscv64,
        object::Architecture::Mips => CpuArchitecture::Mips,
        object::Architecture::Mips64 | object::Architecture::Mips64_N32 => CpuArchitecture::Mips64,
        object::Architecture::PowerPc => CpuArchitecture::PowerPc,
        object::Architecture::PowerPc64 => CpuArchitecture::PowerPc64,
        _ => CpuArchitecture::Other,
    };

    let mut warnings = Vec::new();
    let image_base = if format == object::BinaryFormat::Elf {
        elf_image_base(&file).unwrap_or(0)
    } else {
        file.relative_address_base()
    };

    let mut sections = Vec::new();
    let mut section_names: HashMap<usize, String> = HashMap::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("<invalid>").to_string();
        let file_range = section.file_range();
        let (file_offset, file_size) = match file_range {
            Some((offset, size)) => (Some(offset), size),
            None => (None, 0),
        };
        let kind = section.kind();
        let mut executable = false;
        let mut readable = false;
        let mut writable = false;
        match section.flags() {
            SectionFlags::Coff { characteristics } => {
                executable |= characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0;
                readable |= characteristics & object::pe::IMAGE_SCN_MEM_READ != 0;
                writable |= characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0;
            }
            SectionFlags::Elf { sh_flags } => {
                executable |= sh_flags & object::elf::SHF_EXECINSTR as u64 != 0;
                readable |= sh_flags & object::elf::SHF_ALLOC as u64 != 0;
                writable |= sh_flags & object::elf::SHF_WRITE as u64 != 0;
            }
            SectionFlags::MachO { .. } => {
                readable = true;
            }
            _ => {}
        }
        executable |= kind == SectionKind::Text;
        match kind {
            SectionKind::Text | SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => {
                readable = true;
            }
            SectionKind::Data
            | SectionKind::UninitializedData
            | SectionKind::Common
            | SectionKind::Tls => {
                readable = true;
                writable = true;
            }
            _ => {}
        }
        let size = if section.size() == 0 {
            file_size
        } else {
            section.size()
        };
        section_names.insert(section.index().0, name.clone());
        sections.push(Section {
            name,
            address: section.address(),
            size,
            file_offset,
            file_size,
            executable,
            readable,
            writable,
            kind: section_kind_name(kind).to_string(),
        });
    }

    let mut symbols = Vec::new();
    let mut symbol_total = 0usize;
    for symbol in file.symbols() {
        let name = match symbol.name() {
            Ok(name) if !name.is_empty() => name.to_string(),
            _ => String::new(),
        };
        if name.is_empty() {
            continue;
        }
        symbol_total += 1;
        if symbols.len() >= MAX_SYMBOLS {
            continue;
        }
        let address = symbol.address();
        let defined = symbol.is_definition();
        symbols.push(Symbol {
            name,
            address: if address == 0 { None } else { Some(address) },
            size: symbol.size(),
            kind: symbol_kind_name(symbol.kind()).to_string(),
            scope: symbol_scope_name(symbol.scope()).to_string(),
            section: symbol
                .section_index()
                .and_then(|index| section_names.get(&index.0).cloned()),
            defined,
        });
    }
    if symbol_total > MAX_SYMBOLS {
        warnings.push(format!(
            "symbol table truncated at {} entries ({} total)",
            MAX_SYMBOLS, symbol_total
        ));
    }
    symbols.sort_by(|left, right| {
        let left_key = (
            left.address.is_none(),
            left.address.unwrap_or(0),
            &left.name,
        );
        let right_key = (
            right.address.is_none(),
            right.address.unwrap_or(0),
            &right.name,
        );
        left_key.cmp(&right_key)
    });

    let mut imports = Vec::new();
    match file.imports() {
        Ok(entries) => {
            for entry in entries {
                if imports.len() >= MAX_IMPORTS {
                    warnings.push(format!("import list truncated at {} entries", MAX_IMPORTS));
                    break;
                }
                let name = String::from_utf8_lossy(entry.name()).to_string();
                if name.is_empty() {
                    continue;
                }
                let library = String::from_utf8_lossy(entry.library()).to_string();
                imports.push(ImportInfo {
                    library: if library.is_empty() {
                        None
                    } else {
                        Some(library)
                    },
                    name,
                });
            }
        }
        Err(err) => warnings.push(format!("imports could not be read: {}", err)),
    }

    let mut exports = Vec::new();
    match file.exports() {
        Ok(entries) => {
            for entry in entries {
                if exports.len() >= MAX_EXPORTS {
                    warnings.push(format!("export list truncated at {} entries", MAX_EXPORTS));
                    break;
                }
                let name = String::from_utf8_lossy(entry.name()).to_string();
                if name.is_empty() {
                    continue;
                }
                exports.push(ExportInfo {
                    name,
                    address: entry.address(),
                });
            }
        }
        Err(err) => warnings.push(format!("exports could not be read: {}", err)),
    }

    let has_symbols = !symbols.is_empty();
    let has_debug_symbols = file.has_debug_symbols();
    let mut entry_point = file.entry();
    if entry_point == 0 || (format == object::BinaryFormat::Pe && entry_point == image_base) {
        entry_point = 0;
    }
    if !architecture.supports_disassembly() {
        warnings.push(format!(
            "architecture {} is parsed but not yet disassembled by URA",
            architecture.name()
        ));
    }

    let analysis = Analysis {
        format: format_name.to_string(),
        architecture,
        bitness: if file.is_64() { 64 } else { 32 },
        endianness: if file.is_little_endian() {
            Endianness::Little
        } else {
            Endianness::Big
        },
        image_base,
        entry_point: if entry_point == 0 {
            None
        } else {
            Some(entry_point)
        },
        object_kind: object_kind_name(file.kind()).to_string(),
        has_symbols,
        has_debug_symbols,
        sections,
        symbols,
        imports,
        exports,
        warnings,
    };

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string());

    Ok(LoadedBinary {
        path: path.to_path_buf(),
        file_name,
        bytes: Arc::new(bytes),
        analysis,
    })
}

fn elf_image_base(file: &object::File<'_>) -> Option<u64> {
    let mut base: Option<u64> = None;
    for segment in file.segments() {
        let (offset, _) = segment.file_range();
        let address = segment.address();
        let candidate = address.checked_sub(offset).unwrap_or(address);
        base = Some(match base {
            Some(current) => current.min(candidate),
            None => candidate,
        });
    }
    base
}

fn section_kind_name(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::Unknown => "unknown",
        SectionKind::Text => "text",
        SectionKind::Data => "data",
        SectionKind::ReadOnlyData => "rodata",
        SectionKind::ReadOnlyDataWithRel => "rodata-rel",
        SectionKind::ReadOnlyString => "string",
        SectionKind::UninitializedData => "bss",
        SectionKind::Common => "common",
        SectionKind::Tls => "tls",
        SectionKind::Debug => "debug",
        SectionKind::DebugString => "debug-string",
        SectionKind::Other => "other",
        SectionKind::OtherString => "other-string",
        SectionKind::Metadata => "metadata",
        SectionKind::Note => "note",
        SectionKind::Linker => "linker",
        _ => "unknown",
    }
}

fn symbol_kind_name(kind: object::SymbolKind) -> &'static str {
    match kind {
        object::SymbolKind::Unknown => "unknown",
        object::SymbolKind::Text => "function",
        object::SymbolKind::Data => "data",
        object::SymbolKind::Section => "section",
        object::SymbolKind::File => "file",
        object::SymbolKind::Label => "label",
        object::SymbolKind::Tls => "tls",
        _ => "unknown",
    }
}

fn symbol_scope_name(scope: object::SymbolScope) -> &'static str {
    match scope {
        object::SymbolScope::Unknown => "unknown",
        object::SymbolScope::Compilation => "local",
        object::SymbolScope::Linkage => "linkage",
        object::SymbolScope::Dynamic => "global",
    }
}

fn object_kind_name(kind: object::ObjectKind) -> &'static str {
    match kind {
        object::ObjectKind::Unknown => "unknown",
        object::ObjectKind::Relocatable => "relocatable",
        object::ObjectKind::Executable => "executable",
        object::ObjectKind::Dynamic => "dynamic",
        object::ObjectKind::Core => "core",
        _ => "unknown",
    }
}

/// Explicit raw processor selection; legacy raw API remains x86/x64.
pub fn analyze_raw_processor_bytes(
    path: &Path,
    bytes: Vec<u8>,
    base: Option<u64>,
    processor: crate::processor::Processor,
) -> Result<LoadedBinary> {
    if base.is_some_and(|a| a % processor.alignment() != 0) {
        return Err(UraError::InvalidAddress(
            "raw base must align to the explicitly selected instruction mode".into(),
        ));
    }
    let mut binary = analyze_raw_bytes(path, bytes, base, u32::from(processor.bits()))?;
    binary.analysis.architecture = processor.architecture();
    binary.analysis.object_kind = format!("explicit raw image ({})", processor.name());
    Ok(binary)
}

pub fn analyze_raw_processor_path(
    path: &Path,
    base: Option<u64>,
    processor: crate::processor::Processor,
) -> Result<LoadedBinary> {
    let binary = analyze_raw_path(path, base, u32::from(processor.bits()))?;
    analyze_raw_processor_bytes(path, binary.bytes().to_vec(), base, processor)
}
