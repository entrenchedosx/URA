use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ura_core::binary::{ExportView, ImportView};
use ura_core::{
    analyze_binary_with_seeds, analyze_path, format_address, parse_address, AnalysisOptions,
    AnalysisSeed, BinaryView, Function, FunctionOrigin, LoadedBinary, ProgramAnalysis, SectionView,
    StringScanOptions, UraError, Xref, XrefKind,
};
use ura_project::{BinaryIdentity, ProjectSnapshot};

use crate::dto::{
    AnalysisOptionsView, AnalyzeResponse, BinaryInfoResponse, BlockSummary, BytesResponse,
    CfgBlock, CfgResponse, CloseBinaryResponse, CommentResponse, DisassemblyResponse, EdgeView,
    ExportResponse, FunctionDetailResponse, FunctionListResponse, FunctionRef, FunctionSort,
    FunctionSummary, OpenBinaryResponse, RenameFunctionResponse, SaveProjectResponse,
    StringsResponse, XrefDirection, XrefView, XrefsResponse,
};
use crate::error::{ServiceError, ServiceResult};
use crate::paths::{display_path, PathPolicy};
use crate::RESPONSE_SCHEMA_VERSION;

pub struct Service {
    policy: PathPolicy,
    writes_enabled: bool,
    next_handle: u64,
    sessions: BTreeMap<String, Session>,
}

struct Session {
    binary: LoadedBinary,
    info: BinaryView,
    sections: Vec<SectionView>,
    imports: Vec<ImportView>,
    exports: Vec<ExportView>,
    project: Option<PathBuf>,
    names: BTreeMap<u64, String>,
    manual: Vec<u64>,
    analysis: Option<ProgramAnalysis>,
}

impl Service {
    pub fn new(policy: PathPolicy, writes_enabled: bool) -> Self {
        Self {
            policy,
            writes_enabled,
            next_handle: 1,
            sessions: BTreeMap::new(),
        }
    }

    pub fn open_binary(
        &mut self,
        path: &Path,
        project: Option<&Path>,
    ) -> ServiceResult<OpenBinaryResponse> {
        let resolved = self.policy.allow_read(path)?;
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let binary = analyze_path(&resolved)?;
        let mut open = binary.open_result();
        let mut names = BTreeMap::new();
        let mut manual = Vec::new();
        let mut attached_project = None;

        if let Some(project_path) = project {
            // This resolution also validates missing paths without writing.
            let project_resolved = self.policy.allow_write(project_path)?;
            let snapshot = ura_project::read_project(&project_resolved)?;
            if !snapshot
                .project
                .binary_hash
                .eq_ignore_ascii_case(&open.info.sha256)
            {
                return Err(ServiceError::ProjectBinaryMismatch);
            }
            names = names_from_snapshot(&snapshot);
            manual = manual_from_snapshot(&snapshot);
            attached_project = Some(display_path(&project_resolved));
        }

        let handle = format!("bin{}", self.next_handle);
        self.next_handle += 1;
        open.info.path = display_path(&absolute);

        let response = OpenBinaryResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.clone(),
            attached_project: attached_project.clone(),
            info: open.info.clone(),
            sections: open.sections.clone(),
            imports: open.imports.clone(),
            exports: open.exports.clone(),
        };

        self.sessions.insert(
            handle,
            Session {
                binary,
                info: open.info,
                sections: open.sections,
                imports: open.imports,
                exports: open.exports,
                project: attached_project.map(PathBuf::from),
                names,
                manual,
                analysis: None,
            },
        );

        Ok(response)
    }

    pub fn info(&self, handle: &str) -> ServiceResult<BinaryInfoResponse> {
        let session = self.session(handle)?;
        Ok(BinaryInfoResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            attached_project: session.project.as_deref().map(display_path),
            analyzed: session.analysis.is_some(),
            function_count: session
                .analysis
                .as_ref()
                .map(|analysis| analysis.functions.len()),
            info: session.info.clone(),
            sections: session.sections.clone(),
            imports: session.imports.clone(),
            exports: session.exports.clone(),
        })
    }

    pub fn close_binary(&mut self, handle: &str) -> ServiceResult<CloseBinaryResponse> {
        let closed = self.sessions.remove(handle).is_some();
        if !closed {
            return Err(ServiceError::UnknownHandle(handle.to_string()));
        }
        Ok(CloseBinaryResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            closed,
        })
    }

    pub fn analyze(
        &mut self,
        handle: &str,
        options: &AnalysisOptions,
    ) -> ServiceResult<AnalyzeResponse> {
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        let normalized = options.normalized();
        let seeds: Vec<AnalysisSeed> = session
            .manual
            .iter()
            .map(|address| AnalysisSeed {
                address: *address,
                name: session.names.get(address).cloned(),
                origin: FunctionOrigin::UserDefined,
            })
            .collect();
        let analysis = analyze_binary_with_seeds(&session.binary, &normalized, &seeds, &());
        let report = analysis.report.clone();
        session.analysis = Some(analysis);
        Ok(AnalyzeResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            options: AnalysisOptionsView::from(&normalized),
            report,
        })
    }

    pub fn functions(
        &self,
        handle: &str,
        query: Option<&str>,
        offset: usize,
        limit: usize,
        sort: FunctionSort,
    ) -> ServiceResult<FunctionListResponse> {
        let limit = validate_limit("limit", limit, 1, 1_000)?;
        let session = self.session(handle)?;
        let analysis = require_analysis(session)?;
        let query = query
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());

        let mut functions: Vec<&Function> = analysis
            .functions
            .iter()
            .filter(|function| {
                let Some(query) = query.as_deref() else {
                    return true;
                };
                let name = display_name(session, function).to_ascii_lowercase();
                let address = format_address(function.address).to_ascii_lowercase();
                let symbol = function
                    .symbol
                    .as_deref()
                    .map(|symbol| symbol.to_ascii_lowercase());
                name.contains(query)
                    || address.contains(query)
                    || symbol.is_some_and(|symbol| symbol.contains(query))
            })
            .collect();

        match sort {
            FunctionSort::Address => {}
            FunctionSort::Name => functions.sort_by(|left, right| {
                display_name(session, left)
                    .to_ascii_lowercase()
                    .cmp(&display_name(session, right).to_ascii_lowercase())
                    .then(left.address.cmp(&right.address))
            }),
            FunctionSort::Instructions => functions.sort_by(|left, right| {
                right
                    .instruction_count
                    .cmp(&left.instruction_count)
                    .then(left.address.cmp(&right.address))
            }),
            FunctionSort::References => functions.sort_by(|left, right| {
                right
                    .reference_count
                    .cmp(&left.reference_count)
                    .then(left.address.cmp(&right.address))
            }),
        }

        let total = functions.len();
        let start = offset.min(total);
        let end = start.saturating_add(limit).min(total);
        let rows: Vec<FunctionSummary> = functions[start..end]
            .iter()
            .map(|function| function_summary(session, function))
            .collect();

        Ok(FunctionListResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            query,
            sort: sort.name().to_string(),
            total,
            offset: start,
            limit,
            returned: rows.len(),
            functions: rows,
        })
    }

    pub fn function(&self, handle: &str, address: &str) -> ServiceResult<FunctionDetailResponse> {
        let session = self.session(handle)?;
        let analysis = require_analysis(session)?;
        let address = parse_address(address)?;
        let function = analysis
            .function_containing(address)
            .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?;

        let blocks = function
            .blocks
            .iter()
            .filter_map(|block_address| analysis.blocks.get(block_address))
            .map(|block| BlockSummary {
                address: format_address(block.address),
                end: format_address(block.end),
                instruction_count: block.instructions.len(),
                successors: block
                    .successors
                    .iter()
                    .map(|edge| EdgeView {
                        target: format_address(edge.target),
                        kind: edge.kind.name().to_string(),
                    })
                    .collect(),
            })
            .collect();
        let callers = function
            .callers
            .iter()
            .map(|caller| function_ref(session, *caller))
            .collect();
        let callees = function
            .callees
            .iter()
            .map(|callee| function_ref(session, *callee))
            .collect();

        Ok(FunctionDetailResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            function: function_summary(session, function),
            callers,
            callees,
            blocks,
        })
    }

    pub fn cfg(
        &self,
        handle: &str,
        function: &str,
        max_blocks: usize,
    ) -> ServiceResult<CfgResponse> {
        let max_blocks = validate_limit("maxBlocks", max_blocks, 1, 500)?;
        let session = self.session(handle)?;
        let analysis = require_analysis(session)?;
        let address = parse_address(function)?;
        let selected = analysis
            .function_containing(address)
            .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?;

        let blocks: Vec<CfgBlock> = selected
            .blocks
            .iter()
            .take(max_blocks)
            .filter_map(|block_address| analysis.blocks.get(block_address))
            .map(|block| CfgBlock {
                address: format_address(block.address),
                end: format_address(block.end),
                instructions: block
                    .instructions
                    .iter()
                    .map(|instruction| format_address(*instruction))
                    .collect(),
                successors: block
                    .successors
                    .iter()
                    .map(|edge| EdgeView {
                        target: format_address(edge.target),
                        kind: edge.kind.name().to_string(),
                    })
                    .collect(),
            })
            .collect();

        Ok(CfgResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            function: function_summary(session, selected),
            max_blocks,
            truncated: selected.blocks.len() > max_blocks,
            blocks,
        })
    }

    pub fn xrefs(
        &self,
        handle: &str,
        address: &str,
        direction: XrefDirection,
        kind: Option<&str>,
        limit: usize,
    ) -> ServiceResult<XrefsResponse> {
        let limit = validate_limit("limit", limit, 1, 2_000)?;
        let session = self.session(handle)?;
        let analysis = require_analysis(session)?;
        let address = parse_address(address)?;
        let kind = kind.map(parse_xref_kind).transpose()?;

        let mut xrefs: Vec<&Xref> = match direction {
            XrefDirection::To => analysis.xrefs_to(address).collect(),
            XrefDirection::From => analysis.xrefs_from(address).collect(),
        };
        if let Some(kind) = kind {
            xrefs.retain(|xref| xref.kind == kind);
        }
        let total = xrefs.len();
        let rows: Vec<XrefView> = xrefs
            .into_iter()
            .take(limit)
            .map(|xref| xref_view(session, analysis, xref))
            .collect();

        Ok(XrefsResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            address: format_address(address),
            direction: direction.name().to_string(),
            kind: kind.map(|kind| kind.name().to_string()),
            total,
            returned: rows.len(),
            truncated: total > rows.len(),
            xrefs: rows,
        })
    }

    pub fn disassembly(
        &self,
        handle: &str,
        address: &str,
        count: usize,
    ) -> ServiceResult<DisassemblyResponse> {
        let count = validate_limit("count", count, 1, ura_core::MAX_INSTRUCTIONS)?;
        let session = self.session(handle)?;
        let address = parse_address(address)?;
        let page = session.binary.disassemble(address, count)?;
        Ok(DisassemblyResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            page,
        })
    }

    pub fn strings(
        &self,
        handle: &str,
        options: &StringScanOptions,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<StringsResponse> {
        let limit = validate_limit("limit", limit, 1, 2_000)?;
        if !(2..=512).contains(&options.min_length) {
            return Err(ServiceError::LimitExceeded(
                "minLength must be between 2 and 512".to_string(),
            ));
        }
        if !options.ascii && !options.utf16le {
            return Err(ServiceError::InvalidArgument(
                "at least one of ascii or utf16le must be enabled".to_string(),
            ));
        }
        let session = self.session(handle)?;
        let scan_options = StringScanOptions {
            min_length: options.min_length,
            ascii: options.ascii,
            utf16le: options.utf16le,
            max_results: ura_core::MAX_STRINGS,
        };
        let result = session.binary.extract_strings(&scan_options)?;
        let mut strings = result.strings;
        strings.sort_by_key(|entry| parse_address(&entry.offset).unwrap_or(u64::MAX));
        let total = strings.len();
        let start = offset.min(total);
        let end = start.saturating_add(limit).min(total);
        let rows = strings[start..end].to_vec();

        Ok(StringsResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            min_length: scan_options.min_length,
            ascii: scan_options.ascii,
            utf16le: scan_options.utf16le,
            total,
            offset: start,
            limit,
            returned: rows.len(),
            has_more: end < total,
            scan_truncated: result.truncated,
            ascii_count: result.ascii_count,
            utf16_count: result.utf16_count,
            scanned_bytes: result.scanned_bytes,
            strings: rows,
        })
    }

    pub fn read_bytes(
        &self,
        handle: &str,
        address: Option<&str>,
        offset: Option<&str>,
        length: usize,
    ) -> ServiceResult<BytesResponse> {
        let length = validate_limit("length", length, 1, ura_core::MAX_HEX_READ)?;
        let session = self.session(handle)?;
        let file_offset = match (address, offset) {
            (Some(_), Some(_)) => {
                return Err(ServiceError::InvalidArgument(
                    "provide either address or offset, not both".to_string(),
                ))
            }
            (None, None) => {
                return Err(ServiceError::InvalidArgument(
                    "provide either address or offset".to_string(),
                ))
            }
            (Some(address), None) => {
                let address = parse_address(address)?;
                let section = session
                    .binary
                    .analysis()
                    .section_containing_address(address)
                    .ok_or_else(|| UraError::UnmappedAddress(format_address(address)))?;
                let delta = address - section.address;
                if length as u64 > section.file_size.min(section.size).saturating_sub(delta) {
                    return Err(ServiceError::InvalidArgument(
                        "address-based read crosses a file-backed section boundary; use a file offset for raw reads".into(),
                    ));
                }
                session
                    .binary
                    .analysis()
                    .address_to_file_offset(address)
                    .ok_or_else(|| UraError::UnmappedAddress(format_address(address)))?
            }
            (None, Some(offset)) => parse_address(offset)?,
        };
        let page = session.binary.read_hex(file_offset, length)?;
        let hex = page
            .data
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = page
            .data
            .iter()
            .map(|byte| {
                if (0x20..=0x7e).contains(byte) {
                    *byte as char
                } else {
                    '.'
                }
            })
            .collect();

        Ok(BytesResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            offset: page.offset,
            address: page.address,
            section: page.section,
            requested_length: page.requested_length,
            returned_length: page.data.len(),
            eof: page.eof,
            file_size: page.file_size,
            hex,
            ascii,
        })
    }

    pub fn save_project(
        &mut self,
        handle: &str,
        project_path: &Path,
        name: Option<&str>,
    ) -> ServiceResult<SaveProjectResponse> {
        self.require_writes()?;
        let info = {
            let session = self.session(handle)?;
            session.info.clone()
        };
        let resolved = self.policy.allow_write(project_path)?;
        let (project, names, manual, created) = if resolved.exists() {
            let snapshot = ura_project::read_project(&resolved)?;
            if !snapshot
                .project
                .binary_hash
                .eq_ignore_ascii_case(&info.sha256)
            {
                return Err(ServiceError::ProjectBinaryMismatch);
            }
            let names = names_from_snapshot(&snapshot);
            let manual = manual_from_snapshot(&snapshot);
            (snapshot.project, names, manual, false)
        } else {
            let identity = BinaryIdentity {
                binary_path: info.path.clone(),
                binary_hash: info.sha256.clone(),
                file_size: info.file_size,
                format: info.format.clone(),
                architecture: info.architecture.clone(),
            };
            let project = ura_project::create_project(&resolved, name.unwrap_or(""), &identity)?;
            (project, BTreeMap::new(), Vec::new(), true)
        };

        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        session.project = Some(resolved.clone());
        session.names = names;
        session.manual = manual;

        Ok(SaveProjectResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            created,
            project,
        })
    }

    pub fn rename_function(
        &mut self,
        handle: &str,
        project_path: &Path,
        address: &str,
        name: &str,
    ) -> ServiceResult<RenameFunctionResponse> {
        self.require_writes()?;
        let (function_address, hash) = {
            let session = self.session(handle)?;
            let analysis = require_analysis(session)?;
            let address = parse_address(address)?;
            let function = analysis
                .function_containing(address)
                .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?;
            (function.address, session.info.sha256.clone())
        };
        let resolved = self.policy.allow_write(project_path)?;
        let snapshot = ura_project::read_project(&resolved)?;
        if !snapshot.project.binary_hash.eq_ignore_ascii_case(&hash) {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        let entry =
            ura_project::save_function_name(&resolved, &format_address(function_address), name)?;

        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        session.names.insert(function_address, entry.name);
        session.project = Some(resolved.clone());
        let summary = {
            let analysis = session
                .analysis
                .as_ref()
                .ok_or(ServiceError::AnalysisRequired)?;
            let function = analysis
                .function_by_start(function_address)
                .ok_or_else(|| ServiceError::FunctionNotFound(format_address(function_address)))?;
            function_summary(session, function)
        };

        Ok(RenameFunctionResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            project: display_path(&resolved),
            function: summary,
        })
    }

    pub fn add_comment(
        &self,
        handle: &str,
        project_path: &Path,
        address: &str,
        label: Option<&str>,
        note: &str,
    ) -> ServiceResult<CommentResponse> {
        self.require_writes()?;
        let hash = self.session(handle)?.info.sha256.clone();
        let address = parse_address(address)?;
        let resolved = self.policy.allow_write(project_path)?;
        let snapshot = ura_project::read_project(&resolved)?;
        if !snapshot.project.binary_hash.eq_ignore_ascii_case(&hash) {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        let annotation =
            ura_project::save_annotation(&resolved, &format_address(address), label, note)?;
        Ok(CommentResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.to_string(),
            project: display_path(&resolved),
            annotation,
        })
    }

    pub fn export_analysis(
        &self,
        project_path: &Path,
        destination: &Path,
    ) -> ServiceResult<ExportResponse> {
        self.require_writes()?;
        let project = self.policy.allow_write(project_path)?;
        let destination = self.policy.allow_write(destination)?;
        let export = ura_project::export_annotations(&project, &destination)?;
        Ok(ExportResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            project: display_path(&project),
            export,
        })
    }

    fn session(&self, handle: &str) -> ServiceResult<&Session> {
        self.sessions
            .get(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))
    }

    fn require_writes(&self) -> ServiceResult<()> {
        if self.writes_enabled {
            Ok(())
        } else {
            Err(ServiceError::WriteDisabled)
        }
    }
}

fn require_analysis(session: &Session) -> ServiceResult<&ProgramAnalysis> {
    session
        .analysis
        .as_ref()
        .ok_or(ServiceError::AnalysisRequired)
}

fn display_name(session: &Session, function: &Function) -> String {
    session
        .names
        .get(&function.address)
        .cloned()
        .or_else(|| function.symbol.clone())
        .unwrap_or_else(|| function.fallback_name())
}

fn function_summary(session: &Session, function: &Function) -> FunctionSummary {
    FunctionSummary {
        address: format_address(function.address),
        end: format_address(function.end),
        name: display_name(session, function),
        symbol: function.symbol.clone(),
        origin: function.origin.name().to_string(),
        verified: function.verified(),
        size: function.size(),
        instruction_count: function.instruction_count,
        block_count: function.blocks.len(),
        reference_count: function.reference_count,
        caller_count: function.callers.len(),
        callee_count: function.callees.len(),
    }
}

fn function_ref(session: &Session, address: u64) -> FunctionRef {
    let name = session
        .analysis
        .as_ref()
        .and_then(|analysis| analysis.function_by_start(address))
        .map(|function| display_name(session, function))
        .unwrap_or_else(|| format!("sub_{}", format_address(address).trim_start_matches("0x")));
    FunctionRef {
        address: format_address(address),
        name,
    }
}

fn xref_view(session: &Session, analysis: &ProgramAnalysis, xref: &Xref) -> XrefView {
    let (from_function, from_name) = endpoint(session, analysis, xref.from);
    let (to_function, to_name) = endpoint(session, analysis, xref.to);
    XrefView {
        from: format_address(xref.from),
        to: format_address(xref.to),
        kind: xref.kind.name().to_string(),
        data_kind: xref.data_kind.map(|kind| kind.name().to_string()),
        from_function,
        from_name,
        to_function,
        to_name,
    }
}

fn endpoint(
    session: &Session,
    analysis: &ProgramAnalysis,
    address: u64,
) -> (Option<String>, Option<String>) {
    match analysis.function_containing(address) {
        Some(function) => (
            Some(format_address(function.address)),
            Some(display_name(session, function)),
        ),
        None => (None, None),
    }
}

fn parse_xref_kind(value: &str) -> ServiceResult<XrefKind> {
    match value.trim() {
        "call" => Ok(XrefKind::Call),
        "jump" => Ok(XrefKind::Jump),
        "conditionalJump" | "conditional-jump" | "conditional_jump" => {
            Ok(XrefKind::ConditionalJump)
        }
        "data" => Ok(XrefKind::Data),
        other => Err(ServiceError::InvalidArgument(format!(
            "unknown xref kind '{other}'; expected call, jump, conditionalJump or data"
        ))),
    }
}

fn validate_limit(
    name: &str,
    value: usize,
    minimum: usize,
    maximum: usize,
) -> ServiceResult<usize> {
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(ServiceError::LimitExceeded(format!(
            "{name} must be between {minimum} and {maximum}"
        )))
    }
}

fn names_from_snapshot(snapshot: &ProjectSnapshot) -> BTreeMap<u64, String> {
    snapshot
        .function_names
        .iter()
        .filter_map(|entry| {
            parse_address(&entry.address)
                .ok()
                .map(|address| (address, entry.name.clone()))
        })
        .collect()
}

fn manual_from_snapshot(snapshot: &ProjectSnapshot) -> Vec<u64> {
    snapshot
        .manual_functions
        .iter()
        .filter_map(|entry| parse_address(&entry.address).ok())
        .collect()
}
