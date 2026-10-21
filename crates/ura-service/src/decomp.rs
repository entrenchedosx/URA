use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use ura_core::decomp::signature::{self, SignatureOverride};
use ura_core::decomp::types::{TypeDatabase, TypeRef};
use ura_core::decomp::{self, abi::SignatureHints, FunctionDecompilation, HighLevelLine};
use ura_core::{format_address, parse_address, ProgramAnalysis};

use crate::dto::{
    CallGraphEdgeView, CallGraphNodeView, CallGraphResponse, HighLevelResponse, SignatureResponse,
    StackFrameResponse, StackVariableResponse, TypesResponse,
};
use crate::error::{ServiceError, ServiceResult};
use crate::service::Session;
use crate::{Service, RESPONSE_SCHEMA_VERSION};

const MAX_CACHED_DECOMPILATIONS: usize = 4;
const MAX_CALL_GRAPH_EDGES: usize = 20_000;
const MAX_STACK_OFFSET: i64 = 1 << 30;

/// The typed AST retains the core's legacy u64 addresses in memory. Project
/// its address fields to hex strings at the protocol boundary, including
/// nested statements, signatures and evidence, before a JS client sees them.
fn lossless_hir_addresses(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "function" | "address" | "predecessor" | "target" | "taken" | "fall" | "header"
                ) {
                    if let Some(address) = value.as_u64() {
                        *value = serde_json::Value::String(format_address(address));
                        continue;
                    }
                }
                lossless_hir_addresses(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                lossless_hir_addresses(value);
            }
        }
        _ => {}
    }
}

impl Service {
    fn require_override_project(&self, handle: &str, resolved: &Path) -> ServiceResult<()> {
        let attached = self.session(handle)?.project.as_deref().ok_or_else(|| {
            ServiceError::InvalidArgument(
                "Attach the project to this binary before editing overrides".into(),
            )
        })?;
        if self.policy.allow_write(attached)? != resolved {
            return Err(ServiceError::InvalidArgument(
                "Attach the target project to this binary before editing its overrides".into(),
            ));
        }
        Ok(())
    }

    pub fn type_library(&self, handle: &str) -> ServiceResult<crate::dto::TypeLibraryResponse> {
        let session = self.session(handle)?;
        Ok(crate::dto::TypeLibraryResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            database: session.type_library.clone(),
        })
    }

    pub fn structure_definition(
        &self,
        handle: &str,
        name: &str,
    ) -> ServiceResult<crate::dto::StructureResponse> {
        let session = self.session(handle)?;
        let structure = session
            .type_library
            .structures
            .get(name)
            .cloned()
            .ok_or_else(|| {
                ServiceError::InvalidArgument(format!(
                    "structure '{name}' is not defined in the project type library"
                ))
            })?;
        Ok(crate::dto::StructureResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            structure,
        })
    }

    pub fn set_type_library(
        &mut self,
        handle: &str,
        project: &Path,
        library: &TypeDatabase,
    ) -> ServiceResult<crate::dto::TypeLibraryResponse> {
        self.require_writes()?;
        let session = self.session(handle)?;
        if library.address_bits != session.binary.analysis().bitness as u16 {
            return Err(ServiceError::InvalidArgument(
                "type library target width differs from the binary".into(),
            ));
        }
        let errors = library.validation_errors();
        if !errors.is_empty() {
            return Err(ServiceError::InvalidArgument(errors.join("; ")));
        }
        let resolved = self.policy.allow_write(project)?;
        let snapshot = ura_project::read_project(&resolved)?;
        if !snapshot
            .project
            .binary_hash
            .eq_ignore_ascii_case(&session.info.sha256)
        {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        self.require_override_project(handle, &resolved)?;
        ura_project::save_type_library(&resolved, library)?;
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.into()))?;
        session.type_library = library.clone();
        session.project = Some(resolved);
        session.decomp_cache.clear();
        session.decomp_cache_order.clear();
        self.type_library(handle)
    }

    pub(crate) fn decompiled(
        &mut self,
        handle: &str,
        address: &str,
    ) -> ServiceResult<Arc<FunctionDecompilation>> {
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        let analysis = session
            .analysis
            .as_ref()
            .ok_or(ServiceError::AnalysisRequired)?;
        let address = parse_address(address)?;
        let function = analysis
            .function_containing(address)
            .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?
            .address;
        if let Some(cached) = session.decomp_cache.get(&function).cloned() {
            session.decomp_cache_order.retain(|key| *key != function);
            session.decomp_cache_order.push_back(function);
            return Ok(cached);
        }
        let context = decomp_context(session, analysis, function);
        let result = decomp::analyze_function(&session.binary, analysis, function, &context, &())
            .map_err(ServiceError::InvalidArgument)?;
        let result = Arc::new(result);
        while session.decomp_cache.len() >= MAX_CACHED_DECOMPILATIONS {
            let Some(oldest) = session.decomp_cache_order.pop_front() else {
                session.decomp_cache.clear();
                break;
            };
            session.decomp_cache.remove(&oldest);
        }
        session.decomp_cache.insert(function, result.clone());
        session.decomp_cache_order.push_back(function);
        Ok(result)
    }

    pub fn function_signature(
        &mut self,
        handle: &str,
        address: &str,
    ) -> ServiceResult<SignatureResponse> {
        let decompilation = self.decompiled(handle, address)?;
        let session = self.session(handle)?;
        Ok(SignatureResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            function: format_address(decompilation.function),
            name: decompilation.name.clone(),
            analysis_partial: analysis_partial(session),
            signature: decompilation.signature.clone(),
            diagnostics: decompilation.diagnostics.clone(),
        })
    }

    pub fn stack_frame(
        &mut self,
        handle: &str,
        address: &str,
    ) -> ServiceResult<StackFrameResponse> {
        let decompilation = self.decompiled(handle, address)?;
        let session = self.session(handle)?;
        Ok(StackFrameResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            function: format_address(decompilation.function),
            name: decompilation.name.clone(),
            analysis_partial: analysis_partial(session),
            frame: decompilation.frame.clone(),
            diagnostics: decompilation.diagnostics.clone(),
        })
    }

    pub fn inferred_types(&mut self, handle: &str, address: &str) -> ServiceResult<TypesResponse> {
        let decompilation = self.decompiled(handle, address)?;
        let session = self.session(handle)?;
        let database = session.type_library.clone();
        Ok(TypesResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            function: format_address(decompilation.function),
            name: decompilation.name.clone(),
            analysis_partial: analysis_partial(session),
            database_errors: database.validation_errors(),
            types: decompilation.types.clone(),
            database,
        })
    }

    pub fn high_level(
        &mut self,
        handle: &str,
        address: &str,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<HighLevelResponse> {
        self.high_level_with_ast(handle, address, offset, limit, false)
    }

    pub fn high_level_with_ast(
        &mut self,
        handle: &str,
        address: &str,
        offset: usize,
        limit: usize,
        include_ast: bool,
    ) -> ServiceResult<HighLevelResponse> {
        if !(1..=2_000).contains(&limit) {
            return Err(ServiceError::LimitExceeded(
                "high-level line limit must be 1..2000".into(),
            ));
        }
        let decompilation = self.decompiled(handle, address)?;
        let ast = if include_ast {
            let mut value = serde_json::to_value(&decompilation.ast)
                .map_err(|error| ServiceError::InvalidArgument(error.to_string()))?;
            lossless_hir_addresses(&mut value);
            let bytes = serde_json::to_vec(&value)
                .map_err(|error| ServiceError::InvalidArgument(error.to_string()))?;
            if bytes.len() > 2 * 1024 * 1024 {
                return Err(ServiceError::LimitExceeded(
                    "typed HIR exceeds the 2 MiB response limit; use paged lines or IR".into(),
                ));
            }
            Some(value)
        } else {
            None
        };
        let session = self.session(handle)?;
        let total = decompilation.high_level.lines.len();
        let offset = offset.min(total);
        let lines = decompilation
            .high_level
            .lines
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<HighLevelLine>>();
        Ok(HighLevelResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            function: format_address(decompilation.function),
            name: decompilation.name.clone(),
            analysis_partial: analysis_partial(session),
            syntax: decompilation.high_level.syntax.clone(),
            status: decompilation.high_level.status.clone(),
            total,
            offset,
            limit,
            returned: lines.len(),
            lines,
            unresolved: decompilation.high_level.unresolved,
            truncated: decompilation.high_level.truncated,
            notes: decompilation.high_level.notes.clone(),
            diagnostics: decompilation.diagnostics.clone(),
            program: decompilation.program.clone(),
            ast,
        })
    }

    pub fn call_graph(
        &mut self,
        handle: &str,
        focus: Option<&str>,
        depth: usize,
        max_nodes: usize,
    ) -> ServiceResult<CallGraphResponse> {
        if !(1..=16).contains(&depth) {
            return Err(ServiceError::LimitExceeded(
                "call-graph depth must be 1..16".into(),
            ));
        }
        if !(1..=2_000).contains(&max_nodes) {
            return Err(ServiceError::LimitExceeded(
                "call-graph node limit must be 1..2000".into(),
            ));
        }
        let session = self.session(handle)?;
        let analysis = session
            .analysis
            .as_ref()
            .ok_or(ServiceError::AnalysisRequired)?;
        let focus = focus
            .map(parse_address)
            .transpose()?
            .map(|address| {
                analysis
                    .function_containing(address)
                    .map(|function| function.address)
                    .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))
            })
            .transpose()?;
        let graph = decomp::build_call_graph(analysis);
        let mut selected = BTreeSet::new();
        let mut distances: BTreeMap<u64, usize> = BTreeMap::new();
        if let Some(focus) = focus {
            let mut queue = VecDeque::from([(focus, 0usize)]);
            while let Some((current, distance)) = queue.pop_front() {
                if selected.len() >= max_nodes || !selected.insert(current) {
                    continue;
                }
                distances.insert(current, distance);
                if distance >= depth {
                    continue;
                }
                for edge in graph.callees(current) {
                    if !selected.contains(&edge.to) {
                        queue.push_back((edge.to, distance + 1));
                    }
                }
            }
        } else {
            for node in &graph.nodes {
                if selected.len() >= max_nodes {
                    break;
                }
                selected.insert(node.address);
                distances.insert(node.address, 0);
            }
        }

        let mut returned_edges = Vec::new();
        let mut edges_truncated = false;
        for edge in &graph.edges {
            if !selected.contains(&edge.from) || !selected.contains(&edge.to) {
                continue;
            }
            if returned_edges.len() >= MAX_CALL_GRAPH_EDGES {
                edges_truncated = true;
                break;
            }
            returned_edges.push(CallGraphEdgeView {
                from: format_address(edge.from),
                to: format_address(edge.to),
                kind: edge.kind.clone(),
                instruction: edge.instruction.map(format_address),
            });
        }
        let mut nodes = Vec::new();
        for node in &graph.nodes {
            if !selected.contains(&node.address) {
                continue;
            }
            let name = analysis
                .function_by_start(node.address)
                .map(|function| display_name(session, function))
                .unwrap_or_else(|| node.name.clone());
            nodes.push(CallGraphNodeView {
                address: format_address(node.address),
                name,
                origin: node.origin.clone(),
                external: node.external,
                callers: node.callers,
                callees: node.callees,
                recursive: node.recursive,
                component: node.component,
                depth: distances.get(&node.address).copied().unwrap_or(0),
            });
        }
        let cycles = graph
            .cycles
            .iter()
            .filter(|cycle| cycle.iter().all(|address| selected.contains(address)))
            .map(|cycle| {
                cycle
                    .iter()
                    .map(|address| format_address(*address))
                    .collect()
            })
            .collect::<Vec<Vec<String>>>();
        let roots = graph
            .roots
            .iter()
            .filter(|address| selected.contains(address))
            .map(|address| format_address(*address))
            .collect();
        let leaves = graph
            .leaves
            .iter()
            .filter(|address| selected.contains(address))
            .map(|address| format_address(*address))
            .collect();
        let truncated = graph.truncated
            || edges_truncated
            || selected.len() < graph.nodes.len()
            || returned_edges.len() < graph.edges.len();
        let mut notes = graph.notes.clone();
        if selected.len() < graph.nodes.len() {
            notes.push(format!(
                "the view is limited to {max_nodes} node(s); the full graph has {}",
                graph.nodes.len()
            ));
        }
        if edges_truncated {
            notes.push(format!(
                "the edge view is limited to {MAX_CALL_GRAPH_EDGES} edge(s)"
            ));
        }
        Ok(CallGraphResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            binary_hash: session.info.sha256.clone(),
            analysis_partial: analysis_partial(session),
            focus: focus.map(format_address),
            depth,
            total_nodes: graph.nodes.len(),
            total_edges: graph.edges.len(),
            returned_nodes: nodes.len(),
            returned_edges: returned_edges.len(),
            truncated,
            unresolved_indirect: graph.unresolved_indirect,
            roots,
            leaves,
            cycles,
            notes,
            nodes,
            edges: returned_edges,
        })
    }

    pub fn set_function_signature(
        &mut self,
        handle: &str,
        project_path: &Path,
        address: &str,
        signature_override: &SignatureOverride,
    ) -> ServiceResult<SignatureResponse> {
        self.require_writes()?;
        let errors = signature_override
            .validate_for_width(self.session(handle)?.binary.analysis().bitness as u16);
        if !errors.is_empty() {
            return Err(ServiceError::InvalidArgument(format!(
                "signature override rejected: {}",
                errors.join("; ")
            )));
        }
        let (function, hash) = {
            let session = self.session(handle)?;
            let analysis = session
                .analysis
                .as_ref()
                .ok_or(ServiceError::AnalysisRequired)?;
            let address = parse_address(address)?;
            let function = analysis
                .function_containing(address)
                .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?
                .address;
            (function, session.info.sha256.clone())
        };
        let resolved = self.policy.allow_write(project_path)?;
        let snapshot = ura_project::read_project(&resolved)?;
        if !snapshot.project.binary_hash.eq_ignore_ascii_case(&hash) {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        self.require_override_project(handle, &resolved)?;
        ura_project::save_function_signature(
            &resolved,
            &format_address(function),
            signature_override,
        )?;
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        session
            .signature_overrides
            .insert(function, signature_override.clone());
        session.project = Some(resolved);
        session.decomp_cache.clear();
        session.decomp_cache_order.clear();
        self.function_signature(handle, &format_address(function))
    }

    pub fn set_stack_variable(
        &mut self,
        handle: &str,
        project_path: &Path,
        function: &str,
        offset: i64,
        name: Option<&str>,
        ty: Option<&TypeRef>,
    ) -> ServiceResult<StackVariableResponse> {
        self.require_writes()?;
        if offset.unsigned_abs() > MAX_STACK_OFFSET as u64 {
            return Err(ServiceError::InvalidArgument(format!(
                "stack offset {offset} is outside the supported range"
            )));
        }
        let function_address = {
            let session = self.session(handle)?;
            let analysis = session
                .analysis
                .as_ref()
                .ok_or(ServiceError::AnalysisRequired)?;
            let address = parse_address(function)?;
            analysis
                .function_containing(address)
                .ok_or_else(|| ServiceError::FunctionNotFound(format_address(address)))?
                .address
        };
        let frame = self
            .decompiled(handle, &format_address(function_address))?
            .frame
            .clone();
        if !frame.slots.iter().any(|slot| slot.offset == offset) {
            return Err(ServiceError::InvalidArgument(format!(
                "no stack slot at offset {offset} was recovered for {}",
                format_address(function_address)
            )));
        }
        let hash = self.session(handle)?.info.sha256.clone();
        let resolved = self.policy.allow_write(project_path)?;
        let snapshot = ura_project::read_project(&resolved)?;
        if !snapshot.project.binary_hash.eq_ignore_ascii_case(&hash) {
            return Err(ServiceError::ProjectBinaryMismatch);
        }
        self.require_override_project(handle, &resolved)?;
        let removed = name.is_none() && ty.is_none();
        let entry = if removed {
            ura_project::delete_stack_variable(
                &resolved,
                &format_address(function_address),
                offset,
            )?;
            None
        } else {
            Some(ura_project::save_stack_variable(
                &resolved,
                &format_address(function_address),
                offset,
                name,
                ty,
            )?)
        };
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.to_string()))?;
        let key = offset.to_string();
        if removed {
            if let Some(overrides) = session.stack_overrides.get_mut(&function_address) {
                overrides.remove(&key);
                if overrides.is_empty() {
                    session.stack_overrides.remove(&function_address);
                }
            }
        } else {
            session
                .stack_overrides
                .entry(function_address)
                .or_default()
                .insert(key, (name.map(str::to_string), ty.cloned()));
        }
        session.project = Some(resolved.clone());
        session.decomp_cache.clear();
        session.decomp_cache_order.clear();
        let frame = self
            .decompiled(handle, &format_address(function_address))?
            .frame
            .clone();
        Ok(StackVariableResponse {
            schema_version: RESPONSE_SCHEMA_VERSION,
            handle: handle.into(),
            project: crate::paths::display_path(&resolved),
            function: format_address(function_address),
            removed,
            variable: entry,
            frame,
        })
    }
}

fn decomp_context(
    session: &Session,
    analysis: &ProgramAnalysis,
    function: u64,
) -> decomp::DecompContext {
    let address_bits = session.binary.analysis().bitness as u16;
    let mut context = decomp::DecompContext::new(address_bits);
    context.type_database = session.type_library.clone();
    let mut hints = SignatureHints::default();
    for (address, signature_override) in &session.signature_overrides {
        let hint_name = analysis
            .function_by_start(*address)
            .map(|function| display_name(session, function))
            .unwrap_or_else(|| format!("sub_{address:x}"));
        hints.insert(signature::describe_override(
            *address,
            &hint_name,
            signature_override,
        ));
    }
    context.hints = hints;
    context.override_signature = session.signature_overrides.get(&function).cloned();
    context.stack_overrides = session
        .stack_overrides
        .get(&function)
        .cloned()
        .unwrap_or_default();
    context
}

fn analysis_partial(session: &Session) -> bool {
    session
        .analysis
        .as_ref()
        .is_some_and(|analysis| analysis.report.cancelled || analysis.report.truncated)
}

fn display_name(session: &Session, function: &ura_core::Function) -> String {
    session
        .names
        .get(&function.address)
        .cloned()
        .or_else(|| function.symbol.clone())
        .unwrap_or_else(|| function.fallback_name())
}

#[cfg(test)]
mod hir_address_tests {
    #[test]
    fn addresses_above_javascript_integer_precision_keep_every_bit() {
        let address = 0xffff_ffff_ffff_fffeu64;
        let mut value = serde_json::json!({"function":address,"source":{"signature":{"function":address,"parameters":[{"width":64,"evidence":[{"address":address}]}]}},"statements":[{"type":"ifExit","target":{"type":"goto","target":address}},{"predecessor":address,"header":address,"taken":address,"fall":address}]});
        super::lossless_hir_addresses(&mut value);
        let expected = ura_core::format_address(address);
        assert_eq!(value["function"], expected);
        assert_eq!(
            value["source"]["signature"]["parameters"][0]["evidence"][0]["address"],
            expected
        );
        assert_eq!(value["statements"][0]["target"]["target"], expected);
        assert_eq!(value["source"]["signature"]["parameters"][0]["width"], 64);
        for key in ["predecessor", "header", "taken", "fall"] {
            assert_eq!(value["statements"][1][key], expected);
        }
    }
}
