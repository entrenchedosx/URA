use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use serde::Serialize;
use serde_json::Value;
use ura_core::decomp::signature::{
    CallingConvention, Location, SignatureOverride, SignatureParameterInput,
};
use ura_core::decomp::types::TypeRef;
use ura_core::{AnalysisOptions, StringScanOptions, MAX_STRINGS};
use ura_service::{ErrorView, FunctionSort, Service, ServiceError, XrefDirection};

use crate::params::{
    AddCommentParams, AnalyzeParams, BinaryHandleParams, CallGraphParams, CfgParams,
    DecompFunctionParams, DisassemblyParams, ExportAnalysisParams, FunctionParams,
    GetFunctionsParams, OpenBinaryParams, ReadBytesParams, RenameFunctionParams, SaveProjectParams,
    SearchStringsParams, SetFunctionSignatureParams, SetTypeLibraryParams, SetVariableTypeParams,
    StructureParams, TypesParams, XrefsParams,
};

const INSTRUCTIONS: &str = "URA performs local static analysis of PE, ELF and Mach-O binaries. \
Samples are parsed and analysed, never executed. Call ura_open_binary first, keep the returned \
handle, run ura_analyze, then query functions, disassembly, CFGs, cross-references, strings and raw \
bytes. Every response carries schemaVersion 1. Failures are returned as tool errors whose \
structured content is {\"schemaVersion\":1,\"error\":{\"code\":\"...\",\"message\":\"...\"}}. \
Paths must resolve inside the roots passed with --allow. Project writes are disabled unless the \
server was started with --enable-writes.";

#[derive(Clone)]
pub struct UraServer {
    service: Arc<Mutex<Service>>,
    tool_router: ToolRouter<Self>,
}

impl UraServer {
    pub fn new(service: Service) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            tool_router: Self::tool_router(),
        }
    }

    fn service(&self) -> MutexGuard<'_, Service> {
        self.service
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[tool_router]
impl UraServer {
    #[tool(
        name = "ura_get_ir",
        annotations(title = "Get raw IR", read_only_hint = true),
        description = "Get a bounded page of verified raw bit-vector IR, with typed operations and source instruction addresses. Requires ura_analyze. Unsupported semantics are explicit barriers."
    )]
    fn ura_get_ir(
        &self,
        Parameters(p): Parameters<crate::params::IrParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().ir(
            &p.handle,
            &p.function,
            false,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(100),
        ))
    }
    #[tool(
        name = "ura_get_ssa",
        annotations(title = "Get SSA IR", read_only_hint = true),
        description = "Get a bounded page of scalar SSA IR and predecessor-indexed phi nodes. Uses the same cached lifter as raw IR; memory remains an opaque conservative token."
    )]
    fn ura_get_ssa(
        &self,
        Parameters(p): Parameters<crate::params::IrParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().ir(
            &p.handle,
            &p.function,
            true,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(100),
        ))
    }
    #[tool(
        name = "ura_get_dominators",
        annotations(title = "Get dominators", read_only_hint = true),
        description = "Get immediate dominators, dominator tree children and dominance frontiers for a function. Entry-reachable CFG only; unreachable blocks are listed explicitly."
    )]
    fn ura_get_dominators(
        &self,
        Parameters(p): Parameters<crate::params::IrParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().dominators(
            &p.handle,
            &p.function,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(100),
        ))
    }
    #[tool(
        name = "ura_get_analysis_diagnostics",
        annotations(title = "Get analysis diagnostics", read_only_hint = true),
        description = "Get paginated unsupported-semantic diagnostics and conservative constant/dead-definition summaries for a function. No instructions or branches are rewritten."
    )]
    fn ura_get_analysis_diagnostics(
        &self,
        Parameters(p): Parameters<crate::params::IrParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().analysis_diagnostics(
            &p.handle,
            &p.function,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(100),
        ))
    }
    #[tool(
        name = "ura_get_function_signature",
        annotations(title = "Get function signature", read_only_hint = true),
        description = "Recover the effective signature of a function from verified lifted IR: calling convention, parameter locations, types, return value, confidence and evidence. Requires ura_analyze."
    )]
    fn ura_get_function_signature(
        &self,
        Parameters(p): Parameters<DecompFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().function_signature(&p.handle, &p.function))
    }
    #[tool(
        name = "ura_get_calling_convention",
        annotations(title = "Get calling convention", read_only_hint = true),
        description = "Return the recovered calling convention together with its evidence and any conflicts. This is an evidence-based estimate, not a proof of the original source ABI."
    )]
    fn ura_get_calling_convention(
        &self,
        Parameters(p): Parameters<DecompFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().function_signature(&p.handle, &p.function))
    }
    #[tool(
        name = "ura_get_stack_variables",
        annotations(title = "Get stack variables", read_only_hint = true),
        description = "Recover physical stack slots, incoming argument and local offsets, access widths and per-instruction evidence. User overrides are included when the project is attached."
    )]
    fn ura_get_stack_variables(
        &self,
        Parameters(p): Parameters<DecompFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().stack_frame(&p.handle, &p.function))
    }
    #[tool(
        name = "ura_get_types",
        annotations(title = "Get inferred types", read_only_hint = true),
        description = "Return conservative type constraints and inferred variable widths from verified IR. Signedness, pointee types and floating-point use are never guessed."
    )]
    fn ura_get_types(
        &self,
        Parameters(p): Parameters<TypesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match p.function {
            Some(function) => respond(self.service().inferred_types(&p.handle, &function)),
            None => respond(self.service().type_library(&p.handle)),
        }
    }
    #[tool(
        name = "ura_get_structure",
        annotations(title = "Get structure definition", read_only_hint = true),
        description = "Return an actual named structure or union definition from the project type library, with field offsets, types, size and alignment. An undefined name returns an error. Use ura_get_high_level_ir for control flow."
    )]
    fn ura_get_structure(
        &self,
        Parameters(p): Parameters<StructureParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().structure_definition(&p.handle, &p.name))
    }
    #[tool(
        name = "ura_set_type_library",
        annotations(title = "Save project type library", read_only_hint = false),
        description = "Validate and atomically replace the user-authored structure/union and type-alias library in an existing matching project. Requires --enable-writes. Read the library with ura_get_types first; definitions are limited to 256 structures, 256 aliases, 512 fields per structure and 1 MiB serialized."
    )]
    fn ura_set_type_library(
        &self,
        Parameters(p): Parameters<SetTypeLibraryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let library = serde_json::from_value::<ura_core::decomp::TypeDatabase>(p.database)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()));
        respond(library.and_then(|library| {
            self.service()
                .set_type_library(&p.handle, Path::new(&p.project), &library)
        }))
    }
    #[tool(
        name = "ura_get_call_graph",
        annotations(title = "Get call graph", read_only_hint = true),
        description = "Return a bounded graph of internal calls/tail calls and verified PE IAT or ELF GOT/PLT memory transfers. External nodes carry exact import identity, optional curated signature and uncertainty; edges preserve instruction sites. Unproved indirect transfers stay unresolved."
    )]
    fn ura_get_call_graph(
        &self,
        Parameters(p): Parameters<CallGraphParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().call_graph(
            &p.handle,
            p.function.as_deref(),
            p.depth.unwrap_or(1),
            p.max_nodes.unwrap_or(200),
        ))
    }
    #[tool(
        name = "ura_get_type_constraints",
        annotations(title = "Get type constraints", read_only_hint = true),
        description = "Return per-variable type constraints, conflicts and confidence derived from loads, stores, calls and comparisons. Constraints are evidence, not proof."
    )]
    fn ura_get_type_constraints(
        &self,
        Parameters(p): Parameters<DecompFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().inferred_types(&p.handle, &p.function))
    }
    #[tool(
        name = "ura_get_high_level_ir",
        annotations(title = "Get high-level IR", read_only_hint = true),
        description = "Return paged diagnostic C-like lines plus bounded argument/return type constraints. Set semantic=true for executable semantic HIR, or semanticBlock to select one block with global IDs and explicit external definitions. ast=true retains the legacy presentation tree. Each optional HIR payload has a 2 MiB limit; addresses are hex strings."
    )]
    fn ura_get_high_level_ir(
        &self,
        Parameters(p): Parameters<DecompFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let response = self.service().high_level_with_ast(
            &p.handle,
            &p.function,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(200),
            p.ast.unwrap_or(false),
        );
        let response = response.and_then(|mut response| {
            if p.semantic.unwrap_or(false) || p.semantic_block.is_some() {
                response.semantic = Some(self.service().semantic_hir(
                    &p.handle,
                    &p.function,
                    p.semantic_block.as_deref(),
                )?);
            }
            Ok(response)
        });
        respond(response)
    }
    #[tool(
        name = "ura_set_function_signature",
        annotations(title = "Set function signature", read_only_hint = false),
        description = "Persist a user-authored signature override in an existing .ura project. The inferred evidence is retained and the effective signature is reported. Requires --enable-writes."
    )]
    fn ura_set_function_signature(
        &self,
        Parameters(p): Parameters<SetFunctionSignatureParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = signature_override(&p).and_then(|signature| {
            self.service().set_function_signature(
                &p.handle,
                Path::new(&p.project),
                &p.address,
                &signature,
            )
        });
        respond(result)
    }
    #[tool(
        name = "ura_set_variable_type",
        annotations(title = "Set stack variable name or type", read_only_hint = false),
        description = "Persist a display name and/or C-like type for one recovered stack slot. Omit both to clear the override. Requires --enable-writes."
    )]
    fn ura_set_variable_type(
        &self,
        Parameters(p): Parameters<SetVariableTypeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = (|| {
            let ty =
                p.ty.as_deref()
                    .map(|text| TypeRef::parse(text, 64).map_err(ServiceError::InvalidArgument))
                    .transpose()?;
            self.service().set_stack_variable(
                &p.handle,
                Path::new(&p.project),
                &p.function,
                p.offset,
                p.name.as_deref(),
                ty.as_ref(),
            )
        })();
        respond(result)
    }
    #[tool(
        name = "ura_open_binary",
        annotations(title = "Open binary", read_only_hint = true),
        description = "Open a PE, ELF or Mach-O file for inspection. Returns a handle, binary metadata, sections, imports and exports. Optionally attaches an existing .ura project and applies its function names and manual function seeds."
    )]
    fn ura_open_binary(
        &self,
        Parameters(params): Parameters<OpenBinaryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().open_binary(
            Path::new(&params.binary),
            params.project.as_deref().map(Path::new),
        ))
    }

    #[tool(
        name = "ura_analyze",
        annotations(title = "Analyze binary", read_only_hint = true),
        description = "Discover functions, basic blocks and cross-references for an opened binary. Analysis results are cached on the handle for subsequent queries."
    )]
    fn ura_analyze(
        &self,
        Parameters(params): Parameters<AnalyzeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let defaults = AnalysisOptions::default();
        let options = AnalysisOptions {
            max_instructions: params.max_instructions.unwrap_or(defaults.max_instructions),
            max_functions: params.max_functions.unwrap_or(defaults.max_functions),
            max_blocks: params.max_blocks.unwrap_or(defaults.max_blocks),
            follow_calls: params.follow_calls.unwrap_or(defaults.follow_calls),
            seed_symbols: params.seed_symbols.unwrap_or(defaults.seed_symbols),
        };
        respond(self.service().analyze(&params.handle, &options))
    }

    #[tool(
        name = "ura_get_binary_info",
        annotations(title = "Get binary info", read_only_hint = true),
        description = "Return metadata for an opened binary: format, architecture, hashes, entry point, section counts and warnings."
    )]
    fn ura_get_binary_info(
        &self,
        Parameters(params): Parameters<BinaryHandleParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().info(&params.handle))
    }

    #[tool(
        name = "ura_get_functions",
        annotations(title = "List functions", read_only_hint = true),
        description = "List discovered functions with pagination, optional substring query and sorting by address, name, instruction count or reference count. Requires ura_analyze."
    )]
    fn ura_get_functions(
        &self,
        Parameters(params): Parameters<GetFunctionsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = (|| {
            let sort = match params.sort.as_deref() {
                Some(value) => FunctionSort::from_str(value)?,
                None => FunctionSort::Address,
            };
            self.service().functions(
                &params.handle,
                params.query.as_deref(),
                params.offset.unwrap_or(0),
                params.limit.unwrap_or(100),
                sort,
            )
        })();
        respond(result)
    }

    #[tool(
        name = "ura_get_function",
        annotations(title = "Get function detail", read_only_hint = true),
        description = "Return one function's summary plus a bounded page of its basic blocks and its callers/callees. The address may point anywhere inside the function. Requires ura_analyze."
    )]
    fn ura_get_function(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().function(
            &params.handle,
            &params.address,
            params.max_blocks.unwrap_or(200),
        ))
    }

    #[tool(
        name = "ura_get_disassembly",
        annotations(title = "Get disassembly", read_only_hint = true),
        description = "Decode up to 2000 instructions starting at a virtual address. Returns instruction addresses, bytes, mnemonic text and the containing section. Does not require analysis."
    )]
    fn ura_get_disassembly(
        &self,
        Parameters(params): Parameters<DisassemblyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().disassembly(
            &params.handle,
            &params.address,
            params.count.unwrap_or(50),
        ))
    }

    #[tool(
        name = "ura_get_cfg",
        annotations(title = "Get CFG", read_only_hint = true),
        description = "Return the control-flow graph of a function: basic blocks, instruction addresses and successor edges. Requires ura_analyze."
    )]
    fn ura_get_cfg(
        &self,
        Parameters(params): Parameters<CfgParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().cfg(
            &params.handle,
            &params.function,
            params.max_blocks.unwrap_or(200),
        ))
    }

    #[tool(
        name = "ura_get_xrefs",
        annotations(title = "Get cross-references", read_only_hint = true),
        description = "List cross-references to or from an address, optionally filtered by kind (call, jump, conditionalJump, data). Requires ura_analyze."
    )]
    fn ura_get_xrefs(
        &self,
        Parameters(params): Parameters<XrefsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = (|| {
            let direction = match params.direction.as_deref() {
                Some(value) => XrefDirection::from_str(value)?,
                None => XrefDirection::To,
            };
            self.service().xrefs(
                &params.handle,
                &params.address,
                direction,
                params.kind.as_deref(),
                params.limit.unwrap_or(200),
            )
        })();
        respond(result)
    }

    #[tool(
        name = "ura_search_strings",
        annotations(title = "Search strings", read_only_hint = true),
        description = "Scan the file for ASCII and UTF-16LE strings with pagination. Returns file offsets, virtual addresses where mapped, encoding and text."
    )]
    fn ura_search_strings(
        &self,
        Parameters(params): Parameters<SearchStringsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let options = StringScanOptions {
            min_length: params.min_length.unwrap_or(4),
            ascii: params.ascii.unwrap_or(true),
            utf16le: params.utf16le.unwrap_or(true),
            max_results: MAX_STRINGS,
        };
        respond(self.service().strings(
            &params.handle,
            &options,
            params.offset.unwrap_or(0),
            params.limit.unwrap_or(100),
        ))
    }

    #[tool(
        name = "ura_read_bytes",
        annotations(title = "Read bytes", read_only_hint = true),
        description = "Read raw file bytes by virtual address or file offset (exactly one), up to 65536 bytes. Returns hex and printable ASCII alongside the mapping."
    )]
    fn ura_read_bytes(
        &self,
        Parameters(params): Parameters<ReadBytesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().read_bytes(
            &params.handle,
            params.address.as_deref(),
            params.offset.as_deref(),
            params.length,
        ))
    }

    #[tool(
        name = "ura_rename_function",
        annotations(title = "Rename function", read_only_hint = false),
        description = "Persist a function name in an existing .ura project. Requires the server to be started with --enable-writes."
    )]
    fn ura_rename_function(
        &self,
        Parameters(params): Parameters<RenameFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().rename_function(
            &params.handle,
            Path::new(&params.project),
            &params.address,
            &params.name,
        ))
    }

    #[tool(
        name = "ura_add_comment",
        annotations(title = "Add comment", read_only_hint = false),
        description = "Persist a comment on an address in an existing .ura project. Requires the server to be started with --enable-writes."
    )]
    fn ura_add_comment(
        &self,
        Parameters(params): Parameters<AddCommentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().add_comment(
            &params.handle,
            Path::new(&params.project),
            &params.address,
            params.name.as_deref(),
            &params.note,
        ))
    }

    #[tool(
        name = "ura_save_project",
        annotations(title = "Save project", read_only_hint = false),
        description = "Create or update a .ura project for an opened binary. Requires the server to be started with --enable-writes."
    )]
    fn ura_save_project(
        &self,
        Parameters(params): Parameters<SaveProjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().save_project(
            &params.handle,
            Path::new(&params.project),
            params.name.as_deref(),
        ))
    }

    #[tool(
        name = "ura_export_analysis",
        annotations(title = "Export analysis", read_only_hint = false),
        description = "Export a project's annotations and function names as JSON. Requires the server to be started with --enable-writes."
    )]
    fn ura_export_analysis(
        &self,
        Parameters(params): Parameters<ExportAnalysisParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(
            self.service()
                .export_analysis(Path::new(&params.project), Path::new(&params.export)),
        )
    }

    #[tool(
        name = "ura_close_binary",
        annotations(title = "Close binary", read_only_hint = false),
        description = "Close an opened binary and release its analysis results. The handle becomes invalid."
    )]
    fn ura_close_binary(
        &self,
        Parameters(params): Parameters<BinaryHandleParams>,
    ) -> Result<CallToolResult, ErrorData> {
        respond(self.service().close_binary(&params.handle))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for UraServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ura-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

fn signature_override(p: &SetFunctionSignatureParams) -> Result<SignatureOverride, ServiceError> {
    let convention = CallingConvention::parse(&p.convention).ok_or_else(|| {
        ServiceError::InvalidArgument(format!(
            "unknown calling convention '{}'; expected win64, sysv64, cdecl, stdcall, fastcall or thiscall",
            p.convention
        ))
    })?;
    let return_type = TypeRef::parse(&p.return_type, 64).map_err(ServiceError::InvalidArgument)?;
    let mut parameters = Vec::with_capacity(p.parameters.len());
    for (index, parameter) in p.parameters.iter().enumerate() {
        let name = if parameter.name.trim().is_empty() {
            format!("a{index}")
        } else {
            parameter.name.trim().to_string()
        };
        let ty = TypeRef::parse(&parameter.ty, 64).map_err(ServiceError::InvalidArgument)?;
        let location = match (parameter.register.as_deref(), parameter.stack_offset) {
            (Some(register), _) if !register.trim().is_empty() => Location::Register {
                name: register.trim().to_string(),
            },
            (_, Some(offset)) => Location::Stack { offset, width: 64 },
            _ => {
                return Err(ServiceError::InvalidArgument(format!(
                    "parameter '{name}' needs a register or a stack offset"
                )))
            }
        };
        parameters.push(SignatureParameterInput { name, location, ty });
    }
    Ok(SignatureOverride {
        convention,
        return_type,
        parameters,
        variadic: p.variadic,
    })
}

fn respond<T: Serialize>(result: Result<T, ServiceError>) -> Result<CallToolResult, ErrorData> {
    match result {
        Ok(value) => structured(value),
        Err(error) => {
            let value = serde_json::to_value(ErrorView::new(&error)).map_err(serialization)?;
            Ok(CallToolResult::structured_error(value))
        }
    }
}

fn structured<T: Serialize>(value: T) -> Result<CallToolResult, ErrorData> {
    let value: Value = serde_json::to_value(value).map_err(serialization)?;
    Ok(CallToolResult::structured(value))
}

fn serialization(error: serde_json::Error) -> ErrorData {
    ErrorData::internal_error(format!("response serialization failed: {error}"), None)
}
