use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, serde::Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SymbolicParams {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchReadParams {
    pub handle: String,
    pub space: String,
    pub address: String,
    pub length: usize,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchByteParams {
    pub handle: String,
    pub space: String,
    pub address: String,
    pub expected: String,
    pub replacement: String,
    pub comment: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchInstructionParams {
    pub handle: String,
    pub space: String,
    pub address: String,
    pub budget: usize,
    pub assembly: String,
    pub nop_padding: Option<bool>,
    pub comment: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchApplyParams {
    pub handle: String,
    pub project: String,
    pub preview: serde_json::Value,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchHistoryParams {
    pub handle: String,
    pub project: String,
    pub action: String,
    pub id: Option<u64>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PatchExportParams {
    pub handle: String,
    pub destination: String,
    pub manifest: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenBinaryParams {
    #[schemars(
        description = "Explicit raw processor: x86, x86-64, aarch64, arm, thumb, riscv32, riscv64"
    )]
    pub processor: Option<String>,
    pub raw: Option<bool>,
    pub base: Option<String>,
    pub bitness: Option<u32>,
    #[schemars(description = "Path to a PE, ELF or Mach-O file inside an allowed root")]
    pub binary: String,
    #[schemars(description = "Optional existing .ura project whose names and seeds are applied")]
    pub project: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Maximum instructions decoded (64-2000000)")]
    pub max_instructions: Option<usize>,
    #[schemars(description = "Maximum functions discovered (1-50000)")]
    pub max_functions: Option<usize>,
    #[schemars(description = "Maximum basic blocks constructed (1-500000)")]
    pub max_blocks: Option<usize>,
    #[schemars(
        description = "Discover functions reached through call instructions (default true)"
    )]
    pub follow_calls: Option<bool>,
    #[schemars(
        description = "Seed discovered function symbols (default true); explicit project starts remain"
    )]
    pub seed_symbols: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BinaryHandleParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetFunctionsParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Case-insensitive filter on display name, symbol or address")]
    pub query: Option<String>,
    #[schemars(description = "Sort key: address, name, instructions or references")]
    pub sort: Option<String>,
    #[schemars(description = "Zero-based result offset (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum functions to return (1-1000, default 100)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DisassemblyParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Virtual address in hexadecimal (0x prefix optional)")]
    pub address: String,
    #[schemars(description = "Number of instructions to decode (1-2000, default 50)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FunctionParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub address: String,
    #[schemars(description = "Maximum basic blocks to return (1-500, default 200)")]
    pub max_blocks: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CfgParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub function: String,
    #[schemars(description = "Maximum basic blocks to return (1-500, default 200)")]
    pub max_blocks: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct XrefsParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Virtual address in hexadecimal")]
    pub address: String,
    #[schemars(description = "Direction: to (default) or from")]
    pub direction: Option<String>,
    #[schemars(description = "Restrict to one kind: call, jump, conditionalJump or data")]
    pub kind: Option<String>,
    #[schemars(description = "Maximum cross-references to return (1-2000, default 200)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SearchStringsParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Minimum string length in bytes/characters (2-512, default 4)")]
    pub min_length: Option<usize>,
    #[schemars(description = "Scan for ASCII strings (default true)")]
    pub ascii: Option<bool>,
    #[schemars(description = "Scan for UTF-16LE strings (default true)")]
    pub utf16le: Option<bool>,
    #[schemars(description = "Zero-based result offset (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-2000, default 100)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadBytesParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Virtual address in hexadecimal; mutually exclusive with offset")]
    pub address: Option<String>,
    #[schemars(description = "File offset in hexadecimal; mutually exclusive with address")]
    pub offset: Option<String>,
    #[schemars(description = "Number of bytes to read (1-65536)")]
    pub length: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenameFunctionParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Existing .ura project file inside an allowed root")]
    pub project: String,
    #[schemars(description = "Function start address or an address inside the function")]
    pub address: String,
    #[schemars(description = "New function name")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddCommentParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Existing .ura project file inside an allowed root")]
    pub project: String,
    #[schemars(description = "Address the comment is attached to")]
    pub address: String,
    #[schemars(description = "Optional short label for the annotation")]
    pub name: Option<String>,
    #[schemars(description = "Comment text")]
    pub note: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SaveProjectParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Project file to create or update inside an allowed root")]
    pub project: String,
    #[schemars(description = "Project name used only when the project is created")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportAnalysisParams {
    #[schemars(description = "Existing .ura project file inside an allowed root")]
    pub project: String,
    #[schemars(description = "Destination JSON file inside an allowed root")]
    pub export: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IrParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub function: String,
    #[schemars(description = "Zero-based row offset (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum rows to return (page-specific limits: 1-500)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DecompFunctionParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub function: String,
    #[schemars(description = "Zero-based line offset for line-oriented responses (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum lines to return (1-2000, default 200)")]
    pub limit: Option<usize>,
    /// Include the self-contained typed tree and original SSA semantics (2 MiB maximum); high-level IR queries only.
    pub ast: Option<bool>,
    /// Include executable semantic HIR, independently of the legacy presentation AST (2 MiB maximum).
    pub semantic: Option<bool>,
    /// Select one semantic block by exact address. Partial pages preserve global IDs and list external definitions.
    pub semantic_block: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportDecompiledParams {
    pub handle: String,
    pub function: String,
    /// New file inside an allowed root. Existing files are preserved. Requires --enable-writes.
    pub destination: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TypesParams {
    pub handle: String,
    /// Omit to read the persisted project type library without decompiling a function.
    pub function: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StructureParams {
    pub handle: String,
    /// Exact name from the project type library.
    pub name: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetTypeLibraryParams {
    pub handle: String,
    pub project: String,
    /// Complete TypeDatabase object (addressBits, structures and typedefs). Replaces the library atomically after validation; use ura_get_types first.
    pub database: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(
        description = "Optional function focus; omit for a bounded view of the whole graph"
    )]
    pub function: Option<String>,
    #[schemars(description = "Callee expansion depth from the focus (1-16, default 1)")]
    pub depth: Option<usize>,
    #[schemars(description = "Maximum nodes to return (1-2000, default 200)")]
    pub max_nodes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignatureParameterParams {
    #[schemars(description = "Parameter name; an empty name becomes aN")]
    pub name: String,
    #[schemars(description = "Register location such as rcx or rdi")]
    pub register: Option<String>,
    #[schemars(
        description = "Stack offset relative to the return address, used when register is absent"
    )]
    pub stack_offset: Option<i64>,
    #[schemars(description = "C-like type, for example u64, const char* or u16[4]")]
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetFunctionSignatureParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Existing .ura project file inside an allowed root")]
    pub project: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub address: String,
    #[schemars(
        description = "Calling convention: win64, sysv64, cdecl, stdcall, fastcall or thiscall"
    )]
    pub convention: String,
    #[schemars(description = "C-like return type")]
    pub return_type: String,
    #[schemars(
        description = "Ordered parameter list; location evidence remains visible in output"
    )]
    pub parameters: Vec<SignatureParameterParams>,
    #[schemars(description = "Whether the function is variadic")]
    pub variadic: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetVariableTypeParams {
    #[schemars(description = "Handle returned by ura_open_binary")]
    pub handle: String,
    #[schemars(description = "Existing .ura project file inside an allowed root")]
    pub project: String,
    #[schemars(description = "Function start address, or any address inside the function")]
    pub function: String,
    #[schemars(
        description = "Exact entry-relative stack slot offset shown by ura_get_stack_variables"
    )]
    pub offset: i64,
    #[schemars(
        description = "Optional display name; omit together with type to clear the override"
    )]
    pub name: Option<String>,
    #[schemars(
        description = "Optional C-like type; omit together with name to clear the override"
    )]
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

#[derive(Debug, serde::Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_every: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_at_entry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub over: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass_exception: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynamicParams {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitness: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionParams {
    pub request: serde_json::Value,
}
