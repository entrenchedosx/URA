use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenBinaryParams {
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
