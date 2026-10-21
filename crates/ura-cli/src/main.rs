use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use ura_core::analysis::{DEFAULT_MAX_BLOCKS, DEFAULT_MAX_FUNCTIONS, DEFAULT_MAX_INSTRUCTIONS};
use ura_core::{parse_address, AnalysisOptions, AnalysisReport, StringScanOptions};
use ura_service::{
    BytesResponse, CallGraphResponse, CfgResponse, DisassemblyResponse, ErrorView,
    FunctionListResponse, FunctionSort, HighLevelResponse, OpenBinaryResponse, PathPolicy, Service,
    ServiceError, SignatureResponse, StackFrameResponse, StringsResponse, TypesResponse,
    XrefDirection, XrefsResponse,
};

#[derive(Parser)]
#[command(
    name = "ura-cli",
    version,
    about = "Headless URA static analysis for PE, ELF and Mach-O images",
    long_about = "Headless URA static analysis. Samples are parsed and analysed locally; they are never executed. \
                  All paths must resolve inside an allowed root (--allow, default: the current directory)."
)]
struct Cli {
    /// Directory that binary, project and export paths must resolve inside (repeatable)
    #[arg(long = "allow", value_name = "DIR", global = true)]
    allow: Vec<PathBuf>,
    /// Permit explicit project-editing commands
    #[arg(long, global = true)]
    enable_writes: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a project type library, inspect one structure, or import validated definitions
    TypeLibrary {
        #[command(flatten)]
        common: CommonArgs,
        /// Exact structure or union name
        #[arg(long, conflicts_with = "import")]
        name: Option<String>,
        /// Replace the project type library from a TypeDatabase JSON file (requires --enable-writes)
        #[arg(long, value_name = "FILE")]
        import: Option<PathBuf>,
    },
    /// Save a user signature from a SignatureOverride JSON file
    SetSignature {
        #[command(flatten)]
        common: CommonArgs,
        #[arg(long)]
        function: String,
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
    },
    /// Save or clear a physical stack slot's name/type override
    SetVariableType {
        #[command(flatten)]
        common: CommonArgs,
        #[arg(long)]
        function: String,
        #[arg(long, allow_hyphen_values = true)]
        offset: i64,
        #[arg(long)]
        name: Option<String>,
        /// Type spelling; omit both --name and --type to restore inference
        #[arg(long = "type")]
        ty: Option<String>,
    },
    /// Summarize binary metadata, sections, imports and exports
    Info {
        #[command(flatten)]
        common: CommonArgs,
    },
    /// Discover functions, basic blocks and cross-references
    Analyze {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
    },
    /// List discovered functions
    Functions {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Case-insensitive filter on display name, symbol or address
        #[arg(long)]
        query: Option<String>,
        /// Zero-based function offset for pagination
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Maximum number of functions to return (1-1000)
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Sort key: address, name, instructions or references
        #[arg(long, default_value = "address")]
        sort: String,
    },
    /// Disassemble instructions starting at a virtual address
    Disasm {
        #[command(flatten)]
        common: CommonArgs,
        /// Virtual address in hexadecimal (0x prefix optional)
        #[arg(long)]
        address: String,
        /// Number of instructions to decode (1-2000)
        #[arg(long, default_value_t = 50)]
        count: usize,
    },
    /// Scan ASCII and UTF-16LE strings
    Strings {
        #[command(flatten)]
        common: CommonArgs,
        /// Minimum string length in bytes/characters (2-512)
        #[arg(long, default_value_t = 4)]
        min_length: usize,
        /// Disable ASCII scanning
        #[arg(long)]
        no_ascii: bool,
        /// Disable UTF-16LE scanning
        #[arg(long)]
        no_utf16: bool,
        /// Zero-based string offset for pagination
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Maximum number of strings to return (1-2000)
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List call, jump and data cross-references for an address
    Xrefs {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Virtual address in hexadecimal
        #[arg(long)]
        address: String,
        /// Direction: to or from
        #[arg(long, default_value = "to")]
        direction: String,
        /// Restrict to one kind: call, jump, conditionalJump or data
        #[arg(long)]
        kind: Option<String>,
        /// Maximum number of cross-references to return (1-2000)
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Show the control-flow graph of a function
    Cfg {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Function start address (or any address inside the function)
        #[arg(long)]
        function: String,
        /// Maximum number of basic blocks to return (1-500)
        #[arg(long = "max-cfg-blocks", default_value_t = 200)]
        max_cfg_blocks: usize,
    },
    /// Inspect verified raw or SSA IR for a discovered function
    Ir {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        #[arg(long)]
        function: String,
        #[arg(long)]
        ssa: bool,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Inspect immediate dominators and dominance frontiers
    Dominators {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        #[arg(long)]
        function: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Inspect unsupported IR semantics and conservative dataflow summaries
    Diagnostics {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        #[arg(long)]
        function: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Recover a function's calling convention, parameters and return value
    Signature {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Function start address (or any address inside the function)
        #[arg(long)]
        function: String,
    },
    /// Recover physical stack slots and access evidence for a function
    Stack {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Function start address (or any address inside the function)
        #[arg(long)]
        function: String,
    },
    /// Show conservative type constraints inferred for a function
    Types {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Function start address (or any address inside the function)
        #[arg(long)]
        function: String,
    },
    /// Inspect the bounded direct-call graph, optionally around one function
    Callgraph {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Optional function focus address
        #[arg(long)]
        function: Option<String>,
        /// Callee expansion depth from the focus (1-16)
        #[arg(long, default_value_t = 1)]
        depth: usize,
        /// Maximum nodes to return (1-2000)
        #[arg(long, default_value_t = 200)]
        max_nodes: usize,
    },
    /// Render recovered high-level control structure as C-like lines
    Highlevel {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        analysis: AnalysisArgs,
        /// Function start address (or any address inside the function)
        #[arg(long)]
        function: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Include the typed tree, value types and original SSA semantics (2 MiB maximum)
        #[arg(long, requires = "json")]
        ast: bool,
    },
    /// Read raw file bytes by virtual address or file offset
    Hex {
        #[command(flatten)]
        common: CommonArgs,
        /// Virtual address in hexadecimal
        #[arg(long, conflicts_with = "offset")]
        address: Option<String>,
        /// File offset in hexadecimal
        #[arg(long)]
        offset: Option<String>,
        /// Number of bytes to read (1-65536)
        #[arg(long, default_value_t = 256)]
        length: usize,
    },
}

impl Command {
    fn json(&self) -> bool {
        match self {
            Command::Info { common }
            | Command::TypeLibrary { common, .. }
            | Command::SetSignature { common, .. }
            | Command::SetVariableType { common, .. }
            | Command::Analyze { common, .. }
            | Command::Functions { common, .. }
            | Command::Disasm { common, .. }
            | Command::Strings { common, .. }
            | Command::Xrefs { common, .. }
            | Command::Cfg { common, .. }
            | Command::Ir { common, .. }
            | Command::Dominators { common, .. }
            | Command::Diagnostics { common, .. }
            | Command::Signature { common, .. }
            | Command::Stack { common, .. }
            | Command::Types { common, .. }
            | Command::Callgraph { common, .. }
            | Command::Highlevel { common, .. }
            | Command::Hex { common, .. } => common.json,
        }
    }
}

#[derive(Args)]
struct CommonArgs {
    /// Binary to inspect
    binary: PathBuf,
    /// Existing .ura project whose function names and manual functions should be applied
    #[arg(long, value_name = "FILE")]
    project: Option<PathBuf>,
    /// Emit machine-readable JSON on stdout
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone)]
struct AnalysisArgs {
    /// Maximum instructions decoded during analysis (64-2000000)
    #[arg(long, default_value_t = DEFAULT_MAX_INSTRUCTIONS)]
    max_instructions: usize,
    /// Maximum functions discovered (1-50000)
    #[arg(long, default_value_t = DEFAULT_MAX_FUNCTIONS)]
    max_functions: usize,
    /// Maximum basic blocks constructed (1-500000)
    #[arg(long, default_value_t = DEFAULT_MAX_BLOCKS)]
    max_blocks: usize,
    /// Do not discover functions reached only through call instructions
    #[arg(long)]
    no_follow_calls: bool,
    /// Disable automatic function seeds from symbols (manual project starts remain)
    #[arg(long)]
    no_symbol_seeds: bool,
}

impl AnalysisArgs {
    fn options(&self) -> AnalysisOptions {
        AnalysisOptions {
            max_instructions: self.max_instructions,
            max_functions: self.max_functions,
            max_blocks: self.max_blocks,
            follow_calls: !self.no_follow_calls,
            seed_symbols: !self.no_symbol_seeds,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.command.json();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                match serde_json::to_string_pretty(&ErrorView::new(&error)) {
                    Ok(text) => println!("{text}"),
                    Err(_) => eprintln!("error: {error}"),
                }
            } else {
                eprintln!("error: {error}");
            }
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), ServiceError> {
    let policy = PathPolicy::new(cli.allow)?;
    let mut service = Service::new(policy.clone(), cli.enable_writes);
    match cli.command {
        Command::TypeLibrary {
            common,
            name,
            import,
        } => {
            let handle = open(&mut service, &common)?.handle;
            if let Some(path) = import {
                let library = read_definition(&policy, &path)?;
                let project = common.project.as_deref().ok_or_else(|| {
                    ServiceError::InvalidArgument(
                        "--project is required to save a type library".into(),
                    )
                })?;
                service.set_type_library(&handle, project, &library)?;
            }
            if let Some(name) = name {
                let response = service.structure_definition(&handle, &name)?;
                if common.json {
                    print_json(&response)
                } else {
                    println!(
                        "{} {} (size {:?}, alignment {:?})",
                        if response.structure.union {
                            "union"
                        } else {
                            "struct"
                        },
                        response.structure.name,
                        response.structure.size,
                        response.structure.alignment
                    );
                    for field in response.structure.fields {
                        println!("  +{}  {} {}", field.offset, field.ty.display(), field.name);
                    }
                    Ok(())
                }
            } else {
                let response = service.type_library(&handle)?;
                if common.json {
                    print_json(&response)
                } else {
                    for structure in response.database.structures.values() {
                        println!(
                            "{} {} ({} fields)",
                            if structure.union { "union" } else { "struct" },
                            structure.name,
                            structure.fields.len()
                        );
                    }
                    for (name, ty) in &response.database.typedefs {
                        println!("{name} = {}", ty.display());
                    }
                    Ok(())
                }
            }
        }
        Command::SetSignature {
            common,
            function,
            input,
        } => {
            let project = common.project.as_deref().ok_or_else(|| {
                ServiceError::InvalidArgument("--project is required to save a signature".into())
            })?;
            let signature = read_definition(&policy, &input)?;
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &AnalysisOptions::default())?;
            let response =
                service.set_function_signature(&handle, project, &function, &signature)?;
            if common.json {
                print_json(&response)
            } else {
                render_signature(&response);
                Ok(())
            }
        }
        Command::SetVariableType {
            common,
            function,
            offset,
            name,
            ty,
        } => {
            let project = common.project.as_deref().ok_or_else(|| {
                ServiceError::InvalidArgument(
                    "--project is required to save a variable override".into(),
                )
            })?;
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &AnalysisOptions::default())?;
            let bits = service.info(&handle)?.info.bitness as u16;
            let ty = ty
                .map(|text| ura_core::decomp::TypeRef::parse(&text, bits))
                .transpose()
                .map_err(ServiceError::InvalidArgument)?;
            let response = service.set_stack_variable(
                &handle,
                project,
                &function,
                offset,
                name.as_deref(),
                ty.as_ref(),
            )?;
            if common.json {
                print_json(&response)
            } else {
                println!(
                    "Stack override {}",
                    if response.removed { "removed" } else { "saved" }
                );
                Ok(())
            }
        }
        Command::Info { common } => {
            let opened = open(&mut service, &common)?;
            if common.json {
                print_json(&opened)
            } else {
                render_info(&opened);
                Ok(())
            }
        }
        Command::Analyze { common, analysis } => {
            let handle = open(&mut service, &common)?.handle;
            let response = service.analyze(&handle, &analysis.options())?;
            if common.json {
                print_json(&response)
            } else {
                render_analysis(&response.options, &response.report);
                Ok(())
            }
        }
        Command::Functions {
            common,
            analysis,
            query,
            offset,
            limit,
            sort,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let sort = FunctionSort::from_str(&sort)?;
            let response = service.functions(&handle, query.as_deref(), offset, limit, sort)?;
            if common.json {
                print_json(&response)
            } else {
                render_functions(&response);
                Ok(())
            }
        }
        Command::Disasm {
            common,
            address,
            count,
        } => {
            let handle = open(&mut service, &common)?.handle;
            let response = service.disassembly(&handle, &address, count)?;
            if common.json {
                print_json(&response)
            } else {
                render_disassembly(&response);
                Ok(())
            }
        }
        Command::Strings {
            common,
            min_length,
            no_ascii,
            no_utf16,
            offset,
            limit,
        } => {
            let handle = open(&mut service, &common)?.handle;
            let options = StringScanOptions {
                min_length,
                ascii: !no_ascii,
                utf16le: !no_utf16,
                max_results: ura_core::MAX_STRINGS,
            };
            let response = service.strings(&handle, &options, offset, limit)?;
            if common.json {
                print_json(&response)
            } else {
                render_strings(&response);
                Ok(())
            }
        }
        Command::Xrefs {
            common,
            analysis,
            address,
            direction,
            kind,
            limit,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let direction = XrefDirection::from_str(&direction)?;
            let response = service.xrefs(&handle, &address, direction, kind.as_deref(), limit)?;
            if common.json {
                print_json(&response)
            } else {
                render_xrefs(&response);
                Ok(())
            }
        }
        Command::Cfg {
            common,
            analysis,
            function,
            max_cfg_blocks,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.cfg(&handle, &function, max_cfg_blocks)?;
            if common.json {
                print_json(&response)
            } else {
                render_cfg(&response);
                Ok(())
            }
        }
        Command::Ir {
            common,
            analysis,
            function,
            ssa,
            offset,
            limit,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let page = service.ir(&handle, &function, ssa, offset, limit)?;
            if common.json {
                print_json(&page)
            } else {
                println!(
                    "{} IR v{} · {} · rows {}..{} / {}",
                    page.representation,
                    page.ir_version,
                    page.function,
                    page.offset,
                    page.offset + page.rows.len(),
                    page.total
                );
                for row in page.rows {
                    println!("{}  {}", row.source, row.text);
                }
                Ok(())
            }
        }
        Command::Dominators {
            common,
            analysis,
            function,
            offset,
            limit,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let page = service.dominators(&handle, &function, offset, limit)?;
            if common.json {
                print_json(&page)
            } else {
                for row in page.rows {
                    println!(
                        "{}  idom={}  frontier={:?}",
                        row.block, row.immediate_dominator, row.frontier
                    );
                }
                Ok(())
            }
        }
        Command::Diagnostics {
            common,
            analysis,
            function,
            offset,
            limit,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let page = service.analysis_diagnostics(&handle, &function, offset, limit)?;
            if common.json {
                print_json(&page)
            } else {
                println!(
                    "{} unsupported instructions · {} constant values · {} dead definitions",
                    page.total, page.constant_values, page.dead_definitions
                );
                for d in page.diagnostics {
                    println!("{}  {}", d.source, d.message);
                }
                Ok(())
            }
        }
        Command::Signature {
            common,
            analysis,
            function,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.function_signature(&handle, &function)?;
            if common.json {
                print_json(&response)
            } else {
                render_signature(&response);
                Ok(())
            }
        }
        Command::Stack {
            common,
            analysis,
            function,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.stack_frame(&handle, &function)?;
            if common.json {
                print_json(&response)
            } else {
                render_stack(&response);
                Ok(())
            }
        }
        Command::Types {
            common,
            analysis,
            function,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.inferred_types(&handle, &function)?;
            if common.json {
                print_json(&response)
            } else {
                render_types(&response);
                Ok(())
            }
        }
        Command::Callgraph {
            common,
            analysis,
            function,
            depth,
            max_nodes,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.call_graph(&handle, function.as_deref(), depth, max_nodes)?;
            if common.json {
                print_json(&response)
            } else {
                render_call_graph(&response);
                Ok(())
            }
        }
        Command::Highlevel {
            common,
            analysis,
            function,
            offset,
            limit,
            ast,
        } => {
            let handle = open(&mut service, &common)?.handle;
            service.analyze(&handle, &analysis.options())?;
            let response = service.high_level_with_ast(&handle, &function, offset, limit, ast)?;
            if common.json {
                print_json(&response)
            } else {
                render_high_level(&response);
                Ok(())
            }
        }
        Command::Hex {
            common,
            address,
            offset,
            length,
        } => {
            let handle = open(&mut service, &common)?.handle;
            let response =
                service.read_bytes(&handle, address.as_deref(), offset.as_deref(), length)?;
            if common.json {
                print_json(&response)
            } else {
                render_bytes(&response);
                Ok(())
            }
        }
    }
}

fn read_definition<T: serde::de::DeserializeOwned>(
    policy: &PathPolicy,
    path: &std::path::Path,
) -> Result<T, ServiceError> {
    use std::io::Read;
    let path = policy.allow_read(path)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| ServiceError::Io(e.to_string()))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    if bytes.len() > 1024 * 1024 {
        return Err(ServiceError::LimitExceeded(
            "definition file exceeds 1 MiB".into(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| ServiceError::InvalidArgument(e.to_string()))
}

fn open(service: &mut Service, common: &CommonArgs) -> Result<OpenBinaryResponse, ServiceError> {
    service.open_binary(&common.binary, common.project.as_deref())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), ServiceError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| ServiceError::Serialization(error.to_string()))?;
    println!("{text}");
    Ok(())
}

fn render_info(response: &OpenBinaryResponse) {
    let info = &response.info;
    println!("Handle:      {}", response.handle);
    println!("Path:        {}", info.path);
    if let Some(project) = &response.attached_project {
        println!("Project:     {project}");
    }
    println!(
        "Format:      {} ({}, {}, {}-bit, {}-endian)",
        info.format, info.object_kind, info.architecture, info.bitness, info.endianness
    );
    println!("SHA-256:     {}", info.sha256);
    println!("File size:   {} bytes", info.file_size);
    println!("Image base:  {}", info.image_base);
    println!(
        "Entry point: {}",
        info.entry_point.as_deref().unwrap_or("none")
    );
    println!(
        "Sections:    {}  Symbols: {}  Imports: {}  Exports: {}",
        info.section_count,
        info.symbol_count,
        response.imports.len(),
        response.exports.len()
    );
    for warning in &info.warnings {
        println!("Warning:     {warning}");
    }

    println!();
    println!(
        "{:<12} {:<14} {:>10} {:>10} {:<6} KIND",
        "SECTION", "ADDRESS", "SIZE", "OFFSET", "PERMS"
    );
    for section in &response.sections {
        println!(
            "{:<12} {:<14} {:>10} {:>10} {:<6} {}",
            section.name,
            section.address,
            section.size,
            section.file_offset.as_deref().unwrap_or("-"),
            section.permissions,
            section.kind
        );
    }

    if !response.imports.is_empty() {
        println!();
        println!("Imports:");
        for import in response.imports.iter().take(50) {
            match &import.library {
                Some(library) => println!("  {library}!{}", import.name),
                None => println!("  {}", import.name),
            }
        }
        if response.imports.len() > 50 {
            println!("  ... {} more", response.imports.len() - 50);
        }
    }

    if !response.exports.is_empty() {
        println!();
        println!("Exports:");
        for export in response.exports.iter().take(50) {
            println!("  {} {}", export.address, export.name);
        }
        if response.exports.len() > 50 {
            println!("  ... {} more", response.exports.len() - 50);
        }
    }
}

fn render_analysis(options: &ura_service::AnalysisOptionsView, report: &AnalysisReport) {
    println!(
        "Options:      instructions <= {}, functions <= {}, blocks <= {} (follow calls: {})",
        options.max_instructions, options.max_functions, options.max_blocks, options.follow_calls
    );
    println!("Instructions: {}", report.instruction_count);
    println!("Functions:    {}", report.function_count);
    println!("Blocks:       {}", report.block_count);
    println!(
        "Xrefs:        {} ({} data)",
        report.xref_count, report.data_xref_count
    );
    println!("Elapsed:      {} ms", report.elapsed_ms);
    println!("Cancelled:    {}", report.cancelled);
    println!("Truncated:    {}", report.truncated);
    if report.diagnostics_dropped > 0 {
        println!("Diagnostics:  {} dropped", report.diagnostics_dropped);
    }
    if !report.diagnostics.is_empty() {
        println!();
        for diagnostic in &report.diagnostics {
            match &diagnostic.address {
                Some(address) => println!("  {address}: {}", diagnostic.message),
                None => println!("  {}", diagnostic.message),
            }
        }
    }
}

fn render_functions(response: &FunctionListResponse) {
    let first = if response.returned == 0 {
        0
    } else {
        response.offset + 1
    };
    let last = response.offset + response.returned;
    println!(
        "Functions {first}-{last} of {} (sort: {})",
        response.total, response.sort
    );
    println!(
        "{:<14} {:<32} {:<12} {:>7} {:>7} {:>6} {:>7}",
        "ADDRESS", "NAME", "ORIGIN", "INSNS", "BLOCKS", "REFS", "SIZE"
    );
    for function in &response.functions {
        println!(
            "{:<14} {:<32} {:<12} {:>7} {:>7} {:>6} {:>7}",
            function.address,
            truncate(&function.name, 32),
            function.origin,
            function.instruction_count,
            function.block_count,
            function.reference_count,
            function.size
        );
    }
    if response.offset + response.returned < response.total {
        println!(
            "... {} more; use --offset {}",
            response.total - response.offset - response.returned,
            response.offset + response.returned
        );
    }
}

fn render_disassembly(response: &DisassemblyResponse) {
    let page = &response.page;
    println!(
        "{} in {} ({}), {} instructions, {} bytes",
        page.start_address,
        page.section,
        page.architecture,
        page.instructions.len(),
        page.end_address
    );
    for instruction in &page.instructions {
        println!(
            "{}  {:<24} {}",
            instruction.address,
            truncate(&instruction.bytes, 24),
            instruction.text
        );
    }
    for warning in &page.warnings {
        println!("Warning: {warning}");
    }
}

fn render_strings(response: &StringsResponse) {
    println!(
        "Strings {}-{} of {} (min length {}, ASCII: {}, UTF-16LE: {})",
        if response.returned == 0 {
            0
        } else {
            response.offset + 1
        },
        response.offset + response.returned,
        response.total,
        response.min_length,
        response.ascii,
        response.utf16le
    );
    for entry in &response.strings {
        println!(
            "{}  {}  {:<8} {}",
            entry.offset,
            entry.address.as_deref().unwrap_or("-"),
            entry.encoding,
            entry.value
        );
    }
    if response.scan_truncated {
        println!("Warning: the scan reached the 200000-result limit");
    }
    if response.has_more {
        println!(
            "... {} more; use --offset {}",
            response.total - response.offset - response.returned,
            response.offset + response.returned
        );
    }
}

fn render_xrefs(response: &XrefsResponse) {
    println!(
        "Xrefs {} {}: {} shown of {} (kind: {})",
        response.direction,
        response.address,
        response.returned,
        response.total,
        response.kind.as_deref().unwrap_or("all")
    );
    for xref in &response.xrefs {
        let from = xref
            .from_name
            .as_deref()
            .map(|name| format!("{name} ({})", xref.from))
            .unwrap_or_else(|| xref.from.clone());
        let to = xref
            .to_name
            .as_deref()
            .map(|name| format!("{name} ({})", xref.to))
            .unwrap_or_else(|| xref.to.clone());
        let kind = match &xref.data_kind {
            Some(data_kind) => format!("{}:{}", xref.kind, data_kind),
            None => xref.kind.clone(),
        };
        println!("{from} -> {to}  [{kind}]");
    }
    if response.truncated {
        println!(
            "... {} more; use --limit {}",
            response.total - response.returned,
            response.total
        );
    }
}

fn render_cfg(response: &CfgResponse) {
    println!(
        "Function {} at {} ({} blocks{}, max {})",
        response.function.name,
        response.function.address,
        response.function.block_count,
        if response.truncated {
            ", truncated"
        } else {
            ""
        },
        response.max_blocks
    );
    for block in &response.blocks {
        let successors = if block.successors.is_empty() {
            String::new()
        } else {
            format!(
                " -> {}",
                block
                    .successors
                    .iter()
                    .map(|edge| format!("{} ({})", edge.target, edge.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        println!(
            "{}..{}  {} instructions{}",
            block.address,
            block.end,
            block.instructions.len(),
            successors
        );
    }
}

fn render_signature(response: &SignatureResponse) {
    let signature = &response.signature;
    println!("{}  {}", response.function, signature.declaration());
    println!(
        "Convention: {} ({}){}",
        signature.convention.name(),
        signature.convention_confidence.name(),
        if signature.user_override {
            ", user override"
        } else {
            ""
        }
    );
    println!(
        "Return:     {} ({})",
        signature.return_value.ty.display(),
        signature.return_value.confidence.name()
    );
    if signature.parameters.is_empty() {
        println!("Parameters: none observed");
    } else {
        println!(
            "{:<4} {:<24} {:<20} {:<10} {:>5}",
            "IDX", "NAME", "LOCATION", "TYPE", "USES"
        );
        for parameter in &signature.parameters {
            println!(
                "{:<4} {:<24} {:<20} {:<10} {:>5}",
                parameter.index,
                truncate(&parameter.name, 24),
                parameter.location.display(),
                parameter.ty.display(),
                parameter.uses
            );
        }
    }
    if signature.variadic == Some(true) {
        println!("Variadic:   yes");
    }
    for conflict in &signature.conflicts {
        println!("Conflict:   {conflict}");
    }
    for note in &response.diagnostics {
        println!("Note:       {note}");
    }
}

fn render_stack(response: &StackFrameResponse) {
    let frame = &response.frame;
    println!(
        "{}  {}  frame {} bytes, locals {}, incoming args {}",
        response.function,
        response.name,
        frame.frame_size,
        frame.local_bytes,
        frame.incoming_argument_bytes
    );
    println!(
        "Frame pointer: {}  return offset: {:+}  alignment: {}  slots: {}{}",
        frame.uses_frame_pointer,
        frame.return_address_offset,
        frame.alignment,
        frame.slots.len(),
        if frame.truncated { " (truncated)" } else { "" }
    );
    for slot in &frame.slots {
        let name = slot.user_name.as_deref().unwrap_or(slot.name.as_str());
        let ty = slot.user_type.as_ref().unwrap_or(&slot.ty).display();
        println!(
            "{:+6}  {:<18} {:<20} {:<12} r{} w{}  {}/{}",
            slot.offset,
            slot.kind,
            truncate(name, 20),
            ty,
            slot.reads,
            slot.writes,
            slot.first_instruction,
            slot.last_instruction
        );
    }
    for note in &frame.notes {
        println!("Note:       {note}");
    }
}

fn render_types(response: &TypesResponse) {
    let types = &response.types;
    println!(
        "{}  {} variables, {} conflicts{}",
        response.function,
        types.variables.len(),
        types.conflicts,
        if types.truncated { " (truncated)" } else { "" }
    );
    for error in &response.database_errors {
        println!("Database:   {error}");
    }
    for variable in &types.variables {
        println!(
            "{:<24} {:<20} {:<10} {} constraint(s)",
            truncate(&variable.variable, 24),
            variable.ty.display(),
            variable.confidence.name(),
            variable.constraints.len()
        );
        for conflict in &variable.conflicts {
            println!("  conflict: {conflict}");
        }
    }
    for note in &types.notes {
        println!("Note:       {note}");
    }
}

fn render_call_graph(response: &CallGraphResponse) {
    println!(
        "Call graph: {} of {} nodes, {} of {} edges{}{}",
        response.returned_nodes,
        response.total_nodes,
        response.returned_edges,
        response.total_edges,
        response
            .focus
            .as_deref()
            .map(|focus| format!(", focus {focus}"))
            .unwrap_or_default(),
        if response.truncated {
            ", truncated"
        } else {
            ""
        }
    );
    println!(
        "Roots: {}  Leaves: {}  Cycles: {}  Unresolved indirect: {}",
        response.roots.len(),
        response.leaves.len(),
        response.cycles.len(),
        response.unresolved_indirect
    );
    for node in &response.nodes {
        println!(
            "{:<14} {:<32} in {:>3} out {:>3}{}{}",
            node.address,
            truncate(&node.name, 32),
            node.callers,
            node.callees,
            if node.recursive { " recursive" } else { "" },
            if node.depth > 0 {
                format!(" depth {}", node.depth)
            } else {
                String::new()
            }
        );
    }
    for edge in &response.edges {
        println!("{} -> {} [{}]", edge.from, edge.to, edge.kind);
    }
    for note in &response.notes {
        println!("Note:       {note}");
    }
}

fn render_high_level(response: &HighLevelResponse) {
    println!(
        "{}  {}  lines {}-{} of {} ({}){}",
        response.function,
        response.name,
        response.offset,
        response.offset + response.returned,
        response.total,
        response.status,
        if response.truncated { " truncated" } else { "" }
    );
    for line in &response.lines {
        match line.address {
            Some(address) => println!("{:#x}  {}{}", address, "  ".repeat(line.indent), line.text),
            None => println!("{}{}", "  ".repeat(line.indent), line.text),
        }
    }
    for note in &response.notes {
        println!("Note:       {note}");
    }
}

fn render_bytes(response: &BytesResponse) {
    println!(
        "Offset {}  address {}  section {}  {}/{} bytes{}",
        response.offset,
        response.address.as_deref().unwrap_or("-"),
        response.section.as_deref().unwrap_or("-"),
        response.returned_length,
        response.requested_length,
        if response.eof { "  eof" } else { "" }
    );
    let base = parse_address(&response.offset).unwrap_or(0);
    let hex: Vec<&str> = response.hex.split_whitespace().collect();
    let ascii: Vec<char> = response.ascii.chars().collect();
    for (row, (hex_row, ascii_row)) in hex.chunks(16).zip(ascii.chunks(16)).enumerate() {
        let offset = base + (row * 16) as u64;
        println!(
            "0x{:08X}  {:<47}  |{}|",
            offset,
            hex_row.join(" "),
            ascii_row.iter().collect::<String>()
        );
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(3)).collect();
    out.push_str("...");
    out
}
