use super::*;
use ura_core::patch::{parse_hex, Preview};
#[derive(Args)]
pub struct Location {
    /// Explicit address space: offset, va or rva. Address values are hexadecimal.
    #[arg(long,value_parser=["offset","va","rva"])]
    pub space: String,
    #[arg(long)]
    pub address: String,
}
impl Location {
    fn parsed(&self) -> Result<ura_core::patch::Address, ServiceError> {
        ura_service::patch_address(&self.space, &self.address)
    }
}
#[derive(Subcommand)]
pub enum PatchCommand {
    /// Create/attach a project for subsequent patch writes
    Init {
        #[arg(long)]
        destination: PathBuf,
    },
    List,
    Read {
        #[command(flatten)]
        location: Location,
        #[arg(long, default_value_t = 16)]
        length: usize,
    },
    Preview {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        expected: String,
        #[arg(long)]
        replacement: String,
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Apply an exact previously reviewed preview JSON (including its revision)
    Apply {
        #[arg(long)]
        preview: PathBuf,
    },
    /// Preview supported Intel syntax; --apply explicitly commits it
    Instruction {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        budget: usize,
        #[arg(long)]
        assembly: String,
        #[arg(long)]
        pad: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value = "")]
        comment: String,
    },
    History {
        #[arg(long,value_parser=["undo","redo","revert","revertAll"])]
        action: String,
        #[arg(long)]
        id: Option<u64>,
    },
    Export {
        #[arg(long)]
        destination: PathBuf,
    },
    Manifest {
        #[arg(long)]
        destination: PathBuf,
    },
}
pub fn run(
    service: &mut Service,
    policy: &PathPolicy,
    common: &CommonArgs,
    operation: PatchCommand,
) -> Result<(), ServiceError> {
    let handle = open(service, common)?.handle;
    let project = || {
        common.project.as_deref().ok_or_else(|| {
            ServiceError::InvalidArgument("--project is required for a patch write".into())
        })
    };
    match operation {
        PatchCommand::Init { destination } => {
            print_json(&service.save_project(&handle, &destination, None)?)
        }
        PatchCommand::List => print_json(&service.list_patches(&handle)?),
        PatchCommand::Read { location, length } => {
            print_json(&service.read_effective_bytes(&handle, location.parsed()?, length)?)
        }
        PatchCommand::Preview {
            location,
            expected,
            replacement,
            comment,
        } => {
            let parse =
                |s: &str| parse_hex(s).map_err(|e| ServiceError::InvalidArgument(e.to_string()));
            print_json(&service.preview_byte_patch(
                &handle,
                location.parsed()?,
                &parse(&expected)?,
                &parse(&replacement)?,
                &comment,
            )?)
        }
        PatchCommand::Apply { preview } => {
            let value: serde_json::Value = read_definition(policy, &preview)?;
            let p: Preview = serde_json::from_value(value.get("patch").unwrap_or(&value).clone())
                .map_err(|e| ServiceError::InvalidArgument(e.to_string()))?;
            print_json(&service.apply_patch(&handle, project()?, &p)?)
        }
        PatchCommand::Instruction {
            location,
            budget,
            assembly,
            pad,
            apply,
            comment,
        } => {
            service.analyze(&handle, &AnalysisOptions::default())?;
            let preview = service.preview_instruction_patch(
                &handle,
                location.parsed()?,
                budget,
                &assembly,
                pad,
                &comment,
            )?;
            if apply {
                print_json(&service.apply_patch(&handle, project()?, &preview.patch)?)
            } else {
                print_json(&preview)
            }
        }
        PatchCommand::History { action, id } => {
            print_json(&service.patch_history(&handle, project()?, &action, id)?)
        }
        PatchCommand::Export { destination } => {
            print_json(&service.export_patched_binary(&handle, &destination)?)
        }
        PatchCommand::Manifest { destination } => {
            print_json(&service.export_patch_manifest(&handle, &destination)?)
        }
    }
}
