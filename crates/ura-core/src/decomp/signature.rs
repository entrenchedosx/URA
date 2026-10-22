use super::types::{Confidence, TypeRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallingConvention {
    Win64,
    SysV64,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Unknown,
}
impl CallingConvention {
    pub fn name(self) -> &'static str {
        match self {
            Self::Win64 => "win64",
            Self::SysV64 => "sysv64",
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::Thiscall => "thiscall",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "win64" | "microsoftx64" | "microsoft-x64" => Some(Self::Win64),
            "sysv64" | "systemv" | "system-v" | "sysv-amd64" => Some(Self::SysV64),
            "cdecl" => Some(Self::Cdecl),
            "stdcall" | "winapi" => Some(Self::Stdcall),
            "fastcall" => Some(Self::Fastcall),
            "thiscall" => Some(Self::Thiscall),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
    pub fn argument_registers(self, address_bits: u16) -> &'static [&'static str] {
        match (self, address_bits) {
            (Self::Win64, 64) => &["rcx", "rdx", "r8", "r9"],
            (Self::SysV64, 64) => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            (Self::Fastcall, 32) => &["ecx", "edx"],
            (Self::Thiscall, 32) => &["ecx"],
            _ => &[],
        }
    }
    pub fn callee_saved(self, address_bits: u16) -> &'static [&'static str] {
        match (self, address_bits) {
            (Self::Win64, 64) => &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            (Self::SysV64, 64) => &["rbx", "rbp", "r12", "r13", "r14", "r15"],
            (_, 32) => &["ebx", "esi", "edi", "ebp"],
            _ => &[],
        }
    }
    pub fn return_register(self, address_bits: u16) -> Option<&'static str> {
        match address_bits {
            64 => Some("rax"),
            32 => Some("eax"),
            _ => None,
        }
    }
    pub fn is_user_selectable(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Location {
    Register { name: String },
    Stack { offset: i64, width: u16 },
    Unknown { reason: String },
}
impl Location {
    pub fn display(&self) -> String {
        match self {
            Self::Register { name } => name.clone(),
            Self::Stack { offset, .. } => {
                if *offset >= 0 {
                    format!("stack+0x{offset:x}")
                } else {
                    format!("stack-0x{:x}", offset.unsigned_abs())
                }
            }
            Self::Unknown { reason } => format!("unknown ({reason})"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: String,
    pub address: Option<u64>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    pub index: usize,
    pub name: String,
    pub location: Location,
    pub ty: TypeRef,
    pub width: u16,
    pub confidence: Confidence,
    pub uses: usize,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnValue {
    pub location: Option<Location>,
    pub ty: TypeRef,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionSignature {
    pub function: u64,
    pub name: String,
    pub convention: CallingConvention,
    pub convention_confidence: Confidence,
    pub parameters: Vec<Parameter>,
    pub return_value: ReturnValue,
    pub variadic: Option<bool>,
    pub stack_parameter_bytes: u32,
    pub caller_observed_arguments: Option<usize>,
    pub user_override: bool,
    pub evidence: Vec<Evidence>,
    pub conflicts: Vec<String>,
}
impl FunctionSignature {
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }
    pub fn declaration(&self) -> String {
        let parameters = self
            .parameters
            .iter()
            .map(|parameter| {
                let name = if parameter.name.is_empty() {
                    format!("a{}", parameter.index)
                } else {
                    parameter.name.clone()
                };
                format!("{} {name}", parameter.ty.display())
            })
            .chain(std::iter::once_with(|| {
                if self.variadic == Some(true) {
                    "...".to_string()
                } else {
                    String::new()
                }
            }))
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} {}({parameters})",
            self.return_value.ty.display(),
            self.name
        )
    }
}

/// A user-authored signature. It is stored separately from inference so a bad
/// override cannot mutate the recovered evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureOverride {
    pub convention: CallingConvention,
    pub return_type: TypeRef,
    pub parameters: Vec<SignatureParameterInput>,
    pub variadic: Option<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureParameterInput {
    pub name: String,
    pub location: Location,
    pub ty: TypeRef,
}
impl SignatureOverride {
    pub fn validate_for_width(&self, bits: u16) -> Vec<String> {
        let mut errors = self.validate();
        let valid = match self.convention {
            CallingConvention::Win64 | CallingConvention::SysV64 => bits == 64,
            CallingConvention::Cdecl
            | CallingConvention::Stdcall
            | CallingConvention::Fastcall
            | CallingConvention::Thiscall => bits == 32,
            CallingConvention::Unknown => matches!(bits, 32 | 64),
        };
        if !valid {
            errors.push(format!(
                "calling convention {} is not supported for {bits}-bit code",
                self.convention.name()
            ));
        }
        errors
    }
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.parameters.len() > 64 {
            errors.push("a signature is limited to 64 parameters".into());
        }
        if !self.return_type.valid() {
            errors.push("return type is invalid".into());
        }
        for parameter in &self.parameters {
            if parameter.name.chars().count() > 256
                || parameter.name.starts_with(|c: char| c.is_ascii_digit())
                || !parameter
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                errors.push(format!("invalid parameter name '{}'", parameter.name));
            }
            if !parameter.ty.valid() {
                errors.push(format!("invalid type for '{}'", parameter.name));
            }
            match &parameter.location {
                Location::Stack { offset, width }
                    if offset.unsigned_abs() > 1 << 30 || !(1..=64).contains(width) =>
                {
                    errors.push(format!("invalid stack location for '{}'", parameter.name))
                }
                Location::Register { name } if !valid_register_location(name, self.convention) => {
                    errors.push(format!("unsupported register location '{name}'"))
                }
                Location::Unknown { reason } if reason.len() > 4096 => {
                    errors.push("location reason exceeds 4096 bytes".into())
                }
                _ => {}
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for parameter in &self.parameters {
            if !parameter.name.is_empty() && !names.insert(&parameter.name) {
                errors.push(format!("duplicate parameter name '{}'", parameter.name));
            }
        }
        errors
    }
}

fn valid_register_location(name: &str, convention: CallingConvention) -> bool {
    let x64 = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
        "r15",
    ];
    let x86 = ["eax", "ebx", "ecx", "edx", "esi", "edi"];
    let general = match convention {
        CallingConvention::Win64 | CallingConvention::SysV64 => x64.contains(&name),
        CallingConvention::Cdecl
        | CallingConvention::Stdcall
        | CallingConvention::Fastcall
        | CallingConvention::Thiscall => x86.contains(&name),
        CallingConvention::Unknown => x64.contains(&name) || x86.contains(&name),
    };
    general
        || name
            .strip_prefix("xmm")
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| n < 16 && name == format!("xmm{n}"))
}

/// Build a signature from a user override alone. Used for call-site hints when
/// the callee itself has not been decompiled in this session.
pub fn describe_override(
    function: u64,
    name: &str,
    override_signature: &SignatureOverride,
) -> FunctionSignature {
    let recovered = FunctionSignature {
        function,
        name: name.to_string(),
        convention: CallingConvention::Unknown,
        convention_confidence: Confidence::Low,
        parameters: vec![],
        return_value: ReturnValue {
            location: None,
            ty: TypeRef::unknown(Some(8), "unknown return type"),
            confidence: Confidence::Low,
            evidence: vec![],
        },
        variadic: None,
        stack_parameter_bytes: 0,
        caller_observed_arguments: None,
        user_override: false,
        evidence: vec![],
        conflicts: vec![],
    };
    apply_override(&recovered, override_signature)
}

pub fn apply_override(
    recovered: &FunctionSignature,
    override_signature: &SignatureOverride,
) -> FunctionSignature {
    let mut result = recovered.clone();
    result.user_override = true;
    result.convention = override_signature.convention;
    result.convention_confidence = Confidence::High;
    result.return_value.ty = override_signature.return_type.clone();
    let bits = if matches!(
        override_signature.convention,
        CallingConvention::Win64 | CallingConvention::SysV64
    ) {
        64
    } else {
        32
    };
    let width = result
        .return_value
        .ty
        .bits(&super::types::TypeDatabase::new(bits));
    result.return_value.location = width
        .filter(|width| *width > 0 && *width <= u64::from(bits))
        .and_then(|_| override_signature.convention.return_register(bits))
        .map(|name| Location::Register { name: name.into() });
    if matches!(
        result.return_value.ty,
        TypeRef::Void
            | TypeRef::Float { .. }
            | TypeRef::Struct { .. }
            | TypeRef::Union { .. }
            | TypeRef::Array { .. }
    ) {
        result.return_value.location = None;
    }
    result.return_value.confidence = Confidence::High;
    result.return_value.evidence = vec![Evidence {
        kind: "userOverride".into(),
        address: None,
        detail: "return type supplied by the project".into(),
    }];
    result.parameters = override_signature
        .parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| Parameter {
            index,
            name: parameter.name.clone(),
            location: parameter.location.clone(),
            ty: parameter.ty.clone(),
            width: parameter
                .ty
                .bits(&Default::default())
                .unwrap_or(0)
                .min(u64::from(u16::MAX)) as u16,
            confidence: Confidence::High,
            uses: 0,
            evidence: vec![Evidence {
                kind: "userOverride".into(),
                address: None,
                detail: "parameter supplied by the project".into(),
            }],
        })
        .collect();
    result.variadic = override_signature.variadic;
    result.evidence.push(Evidence {
        kind: "userOverride".into(),
        address: None,
        detail: "effective signature is project-defined; inferred evidence is retained".into(),
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameter(name: &str, ty: TypeRef) -> Parameter {
        Parameter {
            index: 0,
            name: name.into(),
            location: Location::Register { name: "rcx".into() },
            width: 64,
            ty,
            confidence: Confidence::High,
            uses: 1,
            evidence: vec![],
        }
    }

    fn recovered() -> FunctionSignature {
        FunctionSignature {
            function: 0x1000,
            name: "target".into(),
            convention: CallingConvention::Win64,
            convention_confidence: Confidence::Medium,
            parameters: vec![parameter("a0", TypeRef::uint(64))],
            return_value: ReturnValue {
                location: Some(Location::Register { name: "rax".into() }),
                ty: TypeRef::uint(64),
                confidence: Confidence::Low,
                evidence: vec![],
            },
            variadic: None,
            stack_parameter_bytes: 0,
            caller_observed_arguments: Some(1),
            user_override: false,
            evidence: vec![],
            conflicts: vec![],
        }
    }

    #[test]
    fn conventions_round_trip_and_describe_registers() {
        for convention in [
            CallingConvention::Win64,
            CallingConvention::SysV64,
            CallingConvention::Cdecl,
            CallingConvention::Stdcall,
            CallingConvention::Fastcall,
            CallingConvention::Thiscall,
            CallingConvention::Unknown,
        ] {
            assert_eq!(
                CallingConvention::parse(convention.name()),
                Some(convention)
            );
        }
        assert_eq!(
            CallingConvention::Win64.argument_registers(64),
            &["rcx", "rdx", "r8", "r9"]
        );
        assert_eq!(CallingConvention::SysV64.argument_registers(64).len(), 6);
        assert_eq!(CallingConvention::Thiscall.argument_registers(32), &["ecx"]);
        assert_eq!(CallingConvention::Win64.return_register(64), Some("rax"));
        assert_eq!(CallingConvention::Win64.return_register(32), Some("eax"));
        assert!(!CallingConvention::Unknown.is_user_selectable());
    }

    #[test]
    fn override_validation_rejects_unsafe_names_and_large_lists() {
        let mut override_signature = SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::uint(64),
            parameters: vec![SignatureParameterInput {
                name: "bad name".into(),
                location: Location::Register { name: "rcx".into() },
                ty: TypeRef::uint(64),
            }],
            variadic: Some(true),
        };
        assert_eq!(override_signature.validate().len(), 1);
        override_signature.parameters[0].name = "good_name".into();
        assert!(override_signature.validate().is_empty());
        override_signature.parameters = (0..65)
            .map(|index| SignatureParameterInput {
                name: format!("a{index}"),
                location: Location::Unknown {
                    reason: "test".into(),
                },
                ty: TypeRef::uint(8),
            })
            .collect();
        assert_eq!(override_signature.validate().len(), 1);
    }

    #[test]
    fn applying_an_override_keeps_user_evidence_and_drops_inferred_parameters() {
        let override_signature = SignatureOverride {
            convention: CallingConvention::SysV64,
            return_type: TypeRef::pointer_to(TypeRef::uint(8), 64),
            parameters: vec![
                SignatureParameterInput {
                    name: "first".into(),
                    location: Location::Register { name: "rdi".into() },
                    ty: TypeRef::uint(32),
                },
                SignatureParameterInput {
                    name: "second".into(),
                    location: Location::Stack {
                        offset: 8,
                        width: 64,
                    },
                    ty: TypeRef::uint(64),
                },
            ],
            variadic: Some(false),
        };
        let applied = apply_override(&recovered(), &override_signature);
        assert!(applied.user_override);
        assert_eq!(applied.convention, CallingConvention::SysV64);
        assert_eq!(applied.parameter_count(), 2);
        assert_eq!(applied.parameters[0].name, "first");
        assert_eq!(applied.parameters[1].location.display(), "stack+0x8");
        assert_eq!(applied.return_value.ty.display(), "u8*");
        assert_eq!(applied.variadic, Some(false));
        assert!(applied
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "userOverride"));
    }
}
