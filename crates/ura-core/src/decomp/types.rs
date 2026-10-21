//! Architecture-aware, deliberately conservative type descriptions.
//!
//! Inference attaches evidence and conflicts; it never silently upgrades an
//! integer to a pointer or invents a structure from a single memory read.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unknown,
}
impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TypeRef {
    Unknown {
        bits: Option<u16>,
        reason: String,
    },
    Void,
    Bool,
    Int {
        bits: u16,
        signed: Option<bool>,
    },
    Float {
        bits: u16,
    },
    Pointer {
        to: Box<TypeRef>,
        address_bits: u16,
    },
    Array {
        element: Box<TypeRef>,
        count: Option<u64>,
    },
    Struct {
        name: String,
    },
    Union {
        name: String,
    },
    Enum {
        name: String,
        underlying: Box<TypeRef>,
    },
    Function {
        return_type: Box<TypeRef>,
        parameters: Vec<TypeRef>,
        variadic: bool,
    },
    Typedef {
        name: String,
        target: Box<TypeRef>,
    },
    Named {
        name: String,
    },
    Qualified {
        qualifier: String,
        target: Box<TypeRef>,
    },
}
impl TypeRef {
    pub fn unknown(bits: Option<u16>, reason: impl Into<String>) -> Self {
        Self::Unknown {
            bits,
            reason: reason.into(),
        }
    }
    pub fn int(bits: u16) -> Self {
        Self::Int { bits, signed: None }
    }
    pub fn uint(bits: u16) -> Self {
        Self::Int {
            bits,
            signed: Some(false),
        }
    }
    pub fn pointer_to(to: TypeRef, address_bits: u16) -> Self {
        Self::Pointer {
            to: Box::new(to),
            address_bits,
        }
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::Unknown { bits, .. } => bits.map_or(true, |b| (1..=64).contains(&b)),
            Self::Void | Self::Bool => true,
            Self::Int { bits, .. } => (1..=64).contains(bits),
            Self::Float { bits } => matches!(bits, 32 | 64 | 80),
            Self::Pointer { to, address_bits } => {
                matches!(address_bits, 16 | 32 | 64) && to.valid()
            }
            Self::Array { element, count } => {
                element.valid() && count.map_or(true, |count| count > 0)
            }
            Self::Struct { name } | Self::Union { name } | Self::Named { name } => {
                !name.trim().is_empty() && name.chars().count() <= 256
            }
            Self::Enum { name, underlying } => {
                !name.trim().is_empty() && name.chars().count() <= 256 && underlying.valid()
            }
            Self::Function {
                return_type,
                parameters,
                ..
            } => {
                return_type.valid()
                    && parameters.len() <= 64
                    && parameters.iter().all(TypeRef::valid)
            }
            Self::Typedef { name, target } => {
                !name.trim().is_empty() && name.chars().count() <= 256 && target.valid()
            }
            Self::Qualified { qualifier, target } => {
                matches!(qualifier.as_str(), "const" | "volatile" | "restrict") && target.valid()
            }
        }
    }
    pub fn bits(&self, database: &TypeDatabase) -> Option<u64> {
        match self {
            Self::Unknown { bits, .. } => bits.map(u64::from),
            Self::Void => None,
            Self::Bool => Some(8),
            Self::Int { bits, .. } => Some(u64::from(*bits)),
            Self::Float { bits } => Some(u64::from(*bits)),
            Self::Pointer { address_bits, .. } => Some(u64::from(*address_bits)),
            Self::Array { element, count } => Some(element.bits(database)? * (*count)?),
            Self::Struct { name } | Self::Union { name } => {
                database.structures.get(name).and_then(|s| s.size_bits())
            }
            Self::Enum { underlying, .. } => underlying.bits(database),
            Self::Typedef { target, .. } => target.bits(database),
            Self::Named { name } => database
                .typedefs
                .get(name)
                .and_then(|target| target.bits(database)),
            Self::Function { .. } => None,
            Self::Qualified { target, .. } => target.bits(database),
        }
    }
    pub fn size(&self, database: &TypeDatabase) -> Option<u64> {
        self.bits(database).map(|bits| bits.div_ceil(8))
    }
    pub fn display(&self) -> String {
        match self {
            Self::Unknown { bits, .. } => match bits {
                Some(bits) => format!("unknown{bits}"),
                None => "unknown".into(),
            },
            Self::Void => "void".into(),
            Self::Bool => "bool".into(),
            Self::Int {
                bits,
                signed: Some(true),
            } => format!("i{bits}"),
            Self::Int {
                bits,
                signed: Some(false),
            } => format!("u{bits}"),
            Self::Int { bits, signed: None } => format!("int{bits}"),
            Self::Float { bits } => format!("f{bits}"),
            Self::Pointer { to, .. } => format!("{}*", to.display()),
            Self::Array {
                element,
                count: Some(count),
            } => format!("{}[{count}]", element.display()),
            Self::Array {
                element,
                count: None,
            } => format!("{}[]", element.display()),
            Self::Struct { name } => format!("struct {name}"),
            Self::Union { name } => format!("union {name}"),
            Self::Enum { name, .. } => format!("enum {name}"),
            Self::Function {
                return_type,
                parameters,
                variadic,
            } => {
                let mut args = parameters.iter().map(TypeRef::display).collect::<Vec<_>>();
                if *variadic {
                    args.push("...".into());
                }
                format!("{}({})", return_type.display(), args.join(", "))
            }
            Self::Typedef { name, .. } => name.clone(),
            Self::Named { name } => name.clone(),
            Self::Qualified { qualifier, target } => {
                format!("{qualifier} {}", target.display())
            }
        }
    }
    pub fn parse(text: &str, address_bits: u16) -> Result<Self, String> {
        let mut text = text.trim();
        if text.is_empty() {
            return Err("type is empty".into());
        }
        if let Some(rest) = text.strip_prefix("const ") {
            return Ok(Self::Qualified {
                qualifier: "const".into(),
                target: Box::new(Self::parse(rest, address_bits)?),
            });
        }
        if let Some(rest) = text.strip_prefix("volatile ") {
            return Ok(Self::Qualified {
                qualifier: "volatile".into(),
                target: Box::new(Self::parse(rest, address_bits)?),
            });
        }
        if let Some(open) = text.rfind('[') {
            if text.ends_with(']') {
                let base = Self::parse(&text[..open], address_bits)?;
                let count = &text[open + 1..text.len() - 1];
                let count = if count.trim().is_empty() {
                    None
                } else {
                    Some(
                        count
                            .trim()
                            .parse::<u64>()
                            .map_err(|_| "array length must be a positive integer".to_string())
                            .and_then(|count| {
                                if count == 0 {
                                    Err("array length must be positive".into())
                                } else {
                                    Ok(count)
                                }
                            })?,
                    )
                };
                return Ok(Self::Array {
                    element: Box::new(base),
                    count,
                });
            }
        }
        if let Some(base) = text.strip_suffix('*') {
            return Ok(Self::Pointer {
                to: Box::new(Self::parse(base, address_bits)?),
                address_bits,
            });
        }
        text = text.trim();
        let scalar = match text {
            "void" => Self::Void,
            "bool" | "_Bool" => Self::Bool,
            "char" | "u8" | "uint8_t" | "byte" => Self::uint(8),
            "i8" | "int8_t" | "signed char" => Self::Int {
                bits: 8,
                signed: Some(true),
            },
            "u16" | "uint16_t" | "word" | "ushort" => Self::uint(16),
            "i16" | "int16_t" | "short" => Self::Int {
                bits: 16,
                signed: Some(true),
            },
            "u32" | "uint32_t" | "dword" | "uint" | "unsigned int" | "unsigned" => Self::uint(32),
            "i32" | "int32_t" | "int" | "long" if text != "long" => Self::Int {
                bits: 32,
                signed: Some(true),
            },
            "u64" | "uint64_t" | "qword" | "unsigned long long" | "usize" => Self::uint(64),
            "i64" | "int64_t" | "long long" | "ssize_t" | "long" => Self::Int {
                bits: 64,
                signed: Some(true),
            },
            "f32" | "float" => Self::Float { bits: 32 },
            "f64" | "double" => Self::Float { bits: 64 },
            _ => {
                if let Some(name) = text.strip_prefix("struct ") {
                    Self::Struct {
                        name: name.trim().to_string(),
                    }
                } else if let Some(name) = text.strip_prefix("union ") {
                    Self::Union {
                        name: name.trim().to_string(),
                    }
                } else if let Some(name) = text.strip_prefix("enum ") {
                    Self::Enum {
                        name: name.trim().to_string(),
                        underlying: Box::new(Self::int(32)),
                    }
                } else if text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && text
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                {
                    Self::Named {
                        name: text.to_string(),
                    }
                } else {
                    return Err(format!("unsupported type syntax '{text}'"));
                }
            }
        };
        if !scalar.valid() {
            return Err("invalid type description".into());
        }
        Ok(scalar)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructField {
    pub name: String,
    pub offset: u64,
    pub ty: TypeRef,
    pub size: Option<u64>,
    pub source: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Structure {
    pub name: String,
    pub size: Option<u64>,
    pub alignment: Option<u64>,
    pub fields: Vec<StructField>,
    pub union: bool,
    pub source: String,
}
impl Structure {
    pub fn size_bits(&self) -> Option<u64> {
        self.size.map(|size| size * 8)
    }
    pub fn valid(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.name.trim().is_empty() || self.name.chars().count() > 256 {
            errors.push("structure name must be 1..256 characters".into());
        }
        if self.fields.len() > 512 {
            errors.push("structure fields are limited to 512".into());
        }
        let mut names = BTreeSet::new();
        for field in &self.fields {
            if field.name.trim().is_empty() || field.name.chars().count() > 256 {
                errors.push("field names must be 1..256 characters".into());
            }
            if !names.insert(field.name.clone()) {
                errors.push(format!("duplicate field name '{}'", field.name));
            }
            if !field.ty.valid() {
                errors.push(format!("invalid type for field '{}'", field.name));
            }
            if (field.offset as u128) + u128::from(field.size.unwrap_or(0))
                > u128::from(self.size.unwrap_or(u64::MAX))
            {
                errors.push(format!("field '{}' exceeds the structure size", field.name));
            }
        }
        if !self.union {
            let mut sorted = self.fields.iter().collect::<Vec<_>>();
            sorted.sort_by_key(|field| field.offset);
            let mut end = 0u64;
            for field in sorted {
                if field.offset < end {
                    errors.push(format!("field '{}' overlaps a previous field", field.name));
                }
                end = end.max(field.offset.saturating_add(field.size.unwrap_or(0)));
            }
        }
        errors
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeDatabase {
    pub address_bits: u16,
    pub structures: BTreeMap<String, Structure>,
    pub typedefs: BTreeMap<String, TypeRef>,
}
impl TypeDatabase {
    pub fn new(address_bits: u16) -> Self {
        Self {
            address_bits,
            ..Default::default()
        }
    }
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (name, structure) in &self.structures {
            if name != &structure.name {
                errors.push(format!("structure key '{name}' disagrees with its name"));
            }
            errors.extend(structure.valid());
        }
        for (name, target) in &self.typedefs {
            if name.trim().is_empty() || !target.valid() {
                errors.push(format!("invalid typedef '{name}'"));
            }
        }
        errors
    }
    pub fn struct_size(&self, name: &str) -> Option<u64> {
        self.structures.get(name)?.size
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeConstraint {
    pub kind: String,
    pub source: Option<u64>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferredType {
    pub variable: String,
    pub variable_id: usize,
    pub ty: TypeRef,
    pub confidence: Confidence,
    pub constraints: Vec<TypeConstraint>,
    pub conflicts: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeInference {
    pub variables: Vec<InferredType>,
    pub conflicts: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}

const MAX_INFERRED_VARIABLES: usize = 5_000;

/// Derive only constraints that the lifted semantics actually justify.
pub fn infer_types(bundle: &crate::ir::inspect::Bundle) -> TypeInference {
    use crate::ir::ssa::{SsaFunction, Use};
    let ssa: &SsaFunction = &bundle.ssa;
    let mut constraints: BTreeMap<usize, Vec<TypeConstraint>> = BTreeMap::new();
    let mut add = |value: crate::ir::ssa::Value, kind: &str, source: u64, detail: String| {
        if value.version == 0
            || ssa.variables[value.variable].kind == crate::ir::VariableKind::Temporary
        {
            constraints
                .entry(value.variable)
                .or_default()
                .push(TypeConstraint {
                    kind: kind.into(),
                    source: Some(source),
                    detail,
                });
        }
    };
    for block in &ssa.blocks {
        for statement in &block.statements {
            match &statement.op {
                crate::ir::Operation::Load => {
                    if let Some(Use::Value(value)) = statement.args.get(1) {
                        add(
                            *value,
                            "addressUse",
                            statement.source.0,
                            "load address".into(),
                        );
                    }
                }
                crate::ir::Operation::Store => {
                    if let Some(Use::Value(value)) = statement.args.get(1) {
                        add(
                            *value,
                            "addressUse",
                            statement.source.0,
                            "store address".into(),
                        );
                    }
                    if let Some(Use::Value(value)) = statement.args.get(2) {
                        add(
                            *value,
                            "storedValue",
                            statement.source.0,
                            "stored value".into(),
                        );
                    }
                }
                crate::ir::Operation::Call => {
                    if let Some(Use::Value(value)) = statement.args.first() {
                        add(
                            *value,
                            "addressUse",
                            statement.source.0,
                            "call target".into(),
                        );
                    }
                    for (index, arg) in statement.args.iter().enumerate().skip(1) {
                        if let Use::Value(value) = arg {
                            add(
                                *value,
                                "callArgument",
                                statement.source.0,
                                format!("call argument {index}"),
                            );
                        }
                    }
                }
                crate::ir::Operation::Equal | crate::ir::Operation::UnsignedLess => {
                    for arg in &statement.args {
                        if let Use::Value(value) = arg {
                            add(
                                *value,
                                "comparison",
                                statement.source.0,
                                "comparison operand".into(),
                            );
                        }
                    }
                }
                crate::ir::Operation::Add
                | crate::ir::Operation::Sub
                | crate::ir::Operation::And
                | crate::ir::Operation::Or
                | crate::ir::Operation::Xor
                | crate::ir::Operation::Not
                | crate::ir::Operation::Shl
                | crate::ir::Operation::Shr
                | crate::ir::Operation::Select
                | crate::ir::Operation::Parity => {
                    for arg in &statement.args {
                        if let Use::Value(value) = arg {
                            add(
                                *value,
                                "integerArithmetic",
                                statement.source.0,
                                format!("{:?} operand", statement.op),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let truncated = constraints.len() > MAX_INFERRED_VARIABLES;
    let mut variables = Vec::new();
    let mut total_conflicts = 0usize;
    for (variable_id, evidence) in constraints.into_iter().take(MAX_INFERRED_VARIABLES) {
        let variable = &ssa.variables[variable_id];
        let width = variable.ty.width();
        let address_use = evidence.iter().any(|c| c.kind == "addressUse");
        let mut conflicts = Vec::new();
        let (ty, confidence) = if address_use {
            if width == Some(ssa.address_width) {
                (
                    TypeRef::pointer_to(
                        TypeRef::unknown(None, "pointee type is not inferred"),
                        ssa.address_width,
                    ),
                    Confidence::Medium,
                )
            } else {
                conflicts.push(format!(
                    "value is used as a {}-bit address but has width {:?}",
                    ssa.address_width, width
                ));
                (
                    TypeRef::unknown(width, "conflicting address width"),
                    Confidence::Low,
                )
            }
        } else if variable.ty == crate::ir::Type::Bits(1) {
            (TypeRef::Bool, Confidence::High)
        } else if let Some(bits) = width {
            (
                TypeRef::Int { bits, signed: None },
                if evidence.len() >= 3 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                },
            )
        } else {
            (
                TypeRef::unknown(None, "no scalar width"),
                Confidence::Unknown,
            )
        };
        total_conflicts += conflicts.len();
        variables.push(InferredType {
            variable: variable.name.clone(),
            variable_id,
            ty,
            confidence,
            constraints: evidence,
            conflicts,
        });
    }
    variables.sort_by(|a, b| {
        a.variable
            .cmp(&b.variable)
            .then(a.variable_id.cmp(&b.variable_id))
    });
    TypeInference {
        variables,
        conflicts: total_conflicts,
        truncated,
        notes: vec![
            "Signedness, pointee types and floating-point use are not inferred from scalar IR."
                .into(),
            "A value used as an address is evidence, not proof of a valid pointer.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_c_style_types_and_rejects_noise() {
        for (text, expected) in [
            ("u32", "u32"),
            ("int", "i32"),
            ("void*", "void*"),
            ("u8*", "u8*"),
            ("u16[4]", "u16[4]"),
            ("struct Player", "struct Player"),
            ("const char*", "const u8*"),
        ] {
            assert_eq!(TypeRef::parse(text, 64).unwrap().display(), expected);
        }
        assert!(TypeRef::parse("unsigned long long long", 64).is_err());
        assert!(TypeRef::parse("u8[0]", 64).is_err());
        assert!(TypeRef::parse("main()", 64).is_err());
    }

    #[test]
    fn structure_validation_detects_overlap_and_out_of_range_fields() {
        let mut database = TypeDatabase::new(64);
        let structure = Structure {
            name: "Pair".into(),
            size: Some(16),
            alignment: Some(8),
            fields: vec![
                StructField {
                    name: "a".into(),
                    offset: 0,
                    ty: TypeRef::uint(64),
                    size: Some(8),
                    source: "user".into(),
                },
                StructField {
                    name: "b".into(),
                    offset: 8,
                    ty: TypeRef::uint(64),
                    size: Some(8),
                    source: "user".into(),
                },
            ],
            union: false,
            source: "user".into(),
        };
        assert!(structure.valid().is_empty());
        let mut broken = structure.clone();
        broken.fields[1].offset = 4;
        assert!(!broken.valid().is_empty());
        broken.fields[1].offset = 12;
        assert!(!broken.valid().is_empty());
        database.structures.insert("Pair".into(), structure);
        assert_eq!(
            TypeRef::Struct {
                name: "Pair".into()
            }
            .size(&database),
            Some(16)
        );
    }
}
