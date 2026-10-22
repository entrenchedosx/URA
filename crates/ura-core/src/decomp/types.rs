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
        self.valid_at(0)
    }
    fn valid_at(&self, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        match self {
            Self::Unknown { bits, reason } => {
                reason.len() <= 4096 && bits.map_or(true, |b| (1..=64).contains(&b))
            }
            Self::Void | Self::Bool => true,
            Self::Int { bits, .. } => (1..=64).contains(bits),
            Self::Float { bits } => matches!(bits, 32 | 64 | 80),
            Self::Pointer { to, address_bits } => {
                matches!(address_bits, 16 | 32 | 64) && to.valid_at(depth + 1)
            }
            Self::Array { element, count } => {
                element.valid_at(depth + 1) && count.map_or(true, |count| count > 0)
            }
            Self::Struct { name } | Self::Union { name } | Self::Named { name } => {
                type_identifier(name)
            }
            Self::Enum { name, underlying } => {
                type_identifier(name)
                    && matches!(underlying.as_ref(), Self::Int { .. })
                    && underlying.valid_at(depth + 1)
            }
            Self::Function {
                return_type,
                parameters,
                ..
            } => {
                return_type.valid_at(depth + 1)
                    && parameters.len() <= 64
                    && parameters.iter().all(|p| p.valid_at(depth + 1))
            }
            Self::Typedef { name, target } => type_identifier(name) && target.valid_at(depth + 1),
            Self::Qualified { qualifier, target } => {
                matches!(qualifier.as_str(), "const" | "volatile" | "restrict")
                    && target.valid_at(depth + 1)
            }
        }
    }
    pub fn bits(&self, database: &TypeDatabase) -> Option<u64> {
        self.bits_at(database, 0)
    }
    fn bits_at(&self, database: &TypeDatabase, depth: usize) -> Option<u64> {
        if depth > 32 {
            return None;
        }
        match self {
            Self::Unknown { bits, .. } => bits.map(u64::from),
            Self::Void => None,
            Self::Bool => Some(8),
            Self::Int { bits, .. } => Some(u64::from(*bits)),
            Self::Float { bits } => Some(u64::from(*bits)),
            Self::Pointer { address_bits, .. } => Some(u64::from(*address_bits)),
            Self::Array { element, count } => {
                element.bits_at(database, depth + 1)?.checked_mul((*count)?)
            }
            Self::Struct { name } | Self::Union { name } => {
                database.structures.get(name).and_then(|s| s.size_bits())
            }
            Self::Enum { underlying, .. } => underlying.bits_at(database, depth + 1),
            Self::Typedef { target, .. } => target.bits_at(database, depth + 1),
            Self::Named { name } => database
                .typedefs
                .get(name)
                .and_then(|target| target.bits_at(database, depth + 1)),
            Self::Function { .. } => None,
            Self::Qualified { target, .. } => target.bits_at(database, depth + 1),
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
        if !matches!(address_bits, 16 | 32 | 64) {
            return Err("type target must be 16, 32 or 64 bits".into());
        }
        if text.len() > 2048 {
            return Err("type spelling exceeds 2048 bytes".into());
        }
        Self::parse_at(text, address_bits, 0)
    }
    fn parse_at(text: &str, address_bits: u16, depth: usize) -> Result<Self, String> {
        if depth > 32 {
            return Err("type nesting exceeds 32 levels".into());
        }
        let mut text = text.trim();
        if text.is_empty() {
            return Err("type is empty".into());
        }
        if let Some(rest) = text.strip_prefix("const ") {
            return Ok(Self::Qualified {
                qualifier: "const".into(),
                target: Box::new(Self::parse_at(rest, address_bits, depth + 1)?),
            });
        }
        if let Some(rest) = text.strip_prefix("volatile ") {
            return Ok(Self::Qualified {
                qualifier: "volatile".into(),
                target: Box::new(Self::parse_at(rest, address_bits, depth + 1)?),
            });
        }
        if let Some(open) = text.rfind('[') {
            if text.ends_with(']') {
                let base = Self::parse_at(&text[..open], address_bits, depth + 1)?;
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
                to: Box::new(Self::parse_at(base, address_bits, depth + 1)?),
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
            "i32" | "int32_t" | "int" => Self::Int {
                bits: 32,
                signed: Some(true),
            },
            "usize" | "size_t" => Self::uint(address_bits),
            "ssize_t" => Self::Int {
                bits: address_bits,
                signed: Some(true),
            },
            "long" | "unsigned long" => {
                return Err("long depends on the target ABI; use i32, u32, i64 or u64".into())
            }
            "u64" | "uint64_t" | "qword" | "unsigned long long" => Self::uint(64),
            "i64" | "int64_t" | "long long" => Self::Int {
                bits: 64,
                signed: Some(true),
            },
            "f32" | "float" => Self::Float { bits: 32 },
            "f64" | "double" => Self::Float { bits: 64 },
            "f80" => Self::Float { bits: 80 },
            "unknown" => Self::unknown(None, "user supplied unknown type"),
            _ => {
                if let Some(width) = text.strip_prefix("int").and_then(|s| s.parse::<u16>().ok()) {
                    Self::int(width)
                } else if let Some(width) = text
                    .strip_prefix("unknown")
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    Self::unknown(Some(width), "user supplied unknown type")
                } else if let Some(name) = text.strip_prefix("struct ") {
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
        self.size?.checked_mul(8)
    }
    pub fn valid(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self
            .alignment
            .is_some_and(|a| !a.is_power_of_two() || a > 4096)
        {
            errors.push("structure alignment must be a power of two from 1 to 4096".into());
        }
        if self.size.is_some_and(|s| s > u64::MAX / 8) {
            errors.push("structure size exceeds the representable bit size".into());
        }
        if !type_identifier(&self.name) {
            errors.push("structure name must be 1..256 characters".into());
        }
        if self.fields.len() > 512 {
            errors.push("structure fields are limited to 512".into());
            return errors;
        }
        let mut names = BTreeSet::new();
        for field in &self.fields {
            if !type_identifier(&field.name) {
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
        if !matches!(self.address_bits, 16 | 32 | 64) {
            errors.push("type database requires a valid target width".into());
        }
        if self.structures.len() > 256 || self.typedefs.len() > 256 {
            errors.push("type library is limited to 256 structures and 256 aliases".into());
            return errors;
        }
        for (name, structure) in &self.structures {
            if name != &structure.name {
                errors.push(format!("structure key '{name}' disagrees with its name"));
            }
            errors.extend(structure.valid());
            if structure.fields.len() > 512 {
                continue;
            }
            let mut seen = BTreeSet::new();
            if alias_cycle(
                &TypeRef::Struct { name: name.clone() },
                self,
                &mut seen,
                0,
                &mut 4096,
            ) {
                errors.push(format!(
                    "structure '{name}' has a cyclic by-value or excessively complex layout"
                ));
            }
            let mut ranges = Vec::new();
            for field in &structure.fields {
                let actual = field.ty.size(self);
                if let (Some(actual), Some(explicit)) = (actual, field.size) {
                    if actual > explicit {
                        errors.push(format!(
                            "field '{}' type exceeds its declared storage",
                            field.name
                        ));
                    }
                }
                let width = field.size.or(actual);
                if let Some(width) = width {
                    if let Some(end) = field.offset.checked_add(width) {
                        if structure.size.is_some_and(|size| end > size) {
                            errors.push(format!("field '{}' exceeds structure size", field.name));
                        }
                        ranges.push((field.offset, end, &field.name));
                    } else {
                        errors.push(format!("field '{}' storage overflows", field.name));
                    }
                }
            }
            if !structure.union {
                ranges.sort_by_key(|r| r.0);
                let mut end = 0;
                for (start, next, name) in ranges {
                    if start < end {
                        errors.push(format!("field '{name}' overlaps another field"));
                    }
                    end = end.max(next);
                }
            }
        }
        for (name, target) in &self.typedefs {
            if !type_identifier(name) || !target.valid() {
                errors.push(format!("invalid typedef '{name}'"));
            }
            let mut seen = BTreeSet::new();
            if alias_cycle(target, self, &mut seen, 0, &mut 4096) {
                errors.push(format!(
                    "typedef '{name}' has a cyclic or excessively nested definition"
                ));
            }
        }
        errors
    }
    pub fn struct_size(&self, name: &str) -> Option<u64> {
        self.structures.get(name)?.size
    }
}

fn type_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn alias_cycle(
    ty: &TypeRef,
    db: &TypeDatabase,
    seen: &mut BTreeSet<String>,
    depth: usize,
    budget: &mut usize,
) -> bool {
    if depth > 32 || *budget == 0 {
        return true;
    }
    *budget -= 1;
    match ty {
        TypeRef::Named { name } => {
            let Some(target) = db.typedefs.get(name) else {
                return false;
            };
            if !seen.insert(name.clone()) {
                return true;
            }
            let cyclic = alias_cycle(target, db, seen, depth + 1, budget);
            seen.remove(name);
            cyclic
        }
        TypeRef::Struct { name } | TypeRef::Union { name } => {
            let Some(structure) = db.structures.get(name) else {
                return false;
            };
            let tag = format!("tag:{name}");
            if !seen.insert(tag.clone()) {
                return true;
            }
            let cyclic = structure
                .fields
                .iter()
                .any(|field| alias_cycle(&field.ty, db, seen, depth + 1, budget));
            seen.remove(&tag);
            cyclic
        }
        TypeRef::Array { element, .. } => alias_cycle(element, db, seen, depth + 1, budget),
        TypeRef::Typedef { target, .. } | TypeRef::Qualified { target, .. } => {
            alias_cycle(target, db, seen, depth + 1, budget)
        }
        _ => false,
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
    /// Authoritative per-definition evidence. `variables` remains a legacy
    /// display summary and must not be applied to every SSA version.
    #[serde(default)]
    pub values: Vec<SsaInferredType>,
    pub conflicts: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}

const MAX_INFERRED_VARIABLES: usize = 5_000;

/// Derive only constraints that the lifted semantics actually justify.
pub fn infer_types(bundle: &crate::ir::inspect::Bundle) -> TypeInference {
    infer_types_with_control(bundle, &()).unwrap_or_default()
}

pub fn infer_types_with_control(
    bundle: &crate::ir::inspect::Bundle,
    control: &dyn crate::AnalysisControl,
) -> Result<TypeInference, String> {
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
        if control.is_cancelled() {
            return Err("type inference cancelled".into());
        }
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
                crate::ir::Operation::Equal
                | crate::ir::Operation::UnsignedLess
                | crate::ir::Operation::SignedLess => {
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
    let (values, values_partial) = infer_ssa_types(ssa, control)?;
    Ok(TypeInference {
        variables,
        values,
        conflicts: total_conflicts,
        truncated: truncated || values_partial,
        notes: vec![
            "Legacy summaries do not establish source signedness or pointee layout. Version-specific evidence is reported separately in values."
                .into(),
            "A value used as an address is evidence, not proof of a valid pointer.".into(),
        ],
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsaInferredType {
    pub value: crate::ir::ssa::Value,
    pub storage: crate::ir::Type,
    pub ty: TypeRef,
    pub confidence: Confidence,
    pub constraints: Vec<TypeConstraint>,
    pub conflicts: Vec<String>,
}

/// Separate machine storage widths from use-derived types, keyed by exact SSA
/// definition. Unknown effects cannot become a known value merely from a use.
pub fn infer_ssa_types(
    ssa: &crate::ir::ssa::SsaFunction,
    control: &dyn crate::AnalysisControl,
) -> Result<(Vec<SsaInferredType>, bool), String> {
    use crate::ir::{ssa::Use, Operation, Type};
    const MAX_VALUES: usize = 20_000;
    let mut records = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    let mut evidence: BTreeMap<_, Vec<TypeConstraint>> = BTreeMap::new();
    let mut truncated = false;
    let mut remember = |value: crate::ir::ssa::Value| {
        if records.len() < MAX_VALUES {
            if let Some(variable) = ssa.variables.get(value.variable) {
                records.insert(value, variable.ty);
            }
        } else if !records.contains_key(&value) {
            truncated = true;
        }
    };
    for block in &ssa.blocks {
        if control.is_cancelled() {
            return Err("SSA type inference cancelled".into());
        }
        for phi in &block.phis {
            remember(phi.output);
            for value in phi.incoming.values().chain(phi.initial.iter()) {
                remember(*value);
            }
        }
        for statement in &block.statements {
            if let Some(output) = statement.output {
                remember(output);
                if matches!(statement.op, Operation::Unknown { .. }) {
                    unknown.insert(output);
                }
            }
            for operand in &statement.args {
                if let Use::Value(value) = operand {
                    remember(*value);
                }
            }
            let address_operand = match statement.op {
                Operation::Load | Operation::Store => statement.args.get(1),
                Operation::ToAddress | Operation::Call => statement.args.first(),
                _ => None,
            };
            if let Some(Use::Value(value)) = address_operand {
                let claims = evidence.entry(*value).or_default();
                if claims.len() < 8 {
                    claims.push(TypeConstraint {
                        kind: "addressUse".into(),
                        source: Some(statement.source.0),
                        detail:
                            "exact SSA value interpreted as an address; pointee validity is unknown"
                                .into(),
                    });
                }
            }
        }
        for operand in block
            .terminator
            .state
            .iter()
            .chain(block.terminator.value.iter())
        {
            if let Use::Value(value) = operand {
                remember(*value);
            }
        }
    }
    let definitions: BTreeMap<_, _> = ssa
        .blocks
        .iter()
        .flat_map(|block| &block.statements)
        .filter_map(|statement| statement.output.map(|value| (value, statement)))
        .collect();
    let initial_evidence: Vec<_> = evidence
        .iter()
        .map(|(value, claims)| (*value, claims.clone()))
        .collect();
    for (mut value, claims) in initial_evidence {
        for _ in 0..16 {
            let Some(definition) = definitions.get(&value) else {
                break;
            };
            let input = match definition.op {
                Operation::Copy | Operation::ToAddress | Operation::ToBits => {
                    definition.args.first()
                }
                Operation::Add | Operation::Sub
                    if matches!(definition.args.get(1), Some(Use::Constant(_))) =>
                {
                    definition.args.first()
                }
                _ => None,
            };
            let Some(Use::Value(parent)) = input else {
                break;
            };
            if ssa.variables[parent.variable].ty.width() != ssa.variables[value.variable].ty.width()
            {
                break;
            }
            value = *parent;
            let entry = evidence.entry(value).or_default();
            for claim in &claims {
                if entry.len() < 8 && !entry.iter().any(|old| old.source == claim.source) {
                    entry.push(claim.clone());
                }
            }
        }
    }
    let values = records
        .into_iter()
        .map(|(value, storage)| {
            let constraints = evidence.remove(&value).unwrap_or_default();
            let width = storage.width();
            let mut conflicts = Vec::new();
            let (ty, confidence) = if unknown.contains(&value) {
                (
                    TypeRef::unknown(width, "definition has unknown machine effects"),
                    Confidence::Unknown,
                )
            } else if !constraints.is_empty() && width == Some(ssa.address_width) {
                (
                    TypeRef::pointer_to(
                        TypeRef::unknown(None, "pointee type not established"),
                        ssa.address_width,
                    ),
                    Confidence::Low,
                )
            } else if !constraints.is_empty() {
                conflicts.push("address-use width differs from target width".into());
                (
                    TypeRef::unknown(width, "conflicting address width"),
                    Confidence::Unknown,
                )
            } else {
                match storage {
                    Type::Bits(1) => (TypeRef::Bool, Confidence::High),
                    Type::Bits(bits) => (TypeRef::int(bits), Confidence::Low),
                    Type::Address(bits) => (
                        TypeRef::pointer_to(
                            TypeRef::unknown(None, "pointee type not established"),
                            bits,
                        ),
                        Confidence::Low,
                    ),
                    Type::Memory => (
                        TypeRef::unknown(None, "memory state token"),
                        Confidence::Unknown,
                    ),
                }
            };
            SsaInferredType {
                value,
                storage,
                ty,
                confidence,
                constraints,
                conflicts,
            }
        })
        .collect();
    Ok((values, truncated))
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
