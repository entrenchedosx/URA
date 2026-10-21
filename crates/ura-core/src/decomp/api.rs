//! A small curated database of documented imported-API prototypes.
//!
//! These prototypes are external knowledge, not evidence recovered from the
//! binary. They are marked accordingly and are only used to enrich import
//! listings or when the user asks for an import signature by name.
use super::signature::{
    CallingConvention, Evidence, FunctionSignature, Location, Parameter, ReturnValue,
};
use super::types::{Confidence, TypeRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiFamily {
    C,
    Win64,
}
#[derive(Clone, Debug)]
pub struct ApiPrototype {
    pub name: &'static str,
    pub return_type: &'static str,
    pub parameters: &'static [&'static str],
    pub variadic: bool,
    pub family: ApiFamily,
}

const fn api(
    name: &'static str,
    return_type: &'static str,
    parameters: &'static [&'static str],
    variadic: bool,
    family: ApiFamily,
) -> ApiPrototype {
    ApiPrototype {
        name,
        return_type,
        parameters,
        variadic,
        family,
    }
}

pub const API_DATABASE: &[ApiPrototype] = &[
    api(
        "memcpy",
        "void*",
        &["void*", "const void*", "u64"],
        false,
        ApiFamily::C,
    ),
    api(
        "memmove",
        "void*",
        &["void*", "const void*", "u64"],
        false,
        ApiFamily::C,
    ),
    api(
        "memset",
        "void*",
        &["void*", "i32", "u64"],
        false,
        ApiFamily::C,
    ),
    api(
        "memcmp",
        "i32",
        &["const void*", "const void*", "u64"],
        false,
        ApiFamily::C,
    ),
    api("strlen", "u64", &["const char*"], false, ApiFamily::C),
    api(
        "strcmp",
        "i32",
        &["const char*", "const char*"],
        false,
        ApiFamily::C,
    ),
    api(
        "strncmp",
        "i32",
        &["const char*", "const char*", "u64"],
        false,
        ApiFamily::C,
    ),
    api(
        "strcpy",
        "char*",
        &["char*", "const char*"],
        false,
        ApiFamily::C,
    ),
    api("malloc", "void*", &["u64"], false, ApiFamily::C),
    api("calloc", "void*", &["u64", "u64"], false, ApiFamily::C),
    api("realloc", "void*", &["void*", "u64"], false, ApiFamily::C),
    api("free", "void", &["void*"], false, ApiFamily::C),
    api("printf", "i32", &["const char*"], true, ApiFamily::C),
    api(
        "fprintf",
        "i32",
        &["void*", "const char*"],
        true,
        ApiFamily::C,
    ),
    api("puts", "i32", &["const char*"], false, ApiFamily::C),
    api("atoi", "i32", &["const char*"], false, ApiFamily::C),
    api("exit", "void", &["i32"], false, ApiFamily::C),
    api("abort", "void", &[], false, ApiFamily::C),
    api(
        "fopen",
        "void*",
        &["const char*", "const char*"],
        false,
        ApiFamily::C,
    ),
    api(
        "fread",
        "u64",
        &["void*", "u64", "u64", "void*"],
        false,
        ApiFamily::C,
    ),
    api(
        "fwrite",
        "u64",
        &["const void*", "u64", "u64", "void*"],
        false,
        ApiFamily::C,
    ),
    api("fclose", "i32", &["void*"], false, ApiFamily::C),
    api("time", "i64", &["i64*"], false, ApiFamily::C),
    api("rand", "i32", &[], false, ApiFamily::C),
    api("srand", "void", &["u32"], false, ApiFamily::C),
    api("GetLastError", "u32", &[], false, ApiFamily::Win64),
    api("Sleep", "void", &["u32"], false, ApiFamily::Win64),
    api("CloseHandle", "i32", &["void*"], false, ApiFamily::Win64),
    api(
        "ReadFile",
        "i32",
        &["void*", "void*", "u32", "u32*", "void*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "WriteFile",
        "i32",
        &["void*", "const void*", "u32", "u32*", "void*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "CreateFileA",
        "void*",
        &["const char*", "u32", "u32", "void*", "u32", "u32", "void*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "CreateFileW",
        "void*",
        &["const u16*", "u32", "u32", "void*", "u32", "u32", "void*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "VirtualAlloc",
        "void*",
        &["void*", "u64", "u32", "u32"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "VirtualFree",
        "i32",
        &["void*", "u64", "u32"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "LoadLibraryA",
        "void*",
        &["const char*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "LoadLibraryW",
        "void*",
        &["const u16*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "GetProcAddress",
        "void*",
        &["void*", "const char*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "GetModuleHandleA",
        "void*",
        &["const char*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "GetModuleHandleW",
        "void*",
        &["const u16*"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "MessageBoxA",
        "i32",
        &["void*", "const char*", "const char*", "u32"],
        false,
        ApiFamily::Win64,
    ),
    api(
        "MessageBoxW",
        "i32",
        &["void*", "const u16*", "const u16*", "u32"],
        false,
        ApiFamily::Win64,
    ),
];

pub fn lookup(name: &str) -> Option<&'static ApiPrototype> {
    let normalized = normalize(name);
    API_DATABASE
        .iter()
        .find(|prototype| normalize(prototype.name) == normalized)
}

pub fn names() -> Vec<&'static str> {
    let mut names = API_DATABASE
        .iter()
        .map(|prototype| prototype.name)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn normalize(name: &str) -> String {
    let mut value = name.trim().to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix("__imp_") {
        value = rest.to_string();
    }
    if let Some(rest) = value.strip_prefix('_') {
        value = rest.to_string();
    }
    if let Some((base, _)) = value.split_once('@') {
        value = base.to_string();
    }
    value
}

pub fn instantiate(
    prototype: &ApiPrototype,
    convention: CallingConvention,
    address_bits: u16,
) -> Result<FunctionSignature, String> {
    let convention = if convention == CallingConvention::Unknown {
        if address_bits == 64 {
            if prototype.family == ApiFamily::Win64 {
                CallingConvention::Win64
            } else {
                CallingConvention::SysV64
            }
        } else {
            CallingConvention::Cdecl
        }
    } else {
        convention
    };
    let database = super::types::TypeDatabase::new(address_bits);
    let return_type = TypeRef::parse(prototype.return_type, address_bits)?;
    let mut parameters = Vec::with_capacity(prototype.parameters.len());
    for (index, text) in prototype.parameters.iter().enumerate() {
        let ty = TypeRef::parse(text, address_bits)?;
        parameters.push(Parameter {
            index,
            name: format!("a{index}"),
            location: parameter_location(convention, address_bits, index),
            width: ty.bits(&database).unwrap_or(u64::from(address_bits)) as u16,
            ty,
            confidence: Confidence::Medium,
            uses: 0,
            evidence: vec![Evidence {
                kind: "curatedApiPrototype".into(),
                address: None,
                detail: "parameter comes from the curated API database".into(),
            }],
        });
    }
    let return_location = convention
        .return_register(address_bits)
        .map(|name| Location::Register {
            name: name.to_string(),
        });
    Ok(FunctionSignature {
        function: 0,
        name: prototype.name.to_string(),
        convention,
        convention_confidence: Confidence::Low,
        parameters,
        return_value: ReturnValue {
            location: return_location,
            ty: return_type,
            confidence: Confidence::Low,
            evidence: vec![Evidence {
                kind: "curatedApiPrototype".into(),
                address: None,
                detail:
                    "return type comes from the curated API database and is not recovered from this binary"
                        .into(),
            }],
        },
        variadic: Some(prototype.variadic),
        stack_parameter_bytes: 0,
        caller_observed_arguments: None,
        user_override: false,
        evidence: vec![Evidence {
            kind: "curatedApiPrototype".into(),
            address: None,
            detail: "documented imported-API prototype; platform details can differ".into(),
        }],
        conflicts: vec![],
    })
}

fn parameter_location(convention: CallingConvention, address_bits: u16, index: usize) -> Location {
    let registers = convention.argument_registers(address_bits);
    if index < registers.len() {
        return Location::Register {
            name: registers[index].to_string(),
        };
    }
    let word = i64::from(address_bits / 8);
    let offset = match convention {
        CallingConvention::Win64 => word + 0x20 + (index as i64 - registers.len() as i64) * word,
        CallingConvention::SysV64 => word + (index as i64 - registers.len() as i64) * word,
        CallingConvention::Fastcall | CallingConvention::Thiscall => {
            word + (index as i64 - registers.len() as i64) * word
        }
        _ => word + index as i64 * word,
    };
    Location::Stack {
        offset,
        width: address_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_normalizes_import_decorations_and_deduplicates_names() {
        for name in [
            "MessageBoxA",
            "__imp_MessageBoxA",
            "_MessageBoxA@16",
            " messageboxa ",
        ] {
            assert_eq!(
                lookup(name).map(|prototype| prototype.name),
                Some("MessageBoxA")
            );
        }
        assert!(lookup("no_such_api_anywhere").is_none());
        let names = names();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn every_curated_prototype_instantiates_on_supported_widths() {
        for prototype in API_DATABASE {
            for bits in [32u16, 64] {
                let signature = instantiate(prototype, CallingConvention::Unknown, bits).unwrap();
                assert_eq!(signature.parameters.len(), prototype.parameters.len());
                assert_eq!(signature.name, prototype.name);
                assert_eq!(signature.variadic, Some(prototype.variadic));
                assert!(signature
                    .parameters
                    .iter()
                    .all(|parameter| parameter.ty.valid()));
                if bits == 64 && prototype.family == ApiFamily::Win64 {
                    assert_eq!(signature.convention, CallingConvention::Win64);
                }
                if bits == 32 {
                    assert_eq!(signature.convention, CallingConvention::Cdecl);
                }
            }
        }
    }

    #[test]
    fn stack_arguments_follow_win64_shadow_space_and_sysv_red_zone_rules() {
        let win64 =
            instantiate(lookup("CreateFileA").unwrap(), CallingConvention::Win64, 64).unwrap();
        assert_eq!(win64.parameters[3].location.display(), "r9");
        assert_eq!(win64.parameters[4].location.display(), "stack+0x28");
        assert_eq!(win64.parameters[6].location.display(), "stack+0x38");
        let sysv = instantiate(lookup("memcpy").unwrap(), CallingConvention::SysV64, 64).unwrap();
        assert_eq!(sysv.parameters[0].location.display(), "rdi");
        assert_eq!(sysv.parameters[2].location.display(), "rdx");
        let cdecl = instantiate(lookup("memcpy").unwrap(), CallingConvention::Cdecl, 32).unwrap();
        assert_eq!(cdecl.parameters[0].location.display(), "stack+0x4");
        assert_eq!(cdecl.parameters[1].location.display(), "stack+0x8");
    }
}
