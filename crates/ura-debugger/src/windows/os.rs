use crate::*;
use object::Object;
use serde_json::{json, Value};
use std::{
    ffi::{c_void, OsStr},
    io::Read,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Diagnostics::Debug::*, Memory::*, ProcessStatus::*, Threading::*},
};

pub struct Handle(pub HANDLE);
impl Handle {
    pub fn new(h: HANDLE) -> Result<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            Err(error("handle"))
        } else {
            Ok(Self(h))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            if CloseHandle(self.0) == 0 {
                eprintln!(
                    "URA debugger handle close failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}
pub fn error(op: &str) -> DebugError {
    DebugError::new(
        "windows",
        format!("{op}: {}", std::io::Error::last_os_error()),
    )
}
pub fn check(ok: i32, op: &str) -> Result<()> {
    if ok == 0 {
        Err(error(op))
    } else {
        Ok(())
    }
}
pub fn wide(s: impl AsRef<OsStr>) -> Result<Vec<u16>> {
    let mut v: Vec<u16> = s.as_ref().encode_wide().collect();
    if v.contains(&0) {
        return Err(DebugError::new("invalid_argument", "embedded NUL"));
    }
    v.push(0);
    Ok(v)
}
pub fn duplicate(h: HANDLE) -> Result<Handle> {
    unsafe {
        let mut out = null_mut();
        check(
            DuplicateHandle(
                GetCurrentProcess(),
                h,
                GetCurrentProcess(),
                &mut out,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ),
            "DuplicateHandle",
        )?;
        Handle::new(out)
    }
}
#[repr(align(16))]
pub struct Context(pub CONTEXT);
pub fn context(thread: HANDLE) -> Result<Context> {
    unsafe {
        let mut c = Context(CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64,
            ..Default::default()
        });
        check(GetThreadContext(thread, &mut c.0), "GetThreadContext")?;
        Ok(c)
    }
}
pub fn set_context(thread: HANDLE, c: &Context) -> Result<()> {
    unsafe { check(SetThreadContext(thread, &c.0), "SetThreadContext") }
}
pub fn registers(thread: u32, c: &Context) -> Registers {
    let c = &c.0;
    let values = [
        ("rax", c.Rax),
        ("rbx", c.Rbx),
        ("rcx", c.Rcx),
        ("rdx", c.Rdx),
        ("rsi", c.Rsi),
        ("rdi", c.Rdi),
        ("rbp", c.Rbp),
        ("rsp", c.Rsp),
        ("rip", c.Rip),
        ("r8", c.R8),
        ("r9", c.R9),
        ("r10", c.R10),
        ("r11", c.R11),
        ("r12", c.R12),
        ("r13", c.R13),
        ("r14", c.R14),
        ("r15", c.R15),
        ("eflags", c.EFlags as u64),
        ("cs", c.SegCs as u64),
        ("ss", c.SegSs as u64),
        ("ds", c.SegDs as u64),
        ("es", c.SegEs as u64),
        ("fs", c.SegFs as u64),
        ("gs", c.SegGs as u64),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), hex(v)))
    .collect();
    Registers {
        thread,
        architecture: "windows-x64".into(),
        values,
    }
}
pub fn architecture(process: HANDLE) -> Result<()> {
    unsafe {
        let (mut target, mut host) = (0, 0);
        check(
            IsWow64Process2(process, &mut target, &mut host),
            "IsWow64Process2",
        )?;
        if target != 0 || host != 0x8664 {
            return Err(DebugError::new(
                "unsupported",
                "v0.11 supports native Windows x64 targets; WOW64/ARM contexts are not implemented",
            ));
        }
        Ok(())
    }
}
pub fn process_path(process: HANDLE) -> Result<PathBuf> {
    unsafe {
        let mut buf = vec![0u16; 32768];
        let mut length = buf.len() as u32;
        check(
            QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut length),
            "QueryFullProcessImageNameW",
        )?;
        Ok(PathBuf::from(String::from_utf16_lossy(
            &buf[..length as usize],
        )))
    }
}
pub fn image_path(file: HANDLE) -> Option<String> {
    unsafe {
        if file.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let len = GetFinalPathNameByHandleW(file, buf.as_mut_ptr(), buf.len() as u32, 0);
        (len > 0 && (len as usize) < buf.len())
            .then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}
pub fn debug_file_hash(handle: HANDLE) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{Seek, SeekFrom};
    use std::os::windows::io::FromRawHandle;
    let duplicate = duplicate(handle)?;
    let raw = duplicate.0;
    std::mem::forget(duplicate);
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
    let size = file
        .metadata()
        .map_err(|e| DebugError::new("identity", e.to_string()))?
        .len();
    if size > ura_core::MAX_FILE_SIZE {
        return Err(DebugError::new(
            "limit",
            "mapped image identity exceeds 512MiB",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| DebugError::new("identity", e.to_string()))?;
    let mut digest = Sha256::new();
    let mut read = 0;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| DebugError::new("identity", e.to_string()))?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > size {
            return Err(DebugError::new(
                "identity",
                "mapped image grew during identity read",
            ));
        }
        digest.update(&buffer[..count]);
    }
    if read != size {
        return Err(DebugError::new(
            "identity",
            "mapped image short identity read",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}
pub struct Image {
    pub path: PathBuf,
    pub hash: String,
    pub preferred: u64,
    pub entry: u64,
    pub exports: std::collections::BTreeMap<u64, String>,
    pub pdb_identity: Option<([u8; 16], u32)>,
    pub _file: std::fs::File,
}
pub fn image(path: &Path) -> Result<Image> {
    use std::os::windows::fs::OpenOptionsExt;
    let path = path
        .canonicalize()
        .map_err(|e| DebugError::new("path", e.to_string()))?;
    if path.to_string_lossy().starts_with(r"\\?\UNC\") {
        return Err(DebugError::new(
            "path",
            "remote executable paths are not supported",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .map_err(|e| DebugError::new("path", e.to_string()))?;
    if file
        .metadata()
        .map_err(|e| DebugError::new("path", e.to_string()))?
        .len()
        > ura_core::MAX_FILE_SIZE
    {
        return Err(DebugError::new("limit", "image exceeds 512MiB"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(ura_core::MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| DebugError::new("path", e.to_string()))?;
    let parsed = object::File::parse(bytes.as_slice())
        .map_err(|e| DebugError::new("format", e.to_string()))?;
    if parsed.format() != object::BinaryFormat::Pe
        || parsed.architecture() != object::Architecture::X86_64
    {
        return Err(DebugError::new(
            "unsupported",
            "debug launch requires a native x64 PE executable",
        ));
    }
    let pdb_identity = parsed
        .pdb_info()
        .ok()
        .flatten()
        .map(|p| (p.guid(), p.age()));
    Ok(Image {
        pdb_identity,
        path,
        hash: ura_core::sha256_hex(&bytes),
        preferred: parsed.relative_address_base(),
        entry: parsed.entry(),
        exports: parsed
            .exports()
            .unwrap_or_default()
            .into_iter()
            .take(ura_core::MAX_EXPORTS)
            .filter_map(|e| {
                e.address()
                    .checked_sub(parsed.relative_address_base())
                    .map(|rva| {
                        (
                            rva,
                            String::from_utf8_lossy(e.name())
                                .chars()
                                .take(512)
                                .collect(),
                        )
                    })
            })
            .collect(),
        _file: file,
    })
}
pub fn memory(process: HANDLE, address: u64, length: usize) -> Result<Value> {
    unsafe {
        if length == 0 || length > MAX_MEMORY || address.checked_add(length as u64).is_none() {
            return Err(DebugError::new(
                "limit",
                "memory read must be 1..=65536 bytes without address overflow",
            ));
        }
        let mut region = MEMORY_BASIC_INFORMATION::default();
        if VirtualQueryEx(
            process,
            address as *const c_void,
            &mut region,
            std::mem::size_of_val(&region),
        ) == 0
        {
            return Ok(
                json!({"address":hex(address),"requested":length,"bytes":[],"read":0,"partial":true,"error":error("VirtualQueryEx").message}),
            );
        }
        let end = (region.BaseAddress as u64)
            .checked_add(region.RegionSize as u64)
            .ok_or_else(|| DebugError::new("memory", "region overflow"))?;
        let size = length.min(end.saturating_sub(address) as usize);
        let mut bytes = vec![0u8; size];
        let mut read = 0;
        let ok = ReadProcessMemory(
            process,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            size,
            &mut read,
        );
        let failure = if ok == 0 {
            Some(error("ReadProcessMemory").message)
        } else {
            None
        };
        bytes.truncate(read.min(size));
        Ok(
            json!({"addressSpace":"runtime","address":hex(address),"requested":length,"bytes":bytes,"read":read,"partial":read!=length,"error":failure,"region":{"base":hex(region.BaseAddress as u64),"size":region.RegionSize,"protection":region.Protect,"state":region.State,"type":region.Type}}),
        )
    }
}
pub fn read(process: HANDLE, address: u64, len: usize) -> Result<Vec<u8>> {
    let v = memory(process, address, len)?;
    let bytes = v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    if bytes.len() != len {
        return Err(DebugError::new(
            "memory",
            "requested range is not fully readable within one memory region",
        ));
    }
    Ok(bytes)
}
/// The only runtime write API: a checked debugger-owned single breakpoint byte.
pub fn byte(process: HANDLE, address: u64, expected: u8, replacement: u8) -> Result<()> {
    unsafe {
        if read(process, address, 1)?[0] != expected {
            return Err(DebugError::new(
                "conflict",
                "runtime breakpoint byte changed externally; refusing to overwrite it",
            ));
        }
        let mut old = 0;
        check(
            VirtualProtectEx(
                process,
                address as *const c_void,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut old,
            ),
            "VirtualProtectEx",
        )?;
        let mut written = 0;
        let result = check(
            WriteProcessMemory(
                process,
                address as *const c_void,
                (&replacement as *const u8).cast(),
                1,
                &mut written,
            ),
            "WriteProcessMemory",
        )
        .and_then(|_| {
            if written == 1 {
                Ok(())
            } else {
                Err(DebugError::new("memory", "short breakpoint write"))
            }
        })
        .and_then(|_| {
            check(
                FlushInstructionCache(process, address as *const c_void, 1),
                "FlushInstructionCache",
            )
        });
        #[cfg(test)]
        let injected = BYTE_ROLLBACK_FAILURE.with(|flag| flag.replace(0));
        #[cfg(not(test))]
        let injected = 0;
        if injected == 1 {
            return Err(DebugError::new(
                "critical",
                "injected protection/rollback failure after actual breakpoint write",
            ));
        }
        let mut ignored = 0;
        let protection = check(
            if injected == 2 {
                0
            } else {
                VirtualProtectEx(process, address as *const c_void, 1, old, &mut ignored)
            },
            "restore memory protection",
        );
        if result.is_err() || protection.is_err() {
            let mut rollback_old = 0;
            check(
                if injected == 2 {
                    0
                } else {
                    VirtualProtectEx(
                        process,
                        address as *const c_void,
                        1,
                        PAGE_EXECUTE_READWRITE,
                        &mut rollback_old,
                    )
                },
                "rollback protection",
            )
            .map_err(|e| {
                DebugError::new(
                    "critical",
                    format!("breakpoint rollback protection failed after mutation: {e}"),
                )
            })?;
            let restored = WriteProcessMemory(
                process,
                address as *const c_void,
                (&expected as *const u8).cast(),
                1,
                &mut written,
            );
            let flushed = FlushInstructionCache(process, address as *const c_void, 1);
            let protected =
                VirtualProtectEx(process, address as *const c_void, 1, old, &mut ignored);
            if restored == 0 || written != 1 || flushed == 0 || protected == 0 {
                return Err(DebugError::new(
                    "critical",
                    "breakpoint write rollback failed; target remains under debugger control",
                ));
            }
        }
        result.and(protection)
    }
}
#[cfg(test)]
thread_local! {pub(super) static BYTE_ROLLBACK_FAILURE:std::cell::Cell<u8>=const{std::cell::Cell::new(0)};}
/// Recover uncertain debugger byte/protection ownership, checking both values.
pub fn repair_byte(process: HANDLE, address: u64, original: u8, protection: u32) -> Result<()> {
    unsafe {
        let current = read(process, address, 1)?[0];
        if current != original && current != 0xcc {
            return Err(DebugError::new(
                "conflict",
                "uncertain breakpoint changed externally; owner retained",
            ));
        }
        let mut previous = 0;
        check(
            VirtualProtectEx(
                process,
                address as *const _,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut previous,
            ),
            "repair breakpoint protection",
        )?;
        let mut written = 0;
        let write = check(
            WriteProcessMemory(
                process,
                address as *const _,
                (&original as *const u8).cast(),
                1,
                &mut written,
            ),
            "repair breakpoint byte",
        );
        let flush = check(
            FlushInstructionCache(process, address as *const _, 1),
            "repair instruction cache",
        );
        let restore = check(
            VirtualProtectEx(process, address as *const _, 1, protection, &mut previous),
            "repair original page protection",
        );
        write?;
        flush?;
        restore?;
        if written != 1
            || read(process, address, 1)?[0] != original
            || memory(process, address, 1)?["region"]["protection"].as_u64()
                != Some(protection as u64)
        {
            return Err(DebugError::new(
                "critical",
                "breakpoint byte/protection recovery could not be verified",
            ));
        }
        Ok(())
    }
}
pub fn module(process: HANDLE, base: u64, mut path: Option<String>) -> Module {
    unsafe {
        if path.is_none() {
            let mut buffer = vec![0u16; 32768];
            let length = K32GetModuleFileNameExW(
                process,
                base as HMODULE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            );
            if length > 0 && (length as usize) < buffer.len() {
                path = Some(String::from_utf16_lossy(&buffer[..length as usize]));
            }
        }
        let mut info = MODULEINFO::default();
        let size = if K32GetModuleInformation(
            process,
            base as HMODULE,
            &mut info,
            std::mem::size_of_val(&info) as u32,
        ) != 0
        {
            info.SizeOfImage as u64
        } else {
            0
        };
        Module {
            base: hex(base),
            size,
            path,
            sha256: None,
            preferred_base: None,
            entry_point: None,
        }
    }
}
pub(super) static DBGHELP: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn stack(
    process: HANDLE,
    thread: HANDLE,
    tid: u32,
    modules: &[Module],
    limit: usize,
) -> Result<Value> {
    unsafe {
        if limit == 0 || limit > 64 {
            return Err(DebugError::new("limit", "stack limit must be 1..=64"));
        }
        let _lock = DBGHELP.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = context(thread)?;
        let old = SymGetOptions();
        SymSetOptions(
            SYMOPT_DEFERRED_LOADS
                | SYMOPT_FAIL_CRITICAL_ERRORS
                | SYMOPT_NO_PROMPTS
                | SYMOPT_IGNORE_CVREC
                | SYMOPT_IGNORE_NT_SYMPATH
                | SYMOPT_IGNORE_IMAGEDIR
                | SYMOPT_NO_IMAGE_SEARCH
                | SYMOPT_DISABLE_SYMSRV_AUTODETECT,
        );
        let empty = wide("")?;
        if SymInitializeW(process, empty.as_ptr(), 0) == 0 {
            SymSetOptions(old);
            return Err(error("SymInitializeW"));
        }
        let mut warnings = Vec::new();
        for module in modules {
            if let Some(path) = &module.path {
                let path = wide(path)?;
                let base = ura_core::parse_address(&module.base).unwrap_or(0);
                if SymLoadModuleExW(
                    process,
                    null_mut(),
                    path.as_ptr(),
                    null(),
                    base,
                    module.size as u32,
                    null(),
                    0,
                ) == 0
                {
                    warnings.push(format!(
                        "unwind module metadata unavailable at {}",
                        module.base
                    ));
                }
            }
        }
        let mut frame = STACKFRAME64::default();
        frame.AddrPC.Offset = c.0.Rip;
        frame.AddrStack.Offset = c.0.Rsp;
        frame.AddrFrame.Offset = c.0.Rbp;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrStack.Mode = AddrModeFlat;
        frame.AddrFrame.Mode = AddrModeFlat;
        let mut frames = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut duplicate_first = false;
        for _ in 0..limit * 2 {
            let ip = frame.AddrPC.Offset;
            let sp = frame.AddrStack.Offset;
            if ip == 0 || frames.len() >= limit {
                break;
            }
            if !seen.insert((ip, sp)) {
                if frames.len() == 1 && !duplicate_first {
                    duplicate_first = true;
                } else {
                    warnings.push("unwind cycle detected".into());
                    break;
                }
            } else {
                if let Some(last) = frames.last_mut() {
                    let last: &mut Value = last;
                    let previous = last["stackPointer"]
                        .as_str()
                        .and_then(|v| ura_core::parse_address(v).ok())
                        .unwrap_or(0);
                    if sp < previous {
                        warnings.push("non-advancing unwind stack".into());
                        break;
                    }
                    last["returnAddress"] = json!(hex(ip));
                }
                let module = modules.iter().find(|m| {
                    ura_core::parse_address(&m.base).is_ok_and(|b| ip >= b && ip - b < m.size)
                });
                frames.push(json!({"index":frames.len(),"instructionPointer":hex(ip),"stackPointer":hex(sp),"module":module.and_then(|m|m.path.as_ref()),"symbol":null,"returnAddress":null}));
            }
            if StackWalk64(
                0x8664,
                process,
                thread,
                &mut frame,
                (&mut c.0 as *mut CONTEXT).cast(),
                None,
                Some(SymFunctionTableAccess64),
                Some(SymGetModuleBase64),
                None,
            ) == 0
            {
                warnings.push("unwind ended; completeness is not established".into());
                break;
            }
        }
        let cleanup = check(SymCleanup(process), "SymCleanup");
        SymSetOptions(old);
        cleanup?;
        Ok(
            json!({"thread":tid,"method":"Windows DbgHelp StackWalk64 (local metadata, no PDB/symbol-server lookup)","frames":frames,"complete":false,"warnings":warnings}),
        )
    }
}
pub fn quote(argument: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in argument.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat('\\').take(slashes));
                slashes = 0;
                out.push(ch);
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(slashes * 2));
    out.push('"');
    out
}

/// Resolve only the system debug-break helpers from a loaded ntdll image.
/// Their runtime addresses use this process's observed module base, never ours.
pub fn debug_helpers(module: &Module) -> Option<(u64, u64)> {
    let path = std::path::Path::new(module.path.as_deref()?);
    if !path
        .file_name()?
        .to_string_lossy()
        .eq_ignore_ascii_case("ntdll.dll")
    {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > 64 * 1024 * 1024 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let image = object::File::parse(bytes.as_slice()).ok()?;
    let exports = image.exports().ok()?;
    let base = ura_core::parse_address(&module.base).ok()?;
    let resolve = |name: &[u8]| {
        exports
            .iter()
            .find(|e| e.name() == name)
            .and_then(|e| base.checked_add(e.address().checked_sub(image.relative_address_base())?))
    };
    Some((resolve(b"DbgBreakPoint")?, resolve(b"DbgUiRemoteBreakin")?))
}
