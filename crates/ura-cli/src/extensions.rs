use serde_json::{json, Value};
use std::{
    io::{BufRead, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use ura_extensions::{ExecutionConfig, ExtensionHost};
use ura_service::{Service, ServiceError};
fn error(e: String) -> ServiceError {
    if [
        "disabled",
        "not explicitly trusted",
        "Permission denied",
        "startup grants",
    ]
    .iter()
    .any(|s| e.contains(s))
    {
        ServiceError::ExtensionDenied(e)
    } else {
        ServiceError::InvalidArgument(e)
    }
}
pub fn interactive(
    service: Service,
    config: ExecutionConfig,
    handle: Option<String>,
) -> Result<(), ServiceError> {
    let host = ExtensionHost::new(Arc::new(Mutex::new(service)), config).map_err(error)?;
    let mut output = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    writeln!(output,"{}",json!({"schemaVersion":1,"handle":handle,"ready":true,"security":"trusted Python code is NOT sandboxed"})).and_then(|_|output.flush()).map_err(|e|ServiceError::Io(e.to_string()))?;
    loop {
        let mut line = Vec::new();
        let n = std::io::Read::take(&mut input, 65537)
            .read_until(b'\n', &mut line)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        if line.len() > 65536 {
            return Err(error("Extension request exceeds64KiB".into()));
        }
        let r = serde_json::from_slice::<Value>(&line)
            .map_err(|e| e.to_string())
            .and_then(|mut p| {
                if !p.is_object() {
                    return Err("Extension request must be an object".into());
                }
                if p.get("handle").is_none() {
                    if let Some(h) = &handle {
                        p["handle"] = json!(h);
                    }
                }
                host.rpc(p)
            });
        let v = match r {
            Ok(v) => json!({"schemaVersion":1,"result":v}),
            Err(e) => json!({"schemaVersion":1,"error":{"code":"extension_error","message":e}}),
        };
        writeln!(output, "{v}")
            .and_then(|_| output.flush())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
    }
    Ok(())
}
pub fn script(
    service: Service,
    config: ExecutionConfig,
    handle: String,
    path: &Path,
    args: Vec<String>,
    timeout: u64,
) -> Result<(), ServiceError> {
    let capabilities = config.capabilities.clone();
    let host = ExtensionHost::new(Arc::new(Mutex::new(service)), config).map_err(error)?;
    let session=host.rpc(json!({"operation":"scripts","action":"open","handle":handle,"capabilities":capabilities})).map_err(error)?;
    let job=host.rpc(json!({"operation":"scripts","action":"run","session":session["session"],"path":path,"args":args,"limits":{"timeoutMs":timeout}})).map_err(error)?;
    loop {
        let r = host.job(job["job"].as_str().unwrap()).map_err(error)?;
        if r["state"] != "running" {
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            if r["state"] != "complete" {
                return Err(ServiceError::ExtensionFailure {
                    state: r["state"].as_str().unwrap_or("unknown").into(),
                    message: r["error"].as_str().unwrap_or("Script failed").into(),
                });
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
