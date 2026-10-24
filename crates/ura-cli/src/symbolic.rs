use std::io::{BufRead, Write};
use ura_service::{ErrorView, Service, ServiceError};
pub fn run(mut service: Service, handle: String) -> Result<(), ServiceError> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{}",
        serde_json::json!({"schemaVersion":1,"handle":handle,"ready":true})
    )
    .and_then(|_| output.flush())
    .map_err(|e| ServiceError::Io(e.to_string()))?;
    loop {
        let mut line = Vec::new();
        let read = std::io::Read::take(&mut input, 65537)
            .read_until(b'\n', &mut line)
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        if read == 0 {
            break;
        }
        if line.len() > 65536 {
            return Err(ServiceError::LimitExceeded(
                "symbolic request exceeds 64KiB".into(),
            ));
        }
        let result = serde_json::from_slice::<serde_json::Value>(&line)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))
            .and_then(|mut request| {
                if request["action"] == "start" && request.get("handle").is_none() {
                    request["handle"] = serde_json::Value::String(handle.clone());
                }
                service.symbolic_rpc(request)
            });
        let response = match result {
            Ok(value) => serde_json::json!({"schemaVersion":1,"result":value}),
            Err(error) => serde_json::to_value(ErrorView::new(&error)).unwrap(),
        };
        writeln!(output, "{response}")
            .and_then(|_| output.flush())
            .map_err(|e| ServiceError::Io(e.to_string()))?;
    }
    Ok(())
}
