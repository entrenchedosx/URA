use std::io::{BufRead, Write};
use ura_service::{dynamic::DynamicService, ErrorView, PathPolicy, ServiceError};
pub fn run(policy: PathPolicy, enabled: bool, writes: bool) -> Result<(), ServiceError> {
    let mut service = DynamicService::new(policy, writes).with_emulation(enabled);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout().lock();
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
                "dynamic command line exceeds 64KiB; session closed".into(),
            ));
        }
        let result = serde_json::from_slice(&line)
            .map_err(|e| ServiceError::InvalidArgument(e.to_string()))
            .and_then(|v| service.rpc(v));
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
