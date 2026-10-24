//! Owned-fixture adapter: no inspected native executable is launched. Independent
//! oracles consume the returned mappings, registers and reconstructed-AST results.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::Path,
    time::Instant,
};
use ura_core::{
    binary,
    decomp::{self, source::evaluate},
    ir::Address,
    processor::Processor,
    symbolic::{self, Options},
};

fn request(value: Value) -> Result<Value, String> {
    let path = Path::new(value["path"].as_str().ok_or("path required")?);
    let binary = if let Some(processor) = value["rawProcessor"].as_str() {
        binary::analyze_raw_processor_path(
            path,
            Some(0x1000),
            Processor::parse(processor).ok_or("unknown processor")?,
        )
        .map_err(|e| e.to_string())?
    } else {
        binary::analyze_path(path).map_err(|e| e.to_string())?
    };
    let processor = Processor::for_analysis(binary.analysis())?;
    let address = if let Some(address) = value["function"].as_str() {
        ura_core::parse_address(address).map_err(|e| e.to_string())?
    } else {
        let symbol = value["symbol"].as_str().ok_or("symbol/function required")?;
        binary
            .analysis()
            .symbols
            .iter()
            .find(|s| s.name == symbol)
            .and_then(|s| s.address)
            .or_else(|| {
                binary
                    .analysis()
                    .exports
                    .iter()
                    .find(|s| s.name == symbol)
                    .map(|s| s.address)
            })
            .ok_or("fixture symbol absent")?
    } & if processor == Processor::Thumb {
        !1
    } else {
        u64::MAX
    };
    let analysis = ura_core::analyze_functions(&binary, &Default::default(), &());
    let mut options: Options = if value["options"].is_null() {
        Options::default()
    } else {
        serde_json::from_value(value["options"].clone()).map_err(|e| e.to_string())?
    };
    // This is an explicit fixture-entry model, not a hidden solver assumption.
    let stack = processor.stack();
    options
        .concrete_inputs
        .entry(stack.into())
        .or_insert(Address(0x7000_0ff0));
    if matches!(processor, Processor::X86 | Processor::X86_64) {
        for i in 0..8 {
            options
                .memory_bytes
                .entry(Address(0x7000_0ff0 + i))
                .or_insert(0);
        }
    }
    let start = Instant::now();
    let backend: &dyn symbolic::solver::Backend = if value["backend"] == "direct" {
        &symbolic::solver::DirectZ3
    } else {
        &symbolic::solver::IsolatedZ3
    };
    let result = symbolic::deobfuscate(
        &binary,
        &analysis,
        address,
        &decomp::DecompContext::new(u16::from(processor.bits())),
        &options,
        backend,
        &(),
    )?;
    let elapsed = start.elapsed().as_micros();
    let mut executions = Vec::new();
    if let Some(cases) = value["cases"].as_array() {
        if cases.len() > 512 {
            return Err("fixture case bound".into());
        }
        for case in cases {
            let mut registers: BTreeMap<String, u64> = result
                .derived_ir
                .variables
                .iter()
                .filter(|v| {
                    matches!(
                        v.kind,
                        ura_core::ir::VariableKind::Register | ura_core::ir::VariableKind::Flag
                    )
                })
                .filter_map(|v| v.ty.width().map(|_| (v.name.clone(), 0)))
                .collect();
            registers.insert(stack.into(), 0x7000_0ff0);
            for (name, val) in case["registers"]
                .as_object()
                .ok_or("case registers required")?
            {
                registers.insert(name.clone(), val.as_u64().ok_or("u64 register required")?);
            }
            let mut memory: BTreeMap<u64, u8> =
                (0x7000_0000..0x7000_1000).map(|a| (a, 0)).collect();
            for (a, b) in &options.memory_bytes {
                memory.insert(a.0, *b);
            }
            let mut outputs = Vec::new();
            for source in [&result.original.pseudocode, &result.simplified.pseudocode] {
                let mut machine = evaluate::State::default();
                machine.registers = registers.clone();
                machine.memory = memory.clone();
                let exit = match machine.run(&source.ast, 100_000) {
                    Ok(evaluate::Exit::Return {
                        result,
                        destination,
                    }) => {
                        json!({"kind":"return","result":result.map(Address),"destination":destination.map(Address)})
                    }
                    Ok(other) => json!({"kind":"boundary","detail":format!("{other:?}")}),
                    Err(error) => json!({"kind":"error","detail":error}),
                };
                let changes = machine
                    .memory
                    .into_iter()
                    .filter(|(a, b)| memory.get(a) != Some(b))
                    .map(|(a, b)| (Address(a), b))
                    .collect::<Vec<_>>();
                outputs.push(json!({"exit":exit,"changedBytes":changes}));
            }
            let original_ir = ura_core::ir::lift_function(&binary, &analysis, address, &())?;
            let mut ir_outputs = Vec::new();
            for ir in [&original_ir, &result.derived_ir] {
                let mut machine = ura_core::ir::evaluate::Machine {
                    values: registers.clone(),
                    memory: memory.clone(),
                    trace: Vec::new(),
                };
                let exit = match machine.run(ir, 10000) {
                    Ok(destination) => {
                        json!({"kind":"return","destination":destination.map(Address)})
                    }
                    Err(error) => json!({"kind":"error","detail":error}),
                };
                let changes = machine
                    .memory
                    .into_iter()
                    .filter(|(a, b)| memory.get(a) != Some(b))
                    .map(|(a, b)| (Address(a), b))
                    .collect::<Vec<_>>();
                let registers = machine
                    .values
                    .into_iter()
                    .map(|(name, value)| (name, Address(value)))
                    .collect::<BTreeMap<_, _>>();
                ir_outputs.push(json!({"exit":exit,"registers":registers,"changedBytes":changes}));
            }
            executions.push(json!({"initialRegisters":registers,"stackBase":Address(0x7000_0000),"stackSize":4096,"original":outputs[0],"simplified":outputs[1],"irOriginal":ir_outputs[0],"irSimplified":ir_outputs[1]}));
        }
    }
    Ok(
        json!({"processor":processor,"function":Address(address),"effectiveSha256":ura_core::sha256_hex(binary.bytes()),
        "mappings":ura_core::dynamic::image::Image::from_binary(&binary).map_err(|e|e.to_string())?.config(address,Default::default()).map_err(|e|e.to_string())?.mappings,
        "elapsedUs":elapsed,"report":result.report,"valueSets":result.value_sets,
        "original":{"lines":result.original.pseudocode.lines.len(),"unresolved":result.original.pseudocode.unresolved,"text":result.original.pseudocode.text()},
        "simplified":{"lines":result.simplified.pseudocode.lines.len(),"unresolved":result.simplified.pseudocode.unresolved,"text":result.simplified.pseudocode.text()},
        "executions":executions}),
    )
}
fn main() {
    if symbolic::solver::worker_entry() {
        return;
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        match std::io::Read::take(&mut input, 65537).read_until(b'\n', &mut bytes) {
            Ok(0) => break,
            Ok(_) if bytes.len() <= 65536 => {}
            _ => break,
        }
        let result = serde_json::from_slice(&bytes)
            .map_err(|e| e.to_string())
            .and_then(request);
        let response = result.unwrap_or_else(|error| json!({"error":error}));
        if writeln!(output, "{response}")
            .and_then(|_| output.flush())
            .is_err()
        {
            break;
        }
    }
}
