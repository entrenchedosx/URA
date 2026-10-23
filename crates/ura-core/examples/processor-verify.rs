//! Headless test adapter for independent cross-processor oracles.
use serde_json::{json, Value};
use std::{
    io::{self, BufRead},
    path::Path,
    sync::atomic::AtomicBool,
};
use ura_core::{
    binary,
    dynamic::{
        cpu::{Config, Emulator},
        image::Image,
    },
    ir::Address,
    processor::Processor,
};
fn request(v: Value) -> Result<Value, String> {
    if let Some(p) = v["processor"].as_str() {
        let p = Processor::parse(p).ok_or("unknown processor")?;
        let bytes: Vec<u8> =
            serde_json::from_value(v["bytes"].clone()).map_err(|e| e.to_string())?;
        return Ok(
            json!({"decoded":format!("{:?}",ura_core::processor::decode(p,&bytes,0x1000)?)}),
        );
    }
    let path = Path::new(v["path"].as_str().ok_or("path required")?);
    let binary = binary::analyze_path(path).map_err(|e| e.to_string())?;
    let p = Processor::for_analysis(binary.analysis())?;
    let symbol = v["symbol"].as_str().ok_or("symbol required")?;
    let address = binary
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
        .ok_or("symbol missing")?
        & if p == Processor::Thumb { !1 } else { u64::MAX };
    let image = Image::from_binary(&binary).map_err(|e| e.to_string())?;
    let mut cfg = Config::default();
    cfg.limits.instructions = 100000;
    cfg.limits.milliseconds = 10000;
    if let Some(regs) = v["registers"].as_object() {
        for (name, val) in regs {
            cfg.registers.insert(
                name.clone(),
                Address(val.as_u64().ok_or("u64 register required")?),
            );
        }
    }
    let cfg = image.config(address, cfg).map_err(|e| e.to_string())?;
    let mut cpu = Emulator::new(cfg.clone()).map_err(|e| e.to_string())?;
    let source_execution = if v["sourceExecute"] == true {
        use ura_core::decomp::{self, source::evaluate};
        let discovered = ura_core::analyze_functions(&binary, &Default::default(), &());
        let decompiled = decomp::analyze_function(
            &binary,
            &discovered,
            address,
            &decomp::DecompContext::new(u16::from(p.bits())),
            &(),
        )?;
        let mut source = evaluate::State::default();
        source.registers = cpu
            .state()
            .registers
            .into_iter()
            .filter_map(|(n, v)| v.map(|v| (n, v.0)))
            .collect();
        for mapping in &cfg.mappings {
            for offset in 0..mapping.size {
                source.memory.insert(
                    mapping.base.0 + offset as u64,
                    mapping.bytes.get(offset).copied().unwrap_or(0),
                );
            }
        }
        for offset in 0..cfg.stack_size {
            source.memory.insert(cfg.stack_base.0 + offset as u64, 0);
        }
        let original = source.memory.clone();
        let result = match source.run(&decompiled.pseudocode.ast, 100000) {
            Ok(evaluate::Exit::Return {
                result,
                destination,
            }) => json!({"result":result.map(Address),"destination":destination.map(Address)}),
            Ok(other) => json!({"error":format!("unexpected source exit: {other:?}")}),
            Err(e) => json!({"error":e}),
        };
        let changes = source
            .memory
            .into_iter()
            .filter(|(a, b)| original.get(a) != Some(b))
            .map(|(a, b)| (Address(a), b))
            .collect::<Vec<_>>();
        Some(
            json!({"exit":result,"changedBytes":changes,"returnType":decompiled.signature.return_value.ty}),
        )
    } else {
        None
    };
    let state = cpu.run(100000, None, &AtomicBool::new(false), |_| {});
    let analysis = if v["analyze"] == true {
        Some(image.analyze(address).map_err(|e| e.to_string())?)
    } else {
        None
    };
    Ok(
        json!({"processor":p,"entry":Address(address),"config":cfg,"state":state,"sourceExecution":source_execution,"analysis":analysis,"trace":if v["trace"]==true{Some(cpu.export_trace())}else{None}}),
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .and_then(|v| request(v).map_err(|e| e.to_string()));
        println!(
            "{}",
            match result {
                Ok(v) => v,
                Err(e) => json!({"error":e}),
            }
        );
    }
}
