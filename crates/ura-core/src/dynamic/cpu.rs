//! Deterministic scalar CPU execution. Never invokes host code or APIs.
use super::{
    memory::{Memory, Permissions},
    *,
};
use crate::ir::{self, Constant, CpuFlow, Operand, Operation, VariableKind};
use crate::processor::Processor;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub instructions: u64,
    pub milliseconds: u64,
    pub memory_bytes: usize,
    pub call_depth: usize,
    pub events: usize,
    pub trace_bytes: usize,
    pub snapshots: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            instructions: 100000,
            milliseconds: 1000,
            memory_bytes: 8 * 1024 * 1024,
            call_depth: 64,
            events: 2048,
            trace_bytes: 1024 * 1024,
            snapshots: 2,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1000000).contains(&self.instructions)
            || !(1..=10000).contains(&self.milliseconds)
            || !(65536..=16 * 1024 * 1024).contains(&self.memory_bytes)
            || !(1..=256).contains(&self.call_depth)
            || !(1..=10000).contains(&self.events)
            || !(1024..=4 * 1024 * 1024).contains(&self.trace_bytes)
            || self.snapshots > 4
        {
            return Err(Fault::new(
                "configuration",
                0,
                "emulation resource limit outside supported bounds",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mapping {
    pub base: Address,
    pub bytes: Vec<u8>,
    pub size: usize,
    pub permissions: Permissions,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub bitness: u8,
    pub processor: Option<Processor>,
    pub entry: Address,
    pub registers: BTreeMap<String, Address>,
    pub mappings: Vec<Mapping>,
    pub stack_base: Address,
    pub stack_size: usize,
    pub limits: Limits,
    pub external_returns: BTreeMap<Address, Address>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bitness: 64,
            processor: None,
            entry: Address(0x1000),
            registers: BTreeMap::new(),
            mappings: vec![],
            stack_base: Address(0x70000000),
            stack_size: 65536,
            limits: Limits::default(),
            external_returns: BTreeMap::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub processor: Processor,
    pub flags_value: Address,
    pub flags_known_mask: Address,
    pub flags_scope: &'static str,
    pub mode: &'static str,
    pub bitness: u8,
    pub instruction_pointer: Address,
    pub registers: BTreeMap<String, Option<Address>>,
    pub instructions: u64,
    pub call_depth: usize,
    pub status: String,
    pub stop_reason: String,
    pub fault: Option<Fault>,
    pub allocated_bytes: usize,
    pub retained_events: usize,
    pub dropped_events: u64,
    pub serialized_trace_bytes: usize,
    pub snapshots: usize,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub sequence: u64,
    pub mode: &'static str,
    pub address: Address,
    pub next_address: Address,
    pub bytes: Vec<u8>,
    pub flow: String,
    pub changed_registers: BTreeMap<String, Option<Address>>,
    pub writes: Vec<(Address, Vec<u8>)>,
}
#[derive(Clone)]
struct Checkpoint {
    memory: Memory,
    registers: BTreeMap<String, Option<u64>>,
    ip: u64,
    instructions: u64,
    depth: usize,
}
pub struct Emulator {
    pub memory: Memory,
    processor: Processor,
    pub config: Config,
    registers: BTreeMap<String, Option<u64>>,
    ip: u64,
    count: u64,
    depth: usize,
    status: String,
    reason: String,
    fault: Option<Fault>,
    initial: Checkpoint,
    checkpoints: BTreeMap<u64, Checkpoint>,
    next_checkpoint: u64,
    pub breakpoints: BTreeSet<u64>,
    events: VecDeque<(Event, usize)>,
    sequence: u64,
    dropped: u64,
    trace_bytes: usize,
}
impl Emulator {
    pub fn new(config: Config) -> Result<Self> {
        config.limits.validate()?;
        let processor = config.processor.unwrap_or(if config.bitness == 32 {
            Processor::X86
        } else {
            Processor::X86_64
        });
        if config.bitness != processor.bits() {
            return Err(Fault::new(
                "configuration",
                config.entry.0,
                "processor/bitness mismatch",
            ));
        }
        if config.mappings.len() > 128
            || config.external_returns.len() > 32
            || config.registers.len() > 40
            || !(256..=1024 * 1024).contains(&config.stack_size)
        {
            return Err(Fault::new(
                "configuration",
                config.entry.0,
                "mapping/register/stub/stack limit exceeded",
            ));
        }
        let mut memory = Memory::new(config.bitness, config.limits.memory_bytes)?;
        for m in &config.mappings {
            memory.map(
                m.base.0,
                m.size,
                &m.bytes,
                m.permissions,
                "explicit emulated mapping",
            )?;
        }
        memory.map(
            config.stack_base.0,
            config.stack_size,
            &[],
            Permissions::RW,
            "emulated zero-filled stack",
        )?;
        if !memory.executable(config.entry.0) {
            return Err(Fault::new(
                "entry",
                config.entry.0,
                "entry is not mapped executable memory",
            ));
        }
        let p = if processor.x86() {
            ir::lift_cpu_instruction(&[0x90], config.entry.0, config.bitness)
        } else {
            let nop = match processor {
                Processor::Aarch64 => 0xd503201fu32.to_le_bytes().to_vec(),
                Processor::Riscv32 | Processor::Riscv64 => 0x00000013u32.to_le_bytes().to_vec(),
                Processor::Arm => 0xe320f000u32.to_le_bytes().to_vec(),
                Processor::Thumb => 0xbf00u16.to_le_bytes().to_vec(),
                _ => {
                    return Err(Fault::new(
                        "configuration",
                        config.entry.0,
                        "processor emulation is not implemented",
                    ))
                }
            };
            ir::lift_processor_instruction(&nop, config.entry.0, processor)
        }
        .map_err(|e| Fault::new("configuration", config.entry.0, e))?;
        let mut registers: BTreeMap<_, _> = p
            .variables
            .iter()
            .filter(|v| matches!(v.kind, VariableKind::Register | VariableKind::Flag))
            .map(|v| (v.name.clone(), Some(0)))
            .collect();
        let sp = processor.stack();
        registers.insert(
            sp.into(),
            Some(
                (config.stack_base.0 + config.stack_size as u64
                    - if processor.x86() {
                        u64::from(config.bitness / 8)
                    } else {
                        0
                    })
                    & ir::mask(u16::from(config.bitness)),
            ),
        );
        for (name, value) in &config.registers {
            if name.len() > 32 {
                return Err(Fault::new(
                    "register",
                    config.entry.0,
                    "register name exceeds32 bytes",
                ));
            }
            if config.bitness == 32
                && ["es_base", "cs_base", "ss_base", "ds_base"].contains(&name.as_str())
                && value.0 != 0
            {
                return Err(Fault::new(
                    "configuration",
                    config.entry.0,
                    "x86 emulation supports flat CS/DS/ES/SS only",
                ));
            }
            let dest = registers.get_mut(name).ok_or_else(|| {
                Fault::new(
                    "register",
                    config.entry.0,
                    format!("unknown root register/flag {name}"),
                )
            })?;
            let width = if ["cf", "pf", "af", "zf", "sf", "of", "n", "z", "c", "v"]
                .contains(&name.as_str())
            {
                1
            } else {
                u16::from(config.bitness)
            };
            if value.0 & !ir::mask(width) != 0 {
                return Err(Fault::new(
                    "register",
                    config.entry.0,
                    "initial value exceeds register width",
                ));
            }
            *dest = Some(value.0);
        }
        if processor == Processor::Aarch64 && registers["sp"].is_some_and(|sp| sp % 16 != 0) {
            return Err(Fault::new(
                "configuration",
                config.entry.0,
                "AAPCS64 initial stack must be16-byte aligned",
            ));
        }
        let initial = Checkpoint {
            memory: memory.clone(),
            registers: registers.clone(),
            ip: config.entry.0,
            instructions: 0,
            depth: 0,
        };
        Ok(Self {
            memory,
            processor,
            ip: config.entry.0,
            config,
            registers,
            count: 0,
            depth: 0,
            status: "paused".into(),
            reason: "created".into(),
            fault: None,
            initial,
            checkpoints: BTreeMap::new(),
            next_checkpoint: 1,
            breakpoints: BTreeSet::new(),
            events: VecDeque::new(),
            sequence: 0,
            dropped: 0,
            trace_bytes: 0,
        })
    }
    pub fn state(&self) -> State {
        let (mut flags, mut known) = if self.processor.x86() { (2, 2) } else { (0, 0) };
        let fields = if self.processor.x86() {
            vec![
                ("cf", 0),
                ("pf", 2),
                ("af", 4),
                ("zf", 6),
                ("sf", 7),
                ("of", 11),
            ]
        } else {
            vec![("n", 31), ("z", 30), ("c", 29), ("v", 28)]
        };
        for (name, bit) in fields {
            if let Some(Some(value)) = self.registers.get(name) {
                known |= 1 << bit;
                flags |= value << bit;
            }
        }
        State {
            processor: self.processor,
            flags_value: Address(flags),
            flags_known_mask: Address(known),
            flags_scope: if self.processor.x86() {
                "arithmetic flags CF/PF/AF/ZF/SF/OF; other architectural flags unavailable"
            } else if matches!(self.processor, Processor::Riscv32 | Processor::Riscv64) {
                "RISC-V has no arithmetic flags; CSRs unsupported"
            } else {
                "ARM NZCV only; other PSTATE/CPSR bits unavailable"
            },
            mode: "emulated",
            bitness: self.config.bitness,
            instruction_pointer: Address(self.ip),
            registers: self
                .registers
                .iter()
                .map(|(k, v)| (k.clone(), v.map(Address)))
                .collect(),
            instructions: self.count,
            call_depth: self.depth,
            status: self.status.clone(),
            stop_reason: self.reason.clone(),
            fault: self.fault.clone(),
            allocated_bytes: self.memory.allocated,
            retained_events: self.events.len(),
            dropped_events: self.dropped,
            serialized_trace_bytes: self.trace_bytes,
            snapshots: self.checkpoints.len(),
        }
    }
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            memory: self.memory.clone(),
            registers: self.registers.clone(),
            ip: self.ip,
            instructions: self.count,
            depth: self.depth,
        }
    }
    pub fn save(&mut self) -> Result<u64> {
        if self.checkpoints.len() >= self.config.limits.snapshots {
            return Err(Fault::new(
                "snapshotBudget",
                self.ip,
                "remove a checkpoint before saving another",
            ));
        }
        let id = self.next_checkpoint;
        self.next_checkpoint += 1;
        self.checkpoints.insert(id, self.checkpoint());
        Ok(id)
    }
    pub fn restore(&mut self, id: Option<u64>) -> Result<()> {
        let c = match id {
            Some(id) => self
                .checkpoints
                .get(&id)
                .ok_or_else(|| Fault::new("snapshot", self.ip, "unknown checkpoint"))?,
            None => &self.initial,
        }
        .clone();
        self.memory = c.memory;
        self.registers = c.registers;
        self.ip = c.ip;
        self.count = c.instructions;
        self.depth = c.depth;
        self.status = "paused".into();
        self.reason = "restored".into();
        self.fault = None;
        // A new history starts; old sequence numbers are not silently reinterpreted.
        self.events.clear();
        self.trace_bytes = 0;
        self.dropped = 0;
        Ok(())
    }
    pub fn remove_snapshot(&mut self, id: u64) -> Result<()> {
        self.checkpoints
            .remove(&id)
            .ok_or_else(|| Fault::new("snapshot", self.ip, "unknown checkpoint"))?;
        Ok(())
    }
    pub fn trace(&self, after: u64, limit: usize) -> Result<serde_json::Value> {
        if !(1..=512).contains(&limit) {
            return Err(Fault::new("limit", self.ip, "trace page1..512"));
        }
        Ok(
            serde_json::json!({"format":"ura-emulation-trace","schemaVersion":1,"mode":"emulated","processor":self.processor,"events":self.events.iter().filter(|(e,_)|e.sequence>after).take(limit).map(|(e,_)|e).collect::<Vec<_>>(),"dropped":self.dropped,"registersComplete":false,"memoryComplete":false}),
        )
    }
    pub fn export_trace(&self) -> serde_json::Value {
        serde_json::json!({"format":"ura-emulation-trace","schemaVersion":1,"mode":"emulated","bitness":self.config.bitness,"processor":self.processor,"events":self.events.iter().map(|(e,_)|e).collect::<Vec<_>>(),"dropped":self.dropped,"registersComplete":false,"memoryComplete":false})
    }
    pub fn run(
        &mut self,
        steps: u64,
        until: Option<u64>,
        cancel: &AtomicBool,
        mut publish: impl FnMut(State),
    ) -> State {
        if steps == 0 || steps > 1000000 {
            self.reason = "invalidRunBudget".into();
            return self.state();
        }
        if self.status == "faulted" || self.status == "returned" {
            return self.state();
        }
        let resume_breakpoint = self.reason == "breakpoint";
        let started = Instant::now();
        let mut published = Instant::now();
        self.status = "running".into();
        self.reason = "running".into();
        for n in 0..steps {
            let stop = if cancel.load(Ordering::Acquire) {
                Some("cancelled")
            } else if started.elapsed() >= Duration::from_millis(self.config.limits.milliseconds) {
                Some("durationLimit")
            } else if self.count >= self.config.limits.instructions {
                Some("instructionLimit")
            } else if until == Some(self.ip) {
                Some("runTo")
            } else if self.breakpoints.contains(&self.ip)
                && !(n == 0 && (steps == 1 || resume_breakpoint))
            {
                Some("breakpoint")
            } else {
                None
            };
            if let Some(reason) = stop {
                self.reason = reason.into();
                break;
            }
            if let Err(e) = self.execute_one() {
                self.reason = e.kind.clone();
                self.fault = Some(e);
                self.status = "faulted".into();
                break;
            }
            if self.status == "returned" {
                break;
            }
            if published.elapsed() >= Duration::from_millis(20) {
                publish(self.state());
                published = Instant::now();
            }
        }
        if self.status == "running" {
            self.status = "paused".into();
            if self.reason == "running" {
                self.reason = "runLimit".into();
            }
        }
        let state = self.state();
        publish(state.clone());
        state
    }
    fn execute_one(&mut self) -> Result<()> {
        let bytes = self.memory.fetch(self.ip)?;
        let p = if self.processor.x86() {
            ir::lift_cpu_instruction(&bytes, self.ip, self.config.bitness)
        } else {
            ir::lift_processor_instruction(&bytes, self.ip, self.processor)
        }
        .map_err(|e| Fault::new("unsupported", self.ip, e))?;
        let mut values: Vec<Option<Constant>> = p
            .variables
            .iter()
            .map(|v| {
                self.registers
                    .get(&v.name)
                    .copied()
                    .flatten()
                    .map(|n| Constant {
                        ty: v.ty,
                        value: Address(n),
                    })
            })
            .collect();
        let mut writes: Vec<(u64, Vec<u8>)> = vec![];
        for s in &p.statements {
            let arg = |i: usize| -> Result<Constant> {
                get(s.args[i], &values).ok_or_else(|| {
                    Fault::new(
                        "unknownState",
                        self.ip,
                        "instruction needs an undefined or uncaptured input",
                    )
                })
            };
            let value = match &s.op {
                Operation::Unknown { .. } => None,
                Operation::Guard { reason } => {
                    if arg(0)?.value.0 != 0 {
                        return Err(Fault::new("machineFault", self.ip, reason.clone()));
                    }
                    None
                }
                Operation::Load => {
                    let address = arg(1)?.value.0;
                    let ty = p.variables[s.output.unwrap()].ty;
                    let data = self
                        .memory
                        .read(address, usize::from(ty.width().unwrap() / 8))?;
                    let mut n = 0;
                    for (i, b) in data.iter().enumerate() {
                        n |= u64::from(*b) << (i * 8);
                    }
                    Some(Constant {
                        ty,
                        value: Address(n),
                    })
                }
                Operation::Store => {
                    let address = arg(1)?.value.0;
                    let c = arg(2)?;
                    let bytes =
                        c.value.0.to_le_bytes()[..usize::from(c.ty.width().unwrap() / 8)].to_vec();
                    self.memory.validate_write(address, &bytes)?;
                    writes.push((address, bytes));
                    None
                }
                Operation::Select => {
                    let condition = arg(0)?.value.0;
                    get(s.args[if condition != 0 { 1 } else { 2 }], &values)
                }
                Operation::Barrier { reason } => {
                    return Err(Fault::new("unsupported", self.ip, reason.clone()))
                }
                Operation::Call => {
                    return Err(Fault::new(
                        "unsupported",
                        self.ip,
                        "abstract call cannot execute",
                    ))
                }
                op => {
                    let args = s
                        .args
                        .iter()
                        .map(|a| get(*a, &values))
                        .collect::<Option<Vec<_>>>();
                    args.and_then(|args| {
                        ir::evaluate::pure(op, p.variables[s.output.unwrap()].ty, &args)
                    })
                }
            };
            if let Some(id) = s.output {
                values[id] = value;
            }
        }
        let target = || {
            p.transfer
                .and_then(|a| get(a, &values))
                .map(|c| c.value.0)
                .ok_or_else(|| Fault::new("unknownState", self.ip, "unknown transfer input"))
        };
        let mut next = p.next;
        let mut depth = self.depth;
        let mut flow = format!("{:?}", p.flow);
        let mut returned = false;
        let mut overrides = None;
        match p.flow {
            CpuFlow::Next => {}
            CpuFlow::Branch => {
                if target()? != 0 {
                    next = p.target;
                }
            }
            CpuFlow::Jump => next = target()?,
            CpuFlow::Return => {
                next = target()?;
                if depth == 0 && next == 0 {
                    returned = true;
                } else {
                    depth = depth.saturating_sub(1);
                }
            }
            CpuFlow::Call => {
                let target = target()?;
                if let Some(value) = self.config.external_returns.get(&Address(target)) {
                    overrides = Some(value.0);
                    flow = "AssumedExternalReturn".into();
                } else {
                    if !self.memory.executable(target) {
                        return Err(Fault::new(
                            "externalCall",
                            target,
                            "unmapped/non-executable call target; no host API was invoked",
                        ));
                    }
                    if depth >= self.config.limits.call_depth {
                        return Err(Fault::new(
                            "callDepth",
                            self.ip,
                            "emulated call depth exceeded",
                        ));
                    }
                    if let Some(link) = self.processor.link() {
                        let id =
                            p.variables
                                .iter()
                                .position(|v| v.name == link)
                                .ok_or_else(|| {
                                    Fault::new("unsupported", self.ip, "link register unavailable")
                                })?;
                        values[id] = Some(Constant::bits(
                            u16::from(self.config.bitness),
                            p.next | u64::from(self.processor == Processor::Thumb),
                        ));
                        next = target;
                        depth += 1;
                    } else {
                        let sp = if self.config.bitness == 64 {
                            "rsp"
                        } else {
                            "esp"
                        };
                        let old = self.registers[sp].ok_or_else(|| {
                            Fault::new("unknownState", self.ip, "stack pointer unknown")
                        })?;
                        let width = usize::from(self.config.bitness / 8);
                        let new = old.wrapping_sub(width as u64)
                            & ir::mask(u16::from(self.config.bitness));
                        let bytes = p.next.to_le_bytes()[..width].to_vec();
                        self.memory.validate_write(new, &bytes)?;
                        writes.push((new, bytes));
                        let id = p.variables.iter().position(|v| v.name == sp).unwrap();
                        values[id] = Some(Constant::bits(u16::from(self.config.bitness), new));
                        next = target;
                        depth += 1;
                    }
                }
            }
        }
        let mut registers = self.registers.clone();
        for (id, v) in p.variables.iter().enumerate() {
            if matches!(v.kind, VariableKind::Register | VariableKind::Flag) {
                registers.insert(v.name.clone(), values[id].map(|c| c.value.0));
            }
        }
        if let Some(value) = overrides {
            registers.insert(
                self.processor.result().into(),
                Some(value & ir::mask(u16::from(self.config.bitness))),
            );
        }
        if overrides.is_some() {
            if let Some(lr) = self.processor.link() {
                registers.insert(
                    lr.into(),
                    Some(p.next | u64::from(self.processor == Processor::Thumb)),
                );
            }
        }
        let changed = registers
            .iter()
            .filter(|(k, v)| self.registers.get(*k) != Some(*v))
            .map(|(k, v)| (k.clone(), v.map(Address)))
            .collect();
        // All reads, guards and write permissions succeeded before any state commits.
        for (a, b) in &writes {
            self.memory.write(*a, b)?;
        }
        self.registers = registers;
        self.depth = depth;
        self.count += 1;
        let old = self.ip;
        self.ip = next & ir::mask(u16::from(self.config.bitness));
        if returned {
            self.status = "returned".into();
            self.reason = "rootReturn".into();
        }
        self.sequence += 1;
        let event = Event {
            sequence: self.sequence,
            mode: "emulated",
            address: Address(old),
            next_address: Address(self.ip),
            bytes: p.bytes,
            flow,
            changed_registers: changed,
            writes: writes.into_iter().map(|(a, b)| (Address(a), b)).collect(),
        };
        let size = serde_json::to_vec(&event).unwrap().len();
        if size > self.config.limits.trace_bytes {
            self.dropped += 1;
        } else {
            while self.events.len() >= self.config.limits.events
                || self.trace_bytes + size > self.config.limits.trace_bytes
            {
                let (_, n) = self.events.pop_front().unwrap();
                self.trace_bytes -= n;
                self.dropped += 1;
            }
            self.trace_bytes += size;
            self.events.push_back((event, size));
        }
        Ok(())
    }
}
fn get(a: Operand, values: &[Option<Constant>]) -> Option<Constant> {
    match a {
        Operand::Constant(c) => Some(c),
        Operand::Variable(id) => values.get(id).copied().flatten(),
    }
}
