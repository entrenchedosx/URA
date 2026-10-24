//! Bounded, topologically ordered fixed-width expressions. Memory is one
//! persistent byte array, so potentially aliasing stores cannot be forgotten.
use crate::ir::{self, Address, Constant, Operation, Type};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Id = usize;
pub const HARD_NODES: usize = 40_000;
pub const HARD_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "width", rename_all = "camelCase")]
pub enum Sort {
    Bits(u16),
    Memory(u16),
}
impl Sort {
    pub fn from_ir(ty: Type, address_width: u16) -> Self {
        match ty {
            Type::Memory => Self::Memory(address_width),
            Type::Bits(w) | Type::Address(w) => Self::Bits(w),
        }
    }
    pub fn width(self) -> Option<u16> {
        match self {
            Self::Bits(w) => Some(w),
            Self::Memory(_) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Kind {
    Constant {
        value: Address,
    },
    Symbol {
        name: String,
        poison: Option<String>,
    },
    Pure {
        operation: Operation,
        inputs: Vec<Id>,
    },
    ArithmeticShiftRight {
        value: Id,
        count: Id,
    },
    Concat {
        high: Id,
        low: Id,
    },
    Load {
        memory: Id,
        address: Id,
    },
    Store {
        memory: Id,
        address: Id,
        value: Id,
    },
}
impl Kind {
    pub fn inputs(&self) -> Vec<Id> {
        match self {
            Self::Pure { inputs, .. } => inputs.clone(),
            Self::ArithmeticShiftRight { value, count } => vec![*value, *count],
            Self::Concat { high, low } => vec![*high, *low],
            Self::Load { memory, address } => vec![*memory, *address],
            Self::Store {
                memory,
                address,
                value,
            } => vec![*memory, *address, *value],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub sort: Sort,
    pub kind: Kind,
}

#[derive(Clone, Debug, Serialize)]
pub struct Arena {
    pub nodes: Vec<Node>,
    pub max_nodes: usize,
    pub max_depth: usize,
    #[serde(skip)]
    depths: Vec<usize>,
    #[serde(skip)]
    poisoned: Vec<bool>,
    #[serde(skip)]
    symbols: BTreeMap<String, Id>,
}
impl<'de> Deserialize<'de> for Arena {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            nodes: Vec<Node>,
            max_nodes: usize,
            max_depth: usize,
        }
        let wire = Wire::deserialize(deserializer)?;
        let mut arena = Self {
            nodes: wire.nodes,
            max_nodes: wire.max_nodes,
            max_depth: wire.max_depth,
            depths: Vec::new(),
            poisoned: Vec::new(),
            symbols: BTreeMap::new(),
        };
        arena.rebuild().map_err(serde::de::Error::custom)?;
        Ok(arena)
    }
}
impl Arena {
    pub fn new(max_nodes: usize, max_depth: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_nodes: max_nodes.clamp(16, HARD_NODES),
            max_depth: max_depth.clamp(4, HARD_DEPTH),
            depths: Vec::new(),
            poisoned: Vec::new(),
            symbols: BTreeMap::new(),
        }
    }
    pub fn rebuild(&mut self) -> Result<(), String> {
        if self.max_nodes > HARD_NODES
            || self.max_depth > HARD_DEPTH
            || self.nodes.len() > self.max_nodes
        {
            return Err("symbolic expression budget exceeded".into());
        }
        self.depths.clear();
        self.poisoned.clear();
        self.symbols.clear();
        for id in 0..self.nodes.len() {
            self.validate_node(id)?;
            self.index_node(id)?;
        }
        Ok(())
    }
    fn validate_node(&self, id: Id) -> Result<(), String> {
        let node = &self.nodes[id];
        if matches!(&node.kind, Kind::Pure { inputs, .. } if inputs.len() > 3) {
            return Err("symbolic operand arity budget exceeded".into());
        }
        if !matches!(node.sort, Sort::Bits(1..=64) | Sort::Memory(32 | 64)) {
            return Err("unsupported symbolic sort".into());
        }
        if node.kind.inputs().iter().any(|input| *input >= id) {
            return Err("symbolic expressions must form an ordered acyclic graph".into());
        }
        let sort = |i: Id| self.nodes[i].sort;
        let good = match &node.kind {
            Kind::Constant { value } => node
                .sort
                .width()
                .is_some_and(|w| value.0 & !ir::mask(w) == 0),
            Kind::Symbol { name, poison } => {
                !name.is_empty()
                    && name.len() <= 128
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && poison.as_ref().is_none_or(|p| p.len() <= 512)
            }
            Kind::Pure { operation, inputs } => {
                let args: Vec<_> = inputs
                    .iter()
                    .map(|i| match sort(*i) {
                        Sort::Bits(w) => Type::Bits(w),
                        Sort::Memory(_) => Type::Memory,
                    })
                    .collect();
                !matches!(
                    operation,
                    Operation::Guard { .. }
                        | Operation::Call
                        | Operation::Barrier { .. }
                        | Operation::Unknown { .. }
                        | Operation::Load
                        | Operation::Store
                        | Operation::ToAddress
                        | Operation::ToBits
                ) && node
                    .sort
                    .width()
                    .is_some_and(|w| ir::operation_signature(operation, Some(Type::Bits(w)), &args))
            }
            Kind::ArithmeticShiftRight { value, count } => {
                sort(*value) == node.sort
                    && sort(*count) == node.sort
                    && node.sort.width().is_some()
            }
            Kind::Concat { high, low } => sort(*high)
                .width()
                .zip(sort(*low).width())
                .is_some_and(|(h, l)| node.sort == Sort::Bits(h + l)),
            Kind::Load { memory, address } => {
                matches!(sort(*memory), Sort::Memory(w) if sort(*address) == Sort::Bits(w))
                    && node.sort.width().is_some_and(|w| w % 8 == 0)
            }
            Kind::Store {
                memory,
                address,
                value,
            } => {
                sort(*memory) == node.sort
                    && matches!(node.sort, Sort::Memory(w) if sort(*address) == Sort::Bits(w))
                    && sort(*value).width().is_some_and(|w| w % 8 == 0)
            }
        };
        if !good {
            return Err(format!("invalid symbolic operation at expression {id}"));
        }
        Ok(())
    }
    fn index_node(&mut self, id: Id) -> Result<(), String> {
        let inputs = self.nodes[id].kind.inputs();
        let depth = 1 + inputs.iter().map(|i| self.depths[*i]).max().unwrap_or(0);
        if depth > self.max_depth {
            return Err("symbolic expression depth budget exceeded".into());
        }
        let poison = matches!(
            &self.nodes[id].kind,
            Kind::Symbol {
                poison: Some(_),
                ..
            }
        ) || inputs.iter().any(|i| self.poisoned[*i]);
        if let Kind::Symbol { name, .. } = &self.nodes[id].kind {
            if self.symbols.contains_key(name) {
                return Err("duplicate symbolic input identity".into());
            }
        }
        self.depths.push(depth);
        self.poisoned.push(poison);
        if let Kind::Symbol { name, .. } = &self.nodes[id].kind {
            self.symbols.insert(name.clone(), id);
        }
        Ok(())
    }
    pub fn add(&mut self, sort: Sort, kind: Kind) -> Result<Id, String> {
        if self.depths.len() != self.nodes.len() {
            self.rebuild()?;
        }
        if self.nodes.len() >= self.max_nodes {
            return Err("symbolic expression node budget exceeded".into());
        }
        let id = self.nodes.len();
        self.nodes.push(Node { sort, kind });
        if let Err(error) = self.validate_node(id).and_then(|_| self.index_node(id)) {
            self.nodes.pop();
            return Err(error);
        }
        Ok(id)
    }
    pub fn constant(&mut self, width: u16, value: u64) -> Result<Id, String> {
        self.add(
            Sort::Bits(width),
            Kind::Constant {
                value: Address(value & ir::mask(width)),
            },
        )
    }
    pub fn symbol(&mut self, name: &str, sort: Sort, poison: Option<String>) -> Result<Id, String> {
        if self.depths.len() != self.nodes.len() {
            self.rebuild()?;
        }
        if let Some(id) = self.symbols.get(name) {
            if self.nodes[*id].sort != sort
                || !matches!(&self.nodes[*id].kind, Kind::Symbol { poison: p, .. } if p == &poison)
            {
                return Err("symbol identity conflict".into());
            }
            return Ok(*id);
        }
        self.add(
            sort,
            Kind::Symbol {
                name: name.into(),
                poison,
            },
        )
    }
    pub fn pure(&mut self, op: Operation, width: u16, inputs: Vec<Id>) -> Result<Id, String> {
        if inputs.len() > 3 {
            return Err("symbolic operand arity budget exceeded".into());
        }
        if inputs.iter().any(|i| *i >= self.nodes.len()) {
            return Err("missing symbolic input".into());
        }
        if matches!(
            op,
            Operation::Copy
                | Operation::ZeroExtend
                | Operation::Truncate
                | Operation::ToAddress
                | Operation::ToBits
        ) && inputs.len() == 1
            && self.nodes[inputs[0]].sort == Sort::Bits(width)
        {
            return Ok(inputs[0]);
        }
        let constants: Option<Vec<_>> = inputs
            .iter()
            .map(|i| {
                self.concrete(*i)
                    .map(|v| Constant::bits(self.nodes[*i].sort.width().unwrap_or(0), v))
            })
            .collect();
        if let Some(value) =
            constants.and_then(|args| ir::evaluate::pure(&op, Type::Bits(width), &args))
        {
            return self.constant(width, value.value.0);
        }
        self.add(
            Sort::Bits(width),
            Kind::Pure {
                operation: op,
                inputs,
            },
        )
    }
    pub fn concrete(&self, id: Id) -> Option<u64> {
        match self.nodes.get(id)?.kind {
            Kind::Constant { value } => Some(value.0),
            _ => None,
        }
    }
    pub fn is_poisoned(&self, id: Id) -> bool {
        self.poisoned.get(id).copied().unwrap_or(true)
    }
    pub fn sort(&self, id: Id) -> Result<Sort, String> {
        self.nodes
            .get(id)
            .map(|n| n.sort)
            .ok_or_else(|| "unknown expression".into())
    }
    pub fn condition(&mut self, id: Id, outcome: bool) -> Result<Id, String> {
        if self.sort(id)? != Sort::Bits(1) {
            return Err("branch condition must have width one".into());
        }
        let expected = self.constant(1, u64::from(outcome))?;
        self.pure(Operation::Equal, 1, vec![id, expected])
    }
    pub fn dependencies(&self, root: Id) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut todo = vec![root];
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(node) = self.nodes.get(id) {
                if let Kind::Symbol { name, .. } = &node.kind {
                    names.insert(name.clone());
                }
                todo.extend(node.kind.inputs());
            }
        }
        names.into_iter().collect()
    }
}
