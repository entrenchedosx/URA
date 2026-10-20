use std::collections::{BTreeMap, VecDeque};
use ura_core::{EdgeKind, ProgramAnalysis};

pub const BLOCK_CAP: usize = 240;
pub const LINE_CAP: usize = 32;
pub struct GraphNode {
    pub address: u64,
    pub x: f32,
    pub y: f32,
    pub height: f32,
    pub width: f32,
    pub lines: Vec<u64>,
    pub omitted: usize,
}
pub struct GraphEdge {
    pub source: usize,
    pub target: usize,
    pub kind: EdgeKind,
}
pub struct GraphLayout {
    pub function: u64,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub total_blocks: usize,
}

// Deterministic breadth layers. Cycles are drawn as back edges, never fed back
// into rank assignment, so loop-heavy input cannot cause unbounded iteration.
pub fn layout(analysis: &ProgramAnalysis, address: u64) -> Result<GraphLayout, String> {
    let f = analysis
        .function_containing(address)
        .ok_or("No function at the selection")?;
    let addresses: Vec<_> = f.blocks.iter().copied().take(BLOCK_CAP).collect();
    let index: BTreeMap<_, _> = addresses.iter().enumerate().map(|(i, a)| (*a, i)).collect();
    let mut ranks = vec![None; addresses.len()];
    for root in 0..addresses.len() {
        if ranks[root].is_some() {
            continue;
        }
        ranks[root] = Some(0usize);
        let mut queue = VecDeque::from([root]);
        while let Some(i) = queue.pop_front() {
            let Some(block) = analysis.blocks.get(&addresses[i]) else {
                continue;
            };
            for edge in &block.successors {
                if let Some(&j) = index.get(&edge.target)
                    && ranks[j].is_none()
                {
                    ranks[j] = Some(ranks[i].unwrap() + 1);
                    queue.push_back(j);
                }
            }
        }
    }
    let mut heights = BTreeMap::<usize, f32>::new();
    for (i, address) in addresses.iter().enumerate() {
        let lines = analysis.blocks[address].instructions.len();
        let height = 32.0 + (lines.min(LINE_CAP) + usize::from(lines > LINE_CAP)) as f32 * 16.0;
        heights
            .entry(ranks[i].unwrap_or(0))
            .and_modify(|h| *h = h.max(height))
            .or_insert(height);
    }
    let mut layer_y = BTreeMap::new();
    let mut y = 0.0;
    for (rank, height) in heights {
        layer_y.insert(rank, y);
        y += height + 42.0;
    }
    let widths: Vec<f32> = addresses
        .iter()
        .map(|address| {
            let block = &analysis.blocks[address];
            let chars = block
                .instructions
                .iter()
                .take(LINE_CAP)
                .filter_map(|a| analysis.instructions.get(a))
                .map(|i| 11 + i.operands.chars().count())
                .max()
                .unwrap_or(20);
            (chars as f32 * 6.7 + 20.0).clamp(210.0, 760.0)
        })
        .collect();
    let mut layer_widths = BTreeMap::<usize, f32>::new();
    for (i, width) in widths.iter().enumerate() {
        *layer_widths.entry(ranks[i].unwrap_or(0)).or_default() += width + 36.0;
    }
    let max_width = layer_widths.values().copied().fold(1.0_f32, f32::max);
    let mut layer_x: BTreeMap<usize, f32> = layer_widths
        .iter()
        .map(|(rank, w)| (*rank, (max_width - w) * 0.5))
        .collect();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    // Layer pitch follows displayed block height, retaining space for routed edges.
    for (i, address) in addresses.iter().enumerate() {
        let block = &analysis.blocks[address];
        let rank = ranks[i].unwrap_or(0);
        let x = layer_x.entry(rank).or_default();
        let lines = block
            .instructions
            .iter()
            .copied()
            .take(LINE_CAP)
            .collect::<Vec<_>>();
        let omitted = block.instructions.len().saturating_sub(LINE_CAP);
        nodes.push(GraphNode {
            address: *address,
            x: *x,
            width: widths[i],
            y: layer_y[&rank],
            height: 32.0 + (lines.len() + usize::from(omitted > 0)) as f32 * 16.0,
            lines,
            omitted,
        });
        *x += widths[i] + 36.0;
        for edge in &block.successors {
            if let Some(&target) = index.get(&edge.target) {
                edges.push(GraphEdge {
                    source: i,
                    target,
                    kind: edge.kind,
                });
            }
        }
    }
    Ok(GraphLayout {
        function: f.address,
        nodes,
        edges,
        total_blocks: f.blocks.len(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixture_graph_is_deterministic_and_nonoverlapping() {
        let b =
            ura_core::analyze_path(std::path::Path::new("../../tests/fixtures/ura64.exe")).unwrap();
        let a = ura_core::analyze_functions(&b, &Default::default(), &());
        for f in &a.functions {
            let g = super::layout(&a, f.address).unwrap();
            let h = super::layout(&a, f.address).unwrap();
            assert_eq!(g.nodes.len(), f.blocks.len().min(super::BLOCK_CAP));
            for (n, m) in g.nodes.iter().zip(h.nodes.iter()) {
                assert_eq!((n.x, n.y), (m.x, m.y));
            }
            for (i, n) in g.nodes.iter().enumerate() {
                for m in &g.nodes[i + 1..] {
                    assert!(n.x != m.x || (n.y - m.y).abs() >= n.height.min(m.height));
                }
            }
        }
    }
}
