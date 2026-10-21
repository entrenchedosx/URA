//! Post-dominator analysis over verified SSA block graphs.
//!
//! The decompiler only structures control flow that it can prove. A block's
//! post-dominator lies on every finite path from that block to a function exit.
//! Infinite paths require the additional `first_common_on_all_paths` proof;
//! ignoring them would allow a returning arm to hide a diverging arm. The
//! tree is computed with the same Cooper-Harvey-Kennedy iteration used for the
//! SSA dominators, but over the reversed block graph rooted at a synthetic
//! sink that every exit-style terminator feeds into.
use crate::ir::ssa::SsaFunction;
use crate::ir::FlowKind;
use crate::AnalysisControl;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Synthetic root of the reversed graph. Never appears in the reported tree.
pub const SINK: u64 = u64::MAX;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostDominators {
    pub entry: u64,
    /// Immediate post-dominator per assigned block. Exit-style blocks have no
    /// entry (their only post-dominator is the synthetic sink).
    pub immediate: BTreeMap<u64, u64>,
    pub children: BTreeMap<u64, Vec<u64>>,
    /// Reachable blocks whose known successors end the CFG (return, indirect,
    /// unresolved or no known successor). These are the sink edges.
    pub exits: BTreeSet<u64>,
    /// Blocks present in the graph but unreachable from the entry.
    pub unreachable: Vec<u64>,
}

/// Successor edges for one block graph keyed by block address. The map holds
/// reachable and unreachable blocks; empty vectors are exit-style blocks.
/// External destinations are retained, so partial exits cannot disappear.
pub fn graph_for(ssa: &SsaFunction) -> BTreeMap<u64, Vec<u64>> {
    let mut successors = BTreeMap::new();
    for block in &ssa.blocks {
        let taken = match block.terminator.flow.kind {
            FlowKind::Return => Vec::new(),
            _ => block
                .terminator
                .flow
                .successors
                .iter()
                .chain(&block.terminator.flow.exits)
                .map(|address| address.0)
                .collect(),
        };
        let mut taken = taken;
        if matches!(
            block.terminator.flow.kind,
            FlowKind::Indirect | FlowKind::Unresolved
        ) {
            taken.push(SINK);
        }
        successors.insert(block.address.0, taken);
    }
    successors
}

pub fn build(ssa: &SsaFunction) -> Result<PostDominators, String> {
    build_with_control(ssa, &())
}

pub fn build_with_control(
    ssa: &SsaFunction,
    control: &dyn AnalysisControl,
) -> Result<PostDominators, String> {
    over_graph_with_control(ssa.entry.0, &graph_for(ssa), control)
}

pub fn over_graph(
    entry: u64,
    successors: &BTreeMap<u64, Vec<u64>>,
) -> Result<PostDominators, String> {
    over_graph_with_control(entry, successors, &())
}

/// Compute the post-dominator tree for an arbitrary block graph. Every
/// reachable block without known successors is treated as a function exit and
/// feeds the synthetic sink.
pub fn over_graph_with_control(
    entry: u64,
    successors: &BTreeMap<u64, Vec<u64>>,
    control: &dyn AnalysisControl,
) -> Result<PostDominators, String> {
    if control.is_cancelled() {
        return Err("post-dominator analysis cancelled".into());
    }
    if successors.len() > crate::ir::MAX_IR_BLOCKS
        || successors.values().map(Vec::len).sum::<usize>() > crate::ir::MAX_IR_EDGES
    {
        return Err("post-dominator graph exceeds block or edge budget".into());
    }
    if successors.contains_key(&SINK) {
        return Err("post-dominator synthetic sink collides with a block address".into());
    }
    if !successors.contains_key(&entry) {
        return Err("post-dominator entry is not present in the block graph".into());
    }
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::from([entry]);
    while let Some(current) = queue.pop_front() {
        if control.is_cancelled() {
            return Err("post-dominator analysis cancelled".into());
        }
        if !reachable.insert(current) {
            continue;
        }
        for successor in successors
            .get(&current)
            .map(|edges| edges.iter())
            .unwrap_or_default()
        {
            if successors.contains_key(successor) && !reachable.contains(successor) {
                queue.push_back(*successor);
            }
        }
    }
    let exits: BTreeSet<u64> = reachable
        .iter()
        .copied()
        .filter(|block| {
            successors
                .get(block)
                .map(|edges| edges.is_empty())
                .unwrap_or(true)
        })
        .collect();
    let unreachable: Vec<u64> = successors
        .keys()
        .copied()
        .filter(|block| !reachable.contains(block))
        .collect();
    // Internal forward edges only, grouped by target for reversed traversal.
    let mut reversed: BTreeMap<u64, Vec<u64>> =
        reachable.iter().map(|block| (*block, Vec::new())).collect();
    for block in &reachable {
        for successor in successors
            .get(block)
            .map(|edges| edges.iter())
            .unwrap_or_default()
        {
            if reachable.contains(successor) {
                reversed.entry(*successor).or_default().push(*block);
            }
        }
    }
    // A block whose terminator also leaves the analyzed function (unknown
    // target) is a partial exit: it feeds the sink in addition to its known
    // successors, so no internal post-dominator can be proven for it.
    let partial_exits: BTreeSet<u64> = reachable
        .iter()
        .copied()
        .filter(|block| {
            successors
                .get(block)
                .map(|edges| edges.iter().any(|target| !successors.contains_key(target)))
                .unwrap_or(false)
        })
        .collect();
    let sink_roots: BTreeSet<u64> = exits.union(&partial_exits).copied().collect();
    // Reverse-postorder over the reversed graph, rooted at the sink.
    let mut postorder = Vec::new();
    let mut seen = BTreeSet::new();
    let mut todo = vec![(SINK, false)];
    while let Some((block, finish)) = todo.pop() {
        if control.is_cancelled() {
            return Err("post-dominator analysis cancelled".into());
        }
        if finish {
            postorder.push(block);
            continue;
        }
        if !seen.insert(block) {
            continue;
        }
        todo.push((block, true));
        let next: Vec<u64> = if block == SINK {
            sink_roots.iter().copied().collect()
        } else {
            reversed.get(&block).cloned().unwrap_or_default()
        };
        for successor in next.iter().rev() {
            if !seen.contains(successor) {
                todo.push((*successor, false));
            }
        }
    }
    postorder.reverse();
    let order: BTreeMap<u64, usize> = postorder
        .iter()
        .enumerate()
        .map(|(rank, block)| (*block, rank))
        .collect();
    // Cooper-Harvey-Kennedy over the reversed graph. For a block n, the edges
    // entering it in the reversed graph are its forward successors.
    let successor_edges = |block: u64| -> Vec<u64> {
        successors
            .get(&block)
            .map(|edges| {
                edges
                    .iter()
                    .copied()
                    .filter(|successor| reachable.contains(successor))
                    .collect()
            })
            .unwrap_or_default()
    };
    let intersect = |mut a: u64, mut b: u64, parents: &BTreeMap<u64, u64>| -> u64 {
        while a != b {
            while order.get(&a).copied().unwrap_or(usize::MAX)
                > order.get(&b).copied().unwrap_or(usize::MAX)
            {
                a = parents[&a];
            }
            while order.get(&b).copied().unwrap_or(usize::MAX)
                > order.get(&a).copied().unwrap_or(usize::MAX)
            {
                b = parents[&b];
            }
        }
        a
    };
    let mut idom: BTreeMap<u64, u64> = BTreeMap::from([(SINK, SINK)]);
    let mut changed = true;
    let mut rounds = 0;
    let budget = postorder.len() + 2;
    while changed {
        if control.is_cancelled() {
            return Err("post-dominator analysis cancelled".into());
        }
        changed = false;
        rounds += 1;
        if rounds > budget {
            return Err("post-dominator convergence budget exceeded".into());
        }
        for block in postorder.iter().skip(1) {
            let block = *block;
            if block == SINK {
                continue;
            }
            let outgoing = successor_edges(block);
            if outgoing.is_empty() {
                if sink_roots.contains(&block) && idom.get(&block).copied() != Some(SINK) {
                    idom.insert(block, SINK);
                    changed = true;
                }
                continue;
            }
            let mut incoming: Vec<u64> = outgoing
                .iter()
                .copied()
                .filter(|successor| idom.contains_key(successor))
                .collect();
            if sink_roots.contains(&block) {
                // Partial exit: the sink competes with the known successors.
                incoming.push(SINK);
            }
            let Some(first) = incoming.first().copied() else {
                continue;
            };
            let mut parent = first;
            for successor in incoming.iter().copied().skip(1) {
                parent = intersect(parent, successor, &idom);
            }
            if idom.get(&block).copied() != Some(parent) {
                idom.insert(block, parent);
                changed = true;
            }
        }
    }
    let mut children: BTreeMap<u64, Vec<u64>> =
        reachable.iter().map(|block| (*block, Vec::new())).collect();
    for (block, parent) in &idom {
        if *block != *parent && *parent != SINK && reachable.contains(block) {
            children.entry(*parent).or_default().push(*block);
        }
    }
    let immediate: BTreeMap<u64, u64> = idom
        .into_iter()
        .filter(|(block, parent)| *block != *parent && *parent != SINK && reachable.contains(block))
        .collect();
    Ok(PostDominators {
        entry,
        immediate,
        children,
        exits,
        unreachable,
    })
}

impl PostDominators {
    /// True when `a` lies on every finite exiting path from `b`. Strict:
    /// a block never post-dominates itself.
    pub fn postdominates(&self, a: u64, b: u64) -> bool {
        if a == b {
            return false;
        }
        let mut current = b;
        while let Some(parent) = self.immediate.get(&current) {
            current = *parent;
            if current == a {
                return true;
            }
        }
        false
    }

    /// Closest block that lies on every path from both `a` and `b` to an
    /// exit. Returns `None` when they only share the synthetic sink, i.e. when
    /// their traces are mutually incomparable inside the CFG.
    pub fn first_common(&self, a: u64, b: u64) -> Option<u64> {
        if a == b {
            return Some(a);
        }
        let mut chain = BTreeSet::new();
        let mut current = a;
        loop {
            chain.insert(current);
            match self.immediate.get(&current) {
                Some(parent) => current = *parent,
                None => break,
            }
        }
        let mut current = b;
        loop {
            if chain.contains(&current) {
                return Some(current);
            }
            match self.immediate.get(&current) {
                Some(parent) => current = *parent,
                None => break,
            }
        }
        None
    }

    /// A join is usable for structuring only when every maximal path from
    /// both arms reaches it, including infinite and unknown/external paths.
    pub fn first_common_on_all_paths(
        &self,
        a: u64,
        b: u64,
        graph: &BTreeMap<u64, Vec<u64>>,
    ) -> Option<u64> {
        let join = self.first_common(a, b)?;
        let reaches = must_reach(join, graph);
        (reaches.contains(&a) && reaches.contains(&b)).then_some(join)
    }
}

/// Least fixed point of blocks whose *every* successor already must reach
/// target. Cycles avoiding target never enter this set. Empty or external
/// successor paths do not count as reaching it. O(V + E) queue operations.
pub fn must_reach(target: u64, graph: &BTreeMap<u64, Vec<u64>>) -> BTreeSet<u64> {
    if !graph.contains_key(&target) {
        return BTreeSet::new();
    }
    let mut reverse: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut remaining = BTreeMap::new();
    for (&block, edges) in graph {
        let unique: BTreeSet<_> = edges.iter().copied().collect();
        remaining.insert(block, unique.len());
        for successor in unique {
            reverse.entry(successor).or_default().push(block);
        }
    }
    let mut proven = BTreeSet::from([target]);
    let mut queue = VecDeque::from([target]);
    while let Some(block) = queue.pop_front() {
        for predecessor in reverse.get(&block).into_iter().flatten() {
            if proven.contains(predecessor) {
                continue;
            }
            let count = remaining.get_mut(predecessor).expect("known predecessor");
            *count -= 1;
            if *count == 0 {
                proven.insert(*predecessor);
                queue.push_back(*predecessor);
            }
        }
    }
    proven
}

#[cfg(test)]
mod tests {
    use super::*;

    fn successors(edges: &[(u64, u64)]) -> BTreeMap<u64, Vec<u64>> {
        let mut map: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (from, to) in edges {
            map.entry(*from).or_default().push(*to);
        }
        for address in edges.iter().map(|(_, to)| *to) {
            map.entry(address).or_default();
        }
        map
    }

    #[test]
    fn diamond_join_is_the_common_post_dominator() {
        let graph = successors(&[(0, 2), (0, 3), (2, 4), (3, 4)]);
        let tree = over_graph(0, &graph).unwrap();
        assert_eq!(tree.first_common(2, 3), Some(4));
        assert_eq!(tree.immediate.get(&0), Some(&4));
        assert_eq!(tree.immediate.get(&2), Some(&4));
        assert_eq!(tree.immediate.get(&3), Some(&4));
        assert_eq!(tree.immediate.get(&4), None);
        assert!(tree.postdominates(4, 0));
        assert!(tree.postdominates(4, 2));
        assert!(!tree.postdominates(2, 3));
    }

    #[test]
    fn two_independent_exits_share_only_the_sink() {
        let graph = successors(&[(0, 2), (0, 3)]);
        let tree = over_graph(0, &graph).unwrap();
        assert_eq!(tree.exits, BTreeSet::from([2, 3]));
        assert_eq!(tree.first_common(2, 3), None);
        assert_eq!(tree.immediate.get(&0), None);
        assert_eq!(tree.immediate.get(&2), None);
    }

    #[test]
    fn loop_exits_are_post_dominators_of_the_body() {
        // 0 -> 1; 1 -> 2 | 3; 2 -> 1 (latch); 3 exits.
        let graph = successors(&[(0, 1), (1, 2), (1, 3), (2, 1)]);
        let tree = over_graph(0, &graph).unwrap();
        assert!(tree.postdominates(3, 1));
        assert!(tree.postdominates(1, 2));
        assert_eq!(tree.first_common(1, 2), Some(1));
        assert_eq!(tree.immediate.get(&2), Some(&1));
        assert_eq!(tree.immediate.get(&1), Some(&3));
    }

    #[test]
    fn nested_loops_keep_inner_blocks_inside_the_inner_loop() {
        // 0 -> 1; 1 -> 2 | 7(exit); 2 -> 3 | 6; 3 -> 4 | 6; 4 -> 5; 5 -> 2;
        // 6 -> 2. The inner body 2..6 has no route back to 1, so those blocks
        // cannot reach an exit and stay unassigned (conservative).
        let graph = successors(&[
            (0, 1),
            (1, 2),
            (1, 7),
            (2, 3),
            (2, 6),
            (3, 4),
            (3, 6),
            (4, 5),
            (6, 2),
            (5, 2),
        ]);
        let tree = over_graph(0, &graph).unwrap();
        assert!(tree.postdominates(7, 1));
        assert_eq!(tree.immediate.get(&1), Some(&7));
        assert_eq!(tree.immediate.get(&2), None);
        assert_eq!(tree.immediate.get(&4), None);
        assert_eq!(tree.first_common(3, 6), None);
    }

    #[test]
    fn blocks_without_exit_paths_have_no_post_dominator() {
        // 0 -> 1; 1 -> 1 (self loop, never exits)
        let graph = successors(&[(0, 1), (1, 1)]);
        let tree = over_graph(0, &graph).unwrap();
        assert_eq!(tree.exits, BTreeSet::from([]));
        assert_eq!(tree.immediate.get(&1), None);
        assert_eq!(tree.first_common(0, 1), None);
    }

    #[test]
    fn unreachable_blocks_are_reported_and_ignored() {
        let graph = successors(&[(0, 2), (2, 0), (7, 8), (8, 7)]);
        let tree = over_graph(0, &graph).unwrap();
        assert_eq!(tree.unreachable, vec![7, 8]);
        assert!(!tree.immediate.contains_key(&7));
        assert!(!tree.immediate.contains_key(&8));
    }

    #[test]
    fn failed_fallthrough_targets_behave_as_partial_exits() {
        // 0 -> 1 internal, 99 external (not in graph). The block is a partial
        // exit, so no internal post-dominator can be proven for it.
        let mut with_external = successors(&[(0, 1)]);
        with_external.entry(0).or_default().push(99);
        let tree = over_graph(0, &with_external).unwrap();
        assert_eq!(tree.immediate.get(&0), None);
        assert_eq!(tree.immediate.get(&1), None);
        assert!(!tree.postdominates(1, 0));
        // A second block without the external edge gets a real postdom tree.
        let clean = over_graph(0, &successors(&[(0, 1)])).unwrap();
        assert_eq!(clean.immediate.get(&1), None);
        assert_eq!(clean.immediate.get(&0), Some(&1));
        assert!(clean.postdominates(1, 0));
    }

    #[test]
    fn cancelled_control_stops_the_analysis() {
        struct Cancel;
        impl crate::AnalysisControl for Cancel {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn report(&self, _: crate::AnalysisProgress) {}
        }
        let graph = successors(&[(0, 1), (1, 0)]);
        let error = over_graph_with_control(0, &graph, &Cancel).unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
    }
}
