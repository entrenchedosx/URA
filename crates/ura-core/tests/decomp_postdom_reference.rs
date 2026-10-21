//! Independent, deliberately slow references over tiny graphs. These do not
//! reuse the production dominator iteration or must-reach transfer function.
use std::collections::{BTreeMap, BTreeSet};
use ura_core::decomp::postdom::{must_reach, over_graph};

fn all_paths_hit(
    node: u64,
    target: u64,
    graph: &BTreeMap<u64, Vec<u64>>,
    active: &mut BTreeSet<u64>,
) -> bool {
    if node == target {
        return true;
    }
    let Some(edges) = graph.get(&node) else {
        return false;
    };
    if edges.is_empty() || !active.insert(node) {
        return false;
    }
    let result = edges
        .iter()
        .all(|next| all_paths_hit(*next, target, graph, active));
    active.remove(&node);
    result
}

fn can_exit(
    node: u64,
    avoid: Option<u64>,
    graph: &BTreeMap<u64, Vec<u64>>,
    seen: &mut BTreeSet<u64>,
) -> bool {
    if Some(node) == avoid || !seen.insert(node) {
        return false;
    }
    let Some(edges) = graph.get(&node) else {
        return true;
    };
    edges.is_empty() || edges.iter().any(|next| can_exit(*next, avoid, graph, seen))
}

#[test]
fn exhaustive_graphs_match_independent_path_references() {
    // All 4,096 three-node graphs, including self loops, multiple exits,
    // irreducible SCCs, unreachable code and edges leaving the known graph.
    for bits in 0..4096u32 {
        let graph: BTreeMap<u64, Vec<u64>> = (0..3)
            .map(|from| {
                (
                    from,
                    (0..4)
                        .filter(|to| bits & (1 << (from * 4 + to)) != 0)
                        .map(|to| if to == 3 { 99 } else { to })
                        .collect(),
                )
            })
            .collect();
        let tree = over_graph(0, &graph).unwrap();
        for target in 0..3 {
            let proven = must_reach(target, &graph);
            for start in 0..3 {
                assert_eq!(
                    proven.contains(&start),
                    all_paths_hit(start, target, &graph, &mut BTreeSet::new()),
                    "all-path graph={graph:?} target={target} start={start}"
                );
                if start != target
                    && !tree.unreachable.contains(&start)
                    && can_exit(start, None, &graph, &mut BTreeSet::new())
                {
                    let expected = !can_exit(start, Some(target), &graph, &mut BTreeSet::new());
                    assert_eq!(
                        tree.postdominates(target, start),
                        expected,
                        "finite-path graph={graph:?} target={target} start={start}"
                    );
                }
                if let Some(join) = tree.first_common_on_all_paths(start, target, &graph) {
                    assert!(all_paths_hit(start, join, &graph, &mut BTreeSet::new()));
                    assert!(all_paths_hit(target, join, &graph, &mut BTreeSet::new()));
                }
            }
        }
    }
}

#[test]
fn diverging_arm_cannot_become_a_structured_join() {
    let graph = BTreeMap::from([(0, vec![1, 2]), (1, vec![3]), (2, vec![2, 3]), (3, vec![])]);
    let tree = over_graph(0, &graph).unwrap();
    assert_eq!(tree.first_common(1, 2), Some(3));
    assert_eq!(tree.first_common_on_all_paths(1, 2, &graph), None);
}

#[test]
fn graph_budget_and_sink_collision_are_explicit_errors() {
    assert!(over_graph(u64::MAX, &BTreeMap::from([(u64::MAX, vec![])]))
        .unwrap_err()
        .contains("collides"));
    let graph = (0..1025).map(|address| (address, vec![])).collect();
    assert!(over_graph(0, &graph).unwrap_err().contains("budget"));
}
