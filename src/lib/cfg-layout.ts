import type { CfgBlock, CfgEdge } from "./types";

const NODE_WIDTH = 280;
const NODE_HEADER = 28;
const LINE_HEIGHT = 18;
const NODE_PADDING = 7;
const COLUMN_GAP = 64;
const ROW_GAP = 26;
const MARGIN = 32;

export interface CfgNodeLayout {
  block: CfgBlock;
  x: number;
  y: number;
  width: number;
  height: number;
  depth: number;
}

export interface CfgEdgeLayout {
  edge: CfgEdge;
  from: CfgNodeLayout;
  to: CfgNodeLayout;
  path: string;
  backEdge: boolean;
  selfLoop: boolean;
}

export interface CfgLayout {
  nodes: CfgNodeLayout[];
  edges: CfgEdgeLayout[];
  width: number;
  height: number;
  positions: Map<string, CfgNodeLayout>;
}

function compareAddress(left: string, right: string): number {
  try {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1 : a > b ? 1 : 0;
  } catch {
    return left.localeCompare(right);
  }
}

function blockHeight(block: CfgBlock): number {
  return (
    NODE_HEADER +
    NODE_PADDING * 2 +
    block.lines.length * LINE_HEIGHT +
    (block.omittedInstructions > 0 ? LINE_HEIGHT : 0)
  );
}

function edgePath(
  source: CfgNodeLayout,
  target: CfgNodeLayout,
  backEdge: boolean,
): { path: string; selfLoop: boolean } {
  const sx = source.x + source.width;
  const sy = source.y + source.height / 2;
  const tx = target.x;
  const ty = target.y + target.height / 2;

  if (source.block.address === target.block.address) {
    const x = source.x + source.width / 2;
    const y = source.y;
    return {
      path: `M ${x} ${y} C ${x + 74} ${y - 46}, ${x + 96} ${sy - 6}, ${sx} ${sy - 8}`,
      selfLoop: true,
    };
  }

  const curve = Math.max(48, Math.min(180, Math.abs(tx - sx) * 0.45));
  if (!backEdge) {
    return {
      path: `M ${sx} ${sy} C ${sx + curve} ${sy}, ${tx - curve} ${ty}, ${tx} ${ty}`,
      selfLoop: false,
    };
  }
  return {
    path: `M ${sx} ${sy} C ${sx + curve + 60} ${sy + 26}, ${tx - curve - 60} ${ty - 26}, ${tx} ${ty}`,
    selfLoop: false,
  };
}

export function layoutCfg(blocks: CfgBlock[]): CfgLayout {
  if (blocks.length === 0) {
    return {
      nodes: [],
      edges: [],
      width: 0,
      height: 0,
      positions: new Map(),
    };
  }

  const byAddress = new Map<string, CfgBlock>();
  for (const block of blocks) byAddress.set(block.address, block);

  const depth = new Map<string, number>();
  const queue: string[] = [];
  const entry = blocks[0].address;
  depth.set(entry, 0);
  queue.push(entry);
  while (queue.length > 0) {
    const address = queue.shift() as string;
    const block = byAddress.get(address);
    if (!block) continue;
    const nextDepth = (depth.get(address) ?? 0) + 1;
    for (const edge of block.edges) {
      if (!byAddress.has(edge.target) || depth.has(edge.target)) continue;
      depth.set(edge.target, nextDepth);
      queue.push(edge.target);
    }
  }

  let maxDepth = 0;
  for (const value of depth.values()) maxDepth = Math.max(maxDepth, value);
  for (const block of blocks) {
    if (!depth.has(block.address)) {
      maxDepth += 1;
      depth.set(block.address, maxDepth);
    }
  }

  const columns = new Map<number, CfgBlock[]>();
  for (const block of blocks) {
    const column = depth.get(block.address) ?? 0;
    const list = columns.get(column) ?? [];
    list.push(block);
    columns.set(column, list);
  }
  for (const list of columns.values()) {
    list.sort((left, right) => compareAddress(left.address, right.address));
  }

  const nodes: CfgNodeLayout[] = [];
  const positions = new Map<string, CfgNodeLayout>();
  let height = 0;
  const sortedColumns = [...columns.keys()].sort((a, b) => a - b);
  for (const column of sortedColumns) {
    const list = columns.get(column) ?? [];
    let y = MARGIN;
    for (const block of list) {
      const node: CfgNodeLayout = {
        block,
        x: MARGIN + column * (NODE_WIDTH + COLUMN_GAP),
        y,
        width: NODE_WIDTH,
        height: blockHeight(block),
        depth: column,
      };
      nodes.push(node);
      positions.set(block.address, node);
      y += node.height + ROW_GAP;
    }
    height = Math.max(height, y - ROW_GAP);
  }

  const edges: CfgEdgeLayout[] = [];
  const seen = new Set<string>();
  for (const node of nodes) {
    for (const edge of node.block.edges) {
      const target = positions.get(edge.target);
      if (!target) continue;
      const key = `${node.block.address}->${edge.target}:${edge.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const backEdge =
        target.block.address === node.block.address ||
        target.depth <= node.depth;
      const { path, selfLoop } = edgePath(node, target, backEdge);
      edges.push({ edge, from: node, to: target, path, backEdge, selfLoop });
    }
  }

  const columnCount = sortedColumns.length;
  const width =
    MARGIN * 2 + columnCount * NODE_WIDTH + (columnCount - 1) * COLUMN_GAP;

  return {
    nodes,
    edges,
    width: Math.max(width, MARGIN * 2),
    height: Math.max(height + MARGIN, MARGIN * 2),
    positions,
  };
}
