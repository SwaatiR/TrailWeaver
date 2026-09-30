import type { GraphEdge, GraphNode, TimelineEntry } from "../types/api";

/** Horizontal gap between layout columns in canvas pixels. */
export const GRAPH_COLUMN_GAP = 400;
/** Vertical gap between nodes sharing a column in canvas pixels. */
export const GRAPH_ROW_GAP = 230;
/** Baseline vertical center for the deterministic layout. */
const GRAPH_BASE_Y = 190;

const NODE_TYPE_RANK: Record<string, number> = {
  identity: 0,
  credential: 1,
  role: 1,
  resource: 1,
  source_ip: 2,
};

const RELATIONSHIP_LABELS: Record<string, string> = {
  logged_in_from: "Logged in from",
  affected: "Affected",
  granted: "Granted",
  modified: "Modified",
};

export interface GraphPosition {
  x: number;
  y: number;
}

/**
 * Rank a node type for deterministic left-to-right evidence flow:
 * identities first, intermediate entities next, network origins last.
 */
export function nodeTypeRank(nodeType: string): number {
  return NODE_TYPE_RANK[nodeType] ?? 3;
}

/** Present a canonical relationship value in human-readable form. */
export function humanizeRelationship(relationship: string): string {
  const known = RELATIONSHIP_LABELS[relationship];
  if (known) return known;
  return relationship
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/**
 * Compute a deterministic initial layout for the same graph input.
 *
 * Nodes are sorted by (type rank, label, node ID) and grouped into
 * compacted columns so the incident reads left-to-right. No randomness
 * is involved; identical input always yields identical positions.
 */
export function layoutAttackGraph(nodes: GraphNode[]): Map<string, GraphPosition> {
  const ordered = [...nodes].sort((left, right) => {
    const rank = nodeTypeRank(left.node_type) - nodeTypeRank(right.node_type);
    if (rank !== 0) return rank;
    const label = left.label.localeCompare(right.label);
    if (label !== 0) return label;
    return left.node_id.localeCompare(right.node_id);
  });

  const columns = new Map<number, GraphNode[]>();
  for (const node of ordered) {
    const rank = nodeTypeRank(node.node_type);
    const bucket = columns.get(rank) ?? [];
    bucket.push(node);
    columns.set(rank, bucket);
  }

  const rankedColumns = [...columns.keys()].sort((a, b) => a - b);
  const positions = new Map<string, GraphPosition>();
  rankedColumns.forEach((rank, columnIndex) => {
    const bucket = columns.get(rank) ?? [];
    bucket.forEach((node, rowIndex) => {
      positions.set(node.node_id, {
        x: columnIndex * GRAPH_COLUMN_GAP,
        y: GRAPH_BASE_Y + (rowIndex - (bucket.length - 1) / 2) * GRAPH_ROW_GAP,
      });
    });
  });
  return positions;
}

/** An edge whose endpoints both resolve to known graph nodes. */
export interface ResolvedGraphEdge {
  edge: GraphEdge;
  source: GraphNode;
  target: GraphNode;
  selfLoop: boolean;
}

export interface PartitionedGraphEdges {
  resolved: ResolvedGraphEdge[];
  /** Edges referencing a node ID absent from the payload. */
  unresolvable: GraphEdge[];
}

/**
 * Split edges into renderable relationships and defensively omitted ones.
 * Unresolvable references never crash the canvas; they are counted and
 * reported honestly instead.
 */
export function partitionGraphEdges(
  nodes: GraphNode[],
  edges: GraphEdge[],
): PartitionedGraphEdges {
  const byId = new Map(nodes.map((node) => [node.node_id, node]));
  const resolved: ResolvedGraphEdge[] = [];
  const unresolvable: GraphEdge[] = [];
  for (const edge of edges) {
    const source = byId.get(edge.source_node_id);
    const target = byId.get(edge.target_node_id);
    if (!source || !target) {
      unresolvable.push(edge);
      continue;
    }
    resolved.push({
      edge,
      source,
      target,
      selfLoop: edge.source_node_id === edge.target_node_id,
    });
  }
  return { resolved, unresolvable };
}

/** Format an edge timestamp as observed UTC time, without inventing data. */
export function formatObservedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Observed time unavailable";
  return `Observed at ${new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date)}`;
}

/**
 * Connect an edge to its timeline evidence. The incident timeline API
 * does not expose signal IDs, so the join is by exact observed timestamp;
 * the caller must present it as a timestamp match, not an identity join.
 */
export function findTimelineEntryForEdge(
  edge: GraphEdge,
  timeline: TimelineEntry[],
): TimelineEntry | null {
  const edgeTime = new Date(edge.timestamp).valueOf();
  if (Number.isNaN(edgeTime)) return null;
  for (const entry of timeline) {
    if (new Date(entry.timestamp).valueOf() === edgeTime) return entry;
  }
  return null;
}
