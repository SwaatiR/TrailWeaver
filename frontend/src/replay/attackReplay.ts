import type {
  GraphEdge,
  GraphResponse,
  TimelineEntry,
} from "../types/api";

export interface AttackReplayStep {
  /** Unique presentation identity, including source order as a defensive fallback. */
  stepId: string;
  signal: TimelineEntry;
  introducedEdgeIds: string[];
  cumulativeEdgeIds: string[];
  /** Endpoints of cumulative edges whose two node references both resolve. */
  cumulativeNodeIds: string[];
}

export interface AttackReplay {
  steps: AttackReplayStep[];
  /** Relationships retained in Full Graph but unavailable for temporal reveal. */
  unlinkedEdgeIds: string[];
}

interface IndexedTimelineEntry {
  entry: TimelineEntry;
  sourceIndex: number;
}

function timestampValue(value: string): number | null {
  const parsed = new Date(value).valueOf();
  return Number.isNaN(parsed) ? null : parsed;
}

function compareIndexedTimelineEntries(
  left: IndexedTimelineEntry,
  right: IndexedTimelineEntry,
): number {
  const leftTime = timestampValue(left.entry.timestamp);
  const rightTime = timestampValue(right.entry.timestamp);

  if (leftTime !== null && rightTime !== null && leftTime !== rightTime) {
    return leftTime - rightTime;
  }
  if (leftTime === null && rightTime !== null) return 1;
  if (leftTime !== null && rightTime === null) return -1;

  const timestampOrder = left.entry.timestamp.localeCompare(right.entry.timestamp);
  if (timestampOrder !== 0) return timestampOrder;
  const signalOrder = left.entry.signal_id.localeCompare(right.entry.signal_id);
  if (signalOrder !== 0) return signalOrder;
  return left.sourceIndex - right.sourceIndex;
}

/**
 * Return timeline observations in deterministic replay order.
 *
 * Valid timestamps sort ascending. Equal (or equally invalid) timestamps use
 * stable signal identity, then the API's source order only as a final fallback
 * for malformed duplicate identities.
 */
export function orderTimelineEntries(
  timeline: TimelineEntry[],
): TimelineEntry[] {
  return timeline
    .map((entry, sourceIndex) => ({ entry, sourceIndex }))
    .sort(compareIndexedTimelineEntries)
    .map(({ entry }) => entry);
}

function compareEdges(left: GraphEdge, right: GraphEdge): number {
  const leftTime = timestampValue(left.timestamp);
  const rightTime = timestampValue(right.timestamp);
  if (leftTime !== null && rightTime !== null && leftTime !== rightTime) {
    return leftTime - rightTime;
  }
  if (leftTime === null && rightTime !== null) return 1;
  if (leftTime !== null && rightTime === null) return -1;
  const timestampOrder = left.timestamp.localeCompare(right.timestamp);
  if (timestampOrder !== 0) return timestampOrder;
  return left.edge_id.localeCompare(right.edge_id);
}

/**
 * Derive cumulative presentation state from existing incident evidence.
 *
 * This function performs no security analysis. A timeline signal may reveal
 * zero, one, or many graph relationships. Edges without a matching timeline
 * signal remain available to Full Graph, but are never guessed into replay.
 */
export function buildAttackReplay(
  timeline: TimelineEntry[],
  graph: GraphResponse,
): AttackReplay {
  const indexedTimeline = timeline
    .map((entry, sourceIndex) => ({ entry, sourceIndex }))
    .sort(compareIndexedTimelineEntries);
  const timelineSignalIds = new Set(
    indexedTimeline.map(({ entry }) => entry.signal_id),
  );
  const knownNodeIds = new Set(graph.nodes.map((node) => node.node_id));
  // Graph actor metadata is explicit domain context (not a guessed node
  // appearance time). Keep that identity available when a signal introduces
  // no relationship that could otherwise place its actor on the canvas.
  const actorContextNodeIds = graph.nodes
    .filter(
      (node) =>
        node.node_type === "identity" &&
        typeof node.metadata["actor_type"] === "string",
    )
    .map((node) => node.node_id);
  const edgesBySignal = new Map<string, GraphEdge[]>();
  const unlinkedEdgeIds: string[] = [];

  for (const edge of [...graph.edges].sort(compareEdges)) {
    if (!timelineSignalIds.has(edge.signal_id)) {
      unlinkedEdgeIds.push(edge.edge_id);
      continue;
    }
    const bucket = edgesBySignal.get(edge.signal_id) ?? [];
    bucket.push(edge);
    edgesBySignal.set(edge.signal_id, bucket);
  }

  const cumulativeEdgeIds: string[] = [];
  const cumulativeNodeIds = new Set<string>();
  const introducedEdgeIds = new Set<string>();
  const steps = indexedTimeline.map(({ entry, sourceIndex }) => {
    const introduced = (edgesBySignal.get(entry.signal_id) ?? []).filter(
      (edge) => !introducedEdgeIds.has(edge.edge_id),
    );
    for (const edge of introduced) {
      introducedEdgeIds.add(edge.edge_id);
      cumulativeEdgeIds.push(edge.edge_id);
      if (
        knownNodeIds.has(edge.source_node_id) &&
        knownNodeIds.has(edge.target_node_id)
      ) {
        cumulativeNodeIds.add(edge.source_node_id);
        cumulativeNodeIds.add(edge.target_node_id);
      }
    }

    return {
      stepId: `${entry.signal_id}:${sourceIndex}`,
      signal: entry,
      introducedEdgeIds: introduced.map((edge) => edge.edge_id),
      cumulativeEdgeIds: [...cumulativeEdgeIds],
      cumulativeNodeIds: [
        ...new Set([...actorContextNodeIds, ...cumulativeNodeIds]),
      ],
    } satisfies AttackReplayStep;
  });

  return { steps, unlinkedEdgeIds };
}
