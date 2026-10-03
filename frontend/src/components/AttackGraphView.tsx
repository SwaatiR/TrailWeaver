import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type OnEdgesChange,
  type OnNodesChange,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { Icon, type IconName } from "./Icon";
import {
  findTimelineEntryForEdge,
  formatObservedAt,
  humanizeRelationship,
  layoutAttackGraph,
  partitionGraphEdges,
  type ResolvedGraphEdge,
} from "../graph/attackGraph";
import { buildAttackReplay } from "../replay/attackReplay";
import type { GraphNode, GraphResponse, TimelineEntry } from "../types/api";

interface NodeTypeDisplay {
  label: string;
  icon: IconName;
  dot: string;
}

const NODE_TYPE_DISPLAY: Record<string, NodeTypeDisplay> = {
  identity: { label: "Identity", icon: "identity", dot: "#d9f65a" },
  credential: { label: "Credential", icon: "key", dot: "#f0c75e" },
  role: { label: "Role", icon: "shield", dot: "#9db8f0" },
  resource: { label: "Resource", icon: "storage", dot: "#7fd4a8" },
  source_ip: { label: "Source IP", icon: "network", dot: "#e09b8c" },
};

const PLAYBACK_INTERVAL_MS = 1900;

function displayForNodeType(nodeType: string): NodeTypeDisplay {
  return (
    NODE_TYPE_DISPLAY[nodeType] ?? {
      label: nodeType,
      icon: "server",
      dot: "#aeb6b3",
    }
  );
}

function nodeContext(node: GraphNode): string {
  const metadata = node.metadata;
  const account =
    typeof metadata["account_id"] === "string" ? metadata["account_id"] : null;
  const region =
    typeof metadata["region"] === "string" ? metadata["region"] : null;
  const parts = [node.provider];
  if (account) parts.push(`acct ${account}`);
  if (region) parts.push(region);
  return parts.join(" · ");
}

type AttackFlowNode = Node<
  {
    graphNode: GraphNode;
    display: NodeTypeDisplay;
    context: string;
    current: boolean;
  },
  "attackNode"
>;

type AttackFlowEdge = Edge<{
  relationship: string;
  humanLabel: string;
  timestamp: string;
  signalId: string;
  selfLoop: boolean;
  /** Stable order among the full graph's self-loops for this node. */
  loopIndex: number;
  sourceLabel: string;
  targetLabel: string;
  current: boolean;
}>;

const flowNodeTypes = { attackNode: AttackGraphNode };
const flowEdgeTypes = { selfLoop: SelfLoopEdge };

const SELF_LOOP_LIFT = 150;
const SELF_LOOP_LIFT_STEP = 60;
const SELF_LOOP_SPREAD = 60;
const SELF_LOOP_SPREAD_STEP = 24;

function AttackGraphNode({
  data,
  selected,
}: {
  data: AttackFlowNode["data"];
  selected?: boolean;
}) {
  const { graphNode, display, context, current } = data;
  const classNames = [
    "graph-node",
    selected ? "graph-node--selected" : "",
    current ? "graph-node--current" : "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <div
      className={classNames}
      style={{ ["--node-dot" as string]: display.dot }}
    >
      <Handle
        type="target"
        position={Position.Left}
        id="in"
        aria-label={`Incoming relationships for ${graphNode.label}`}
      />
      <p className="graph-node__type">
        <span className="graph-node__dot" aria-hidden="true" />
        {display.label}
      </p>
      <p className="graph-node__label">
        <Icon name={display.icon} />
        <span>{graphNode.label}</span>
      </p>
      <p className="graph-node__context">{context}</p>
      <Handle
        type="source"
        position={Position.Right}
        id="out"
        aria-label={`Outgoing relationships for ${graphNode.label}`}
      />
    </div>
  );
}

/**
 * React Flow's stock smoothstep collapses same-node edges into the node card,
 * so each observed self-loop gets a deterministic arch above its node. Loop
 * indices come from the full graph and therefore never shift during replay.
 */
function SelfLoopEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  data,
  selected,
}: EdgeProps<AttackFlowEdge>) {
  const loopIndex = data?.loopIndex ?? 0;
  const lift = SELF_LOOP_LIFT + loopIndex * SELF_LOOP_LIFT_STEP;
  const spread = SELF_LOOP_SPREAD + loopIndex * SELF_LOOP_SPREAD_STEP;
  const controlLift = lift * 0.6;
  const control1X = sourceX + spread;
  const control1Y = sourceY - controlLift;
  const control2X = targetX - spread;
  const control2Y = targetY - controlLift;
  const path =
    `M ${sourceX} ${sourceY} ` +
    `C ${control1X} ${control1Y}, ${control2X} ${control2Y}, ${targetX} ${targetY}`;
  const labelX =
    (sourceX + 3 * control1X + 3 * control2X + targetX) / 8;
  const labelY =
    (sourceY + 3 * control1Y + 3 * control2Y + targetY) / 8 - 14;
  const labelClassNames = [
    "graph-loop-label",
    selected ? "graph-loop-label--selected" : "",
    data?.current ? "graph-loop-label--current" : "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <>
      <BaseEdge id={id} path={path} />
      <EdgeLabelRenderer>
        <div
          className={labelClassNames}
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
          }}
        >
          {data?.humanLabel ?? "Observed relationship"}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

function metadataRows(node: GraphNode): Array<{ key: string; value: string }> {
  const rows: Array<{ key: string; value: string }> = [];
  const push = (key: string, label: string) => {
    const value = node.metadata[key];
    if (typeof value === "string" && value.trim()) {
      rows.push({ key: label, value });
    }
  };
  push("arn", "ARN");
  push("identifier", "Identifier");
  push("actor_type", "Actor type");
  push("account_id", "Account");
  push("region", "Region");
  push("ip", "IP address");
  push("resource_type", "Resource type");
  return rows;
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Time unavailable";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function formatReplayTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Time unavailable";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function relationshipText(edge: ResolvedGraphEdge): string {
  return `${edge.source.label} ${humanizeRelationship(edge.edge.relationship)} ${
    edge.selfLoop ? "itself (same observed entity)" : edge.target.label
  }`;
}

export function AttackGraphView({
  graph,
  timeline,
  onViewTimeline,
}: {
  graph: GraphResponse;
  timeline: TimelineEntry[];
  onViewTimeline: (signalId: string) => void;
}) {
  const [instance, setInstance] =
    useState<ReactFlowInstance<AttackFlowNode, AttackFlowEdge> | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [mode, setMode] = useState<"full" | "replay">("full");
  const [replayIndex, setReplayIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(() =>
    typeof window === "undefined"
      ? false
      : window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );

  const positions = useMemo(() => layoutAttackGraph(graph.nodes), [graph.nodes]);
  const { resolved, unresolvable } = useMemo(
    () => partitionGraphEdges(graph.nodes, graph.edges),
    [graph.edges, graph.nodes],
  );
  const replay = useMemo(
    () => buildAttackReplay(timeline, graph),
    [graph, timeline],
  );
  const currentStep = replay.steps[replayIndex] ?? null;

  // Full-graph positions and loop geometry are fixed before replay filtering.
  const [flowNodes, setFlowNodes] = useState<AttackFlowNode[]>(() =>
    graph.nodes.map((node) => ({
      id: node.node_id,
      type: "attackNode",
      position: positions.get(node.node_id) ?? { x: 0, y: 0 },
      data: {
        graphNode: node,
        display: displayForNodeType(node.node_type),
        context: nodeContext(node),
        current: false,
      },
    })),
  );

  const [flowEdges, setFlowEdges] = useState<AttackFlowEdge[]>(() => {
    const loopsSeen = new Map<string, number>();
    return resolved.map(({ edge, selfLoop, source, target }) => {
      const loopIndex = selfLoop
        ? (loopsSeen.get(edge.source_node_id) ?? 0)
        : 0;
      if (selfLoop) loopsSeen.set(edge.source_node_id, loopIndex + 1);
      const humanLabel = humanizeRelationship(edge.relationship);
      return {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        sourceHandle: "out",
        targetHandle: "in",
        type: selfLoop ? "selfLoop" : "smoothstep",
        animated: false,
        ...(selfLoop
          ? {}
          : {
              label: humanLabel,
              labelStyle: {
                fill: "#f2f4f1",
                fontSize: 11,
                fontWeight: 700,
              },
              labelBgStyle: {
                fill: "#1b2324",
                fillOpacity: 0.92,
              },
            }),
        data: {
          relationship: edge.relationship,
          humanLabel,
          timestamp: edge.timestamp,
          signalId: edge.signal_id,
          selfLoop,
          loopIndex,
          sourceLabel: source.label,
          targetLabel: target.label,
          current: false,
        },
      };
    });
  });

  useEffect(() => {
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handleChange = () => setReducedMotion(preference.matches);
    preference.addEventListener("change", handleChange);
    return () => preference.removeEventListener("change", handleChange);
  }, []);

  useEffect(() => {
    if (
      mode !== "replay" ||
      !playing ||
      replay.steps.length <= 1 ||
      replayIndex >= replay.steps.length - 1
    ) {
      if (playing && replayIndex >= replay.steps.length - 1) setPlaying(false);
      return;
    }

    const timer = window.setTimeout(() => {
      const nextIndex = Math.min(replayIndex + 1, replay.steps.length - 1);
      setReplayIndex(nextIndex);
      if (nextIndex === replay.steps.length - 1) setPlaying(false);
    }, PLAYBACK_INTERVAL_MS);
    return () => window.clearTimeout(timer);
  }, [mode, playing, replay.steps.length, replayIndex]);

  const visibleEdgeIds = useMemo(
    () =>
      mode === "full"
        ? new Set(resolved.map(({ edge }) => edge.edge_id))
        : new Set(currentStep?.cumulativeEdgeIds ?? []),
    [currentStep, mode, resolved],
  );
  const visibleNodeIds = useMemo(
    () =>
      mode === "full"
        ? new Set(graph.nodes.map((node) => node.node_id))
        : new Set(currentStep?.cumulativeNodeIds ?? []),
    [currentStep, graph.nodes, mode],
  );
  const currentEdgeIds = useMemo(
    () => new Set(currentStep?.introducedEdgeIds ?? []),
    [currentStep],
  );
  const currentNodeIds = useMemo(() => {
    const ids = new Set<string>();
    for (const item of resolved) {
      if (currentEdgeIds.has(item.edge.edge_id)) {
        ids.add(item.edge.source_node_id);
        ids.add(item.edge.target_node_id);
      }
    }
    return ids;
  }, [currentEdgeIds, resolved]);

  const visibleFlowNodes = useMemo(
    () =>
      flowNodes
        .filter((node) => visibleNodeIds.has(node.id))
        .map((node) => ({
          ...node,
          data: {
            ...node.data,
            current: mode === "replay" && currentNodeIds.has(node.id),
          },
        })),
    [currentNodeIds, flowNodes, mode, visibleNodeIds],
  );
  const visibleFlowEdges = useMemo(
    () =>
      flowEdges
        .filter((edge) => visibleEdgeIds.has(edge.id))
        .map((edge) => {
          const current = mode === "replay" && currentEdgeIds.has(edge.id);
          return {
            ...edge,
            className: current ? "graph-edge--current" : undefined,
            labelStyle:
              current && edge.type !== "selfLoop"
                ? { ...edge.labelStyle, fill: "#d9f65a" }
                : edge.labelStyle,
            data: edge.data ? { ...edge.data, current } : edge.data,
          };
        }),
    [currentEdgeIds, flowEdges, mode, visibleEdgeIds],
  );
  const visibleResolved = useMemo(
    () => resolved.filter(({ edge }) => visibleEdgeIds.has(edge.edge_id)),
    [resolved, visibleEdgeIds],
  );
  const visibleUnresolvable = useMemo(
    () =>
      mode === "full"
        ? unresolvable
        : unresolvable.filter((edge) => visibleEdgeIds.has(edge.edge_id)),
    [mode, unresolvable, visibleEdgeIds],
  );

  const onNodesChange: OnNodesChange<AttackFlowNode> = useCallback(
    (changes) => setFlowNodes((current) => applyNodeChanges(changes, current)),
    [],
  );
  const onEdgesChange: OnEdgesChange<AttackFlowEdge> = useCallback(
    (changes) => setFlowEdges((current) => applyEdgeChanges(changes, current)),
    [],
  );

  const selectedNode =
    graph.nodes.find(
      (node) =>
        node.node_id === selectedNodeId && visibleNodeIds.has(node.node_id),
    ) ?? null;
  const selectedResolvedEdge =
    resolved.find(
      ({ edge }) =>
        edge.edge_id === selectedEdgeId && visibleEdgeIds.has(edge.edge_id),
    ) ?? null;
  const selectedEdgeTimeline = selectedResolvedEdge
    ? findTimelineEntryForEdge(selectedResolvedEdge.edge, timeline)
    : null;
  const currentResolvedEdges = currentStep
    ? resolved.filter(({ edge }) =>
        currentStep.introducedEdgeIds.includes(edge.edge_id),
      )
    : [];
  const currentUnresolvableCount = currentStep
    ? currentStep.introducedEdgeIds.length - currentResolvedEdges.length
    : 0;

  const presentTypes = useMemo(() => {
    const seen = new Map<string, NodeTypeDisplay>();
    for (const node of graph.nodes) {
      if (!seen.has(node.node_type)) {
        seen.set(node.node_type, displayForNodeType(node.node_type));
      }
    }
    return [...seen.entries()];
  }, [graph.nodes]);

  const clearSelection = useCallback(() => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    setFlowNodes((current) =>
      current.map((node) => ({ ...node, selected: false })),
    );
    setFlowEdges((current) =>
      current.map((edge) => ({ ...edge, selected: false })),
    );
  }, []);

  const changeMode = (nextMode: "full" | "replay") => {
    setPlaying(false);
    clearSelection();
    if (nextMode === "replay") setReplayIndex(0);
    setMode(nextMode);
  };

  const goToStep = (index: number) => {
    setPlaying(false);
    clearSelection();
    setReplayIndex(Math.max(0, Math.min(index, replay.steps.length - 1)));
  };

  const fitDuration = reducedMotion ? 0 : 200;
  const fitGraph = () =>
    instance?.fitView({ padding: 0.3, maxZoom: 1, duration: fitDuration });
  const isFirstStep = replayIndex <= 0;
  const isFinalStep = replayIndex >= replay.steps.length - 1;
  const progress =
    replay.steps.length <= 1
      ? replay.steps.length === 1
        ? 100
        : 0
      : (replayIndex / (replay.steps.length - 1)) * 100;

  return (
    <div className="graph-workspace">
      <div className="graph-mode-bar">
        <div className="graph-mode-switch" aria-label="Attack graph mode">
          <button
            type="button"
            aria-pressed={mode === "full"}
            onClick={() => changeMode("full")}
          >
            Full graph
          </button>
          <button
            type="button"
            aria-pressed={mode === "replay"}
            onClick={() => changeMode("replay")}
          >
            Replay
          </button>
        </div>
        <p>
          {mode === "full"
            ? "All observed relationships in this incident."
            : "Observed relationships revealed cumulatively by linked evidence."}
        </p>
      </div>

      <div className="graph-workspace__top">
        <div className="graph-legend" aria-label="Node types in this incident">
          {presentTypes.map(([nodeType, display]) => (
            <span key={nodeType} className="graph-legend__chip">
              <span
                className="graph-node__dot"
                style={{ background: display.dot }}
                aria-hidden="true"
              />
              <Icon name={display.icon} />
              {display.label}
            </span>
          ))}
        </div>
        <p className="graph-counts" aria-live="polite">
          {visibleFlowNodes.length}{" "}
          {visibleFlowNodes.length === 1 ? "entity" : "entities"} ·{" "}
          {visibleResolved.length}{" "}
          {visibleResolved.length === 1
            ? "observed relationship"
            : "observed relationships"}
        </p>
        <div className="graph-actions">
          <button type="button" onClick={fitGraph}>
            Fit to view
          </button>
          <button
            type="button"
            onClick={() => {
              clearSelection();
              fitGraph();
            }}
          >
            Reset
          </button>
        </div>
      </div>

      <div className="graph-body">
        <div
          className="graph-canvas"
          role="application"
          aria-roledescription="attack graph"
          aria-label={`${mode === "replay" ? "Cumulative replay graph" : "Observed attack graph"} with ${visibleFlowNodes.length} entities and ${visibleResolved.length} relationships. Use the relationship list below for an equivalent text representation.`}
        >
          {visibleFlowNodes.length === 0 ? (
            <div className="graph-canvas__empty" role="status">
              <Icon name="attack" />
              <strong>
                {mode === "replay" && replay.steps.length === 0
                  ? "No replayable evidence"
                  : "No relationship is visible at this step"}
              </strong>
              <p>
                {mode === "replay" && replay.steps.length === 0
                  ? "The incident timeline contains no observations to replay. Full Graph still preserves any observed entities and relationships returned by the API."
                  : "This observation creates no graph relationship, and no earlier relationship has been revealed. The evidence panel remains authoritative."}
              </p>
            </div>
          ) : (
            <ReactFlow<AttackFlowNode, AttackFlowEdge>
              nodes={visibleFlowNodes}
              edges={visibleFlowEdges}
              nodeTypes={flowNodeTypes}
              edgeTypes={flowEdgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onInit={setInstance}
              fitView
              fitViewOptions={{ padding: 0.3, maxZoom: 1 }}
              minZoom={0.2}
              maxZoom={2}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
              onSelectionChange={({ nodes, edges }) => {
                setSelectedNodeId(nodes[0]?.id ?? null);
                setSelectedEdgeId(edges[0]?.id ?? null);
              }}
              onPaneClick={clearSelection}
              proOptions={{ hideAttribution: false }}
              colorMode="dark"
            >
              <Background gap={28} size={1} />
              <Controls
                showInteractive={false}
                aria-label="Graph pan and zoom controls"
              />
            </ReactFlow>
          )}
        </div>

        <aside
          className="graph-inspector"
          aria-label={
            selectedNode
              ? "Selected entity details"
              : selectedResolvedEdge
                ? "Selected relationship evidence"
                : "Graph inspector"
          }
          aria-live="polite"
          tabIndex={-1}
        >
          {!selectedNode && !selectedResolvedEdge ? (
            <div className="graph-inspector__empty">
              <span className="graph-inspector__empty-icon" aria-hidden="true">
                <Icon name="search" />
              </span>
              <strong>Inspector</strong>
              <p>
                Select a visible entity or relationship to inspect its observed
                evidence. Inspection never changes replay position.
              </p>
            </div>
          ) : null}

          {selectedNode ? (
            <div className="graph-inspector__section">
              <p className="graph-inspector__kicker">
                Observed entity · part of this incident
              </p>
              <h3>{selectedNode.label}</h3>
              <dl>
                <div>
                  <dt>Type</dt>
                  <dd>{displayForNodeType(selectedNode.node_type).label}</dd>
                </div>
                <div>
                  <dt>Provider</dt>
                  <dd>{selectedNode.provider}</dd>
                </div>
                {metadataRows(selectedNode).map((row) => (
                  <div key={row.key}>
                    <dt>{row.key}</dt>
                    <dd>{row.value}</dd>
                  </div>
                ))}
              </dl>
              <button type="button" onClick={clearSelection}>
                Clear selection
              </button>
            </div>
          ) : null}

          {selectedResolvedEdge && !selectedNode ? (
            <div className="graph-inspector__section">
              <p className="graph-inspector__kicker">
                Observed relationship → evidence
              </p>
              <h3>
                {humanizeRelationship(selectedResolvedEdge.edge.relationship)}
              </h3>
              <p className="graph-inspector__flow">
                {selectedResolvedEdge.source.label}
                {selectedResolvedEdge.selfLoop
                  ? " → itself (same observed entity)"
                  : ` → ${selectedResolvedEdge.target.label}`}
              </p>
              <dl>
                <div>
                  <dt>Relationship</dt>
                  <dd>
                    {humanizeRelationship(
                      selectedResolvedEdge.edge.relationship,
                    )}{" "}
                    <span className="graph-inspector__canonical">
                      ({selectedResolvedEdge.edge.relationship})
                    </span>
                  </dd>
                </div>
                <div>
                  <dt>Observed</dt>
                  <dd>{formatObservedAt(selectedResolvedEdge.edge.timestamp)}</dd>
                </div>
                <div>
                  <dt>Evidence</dt>
                  <dd>{selectedResolvedEdge.edge.signal_id}</dd>
                </div>
              </dl>
              {selectedEdgeTimeline ? (
                <div className="graph-inspector__evidence">
                  <strong>Linked observed signal</strong>
                  <p>{selectedEdgeTimeline.title}</p>
                  <p>{selectedEdgeTimeline.reason}</p>
                  <span className="rule-chip">
                    {selectedEdgeTimeline.rule_id}
                  </span>
                </div>
              ) : (
                <p className="graph-inspector__no-evidence">
                  Evidence linkage unavailable. This observed relationship remains
                  in Full Graph, but TrailWeaver will not guess its timeline entry.
                </p>
              )}
              <button type="button" onClick={clearSelection}>
                Clear selection
              </button>
            </div>
          ) : null}
        </aside>
      </div>

      {visibleUnresolvable.length > 0 ? (
        <p className="graph-warning" role="note">
          {visibleUnresolvable.length}{" "}
          {visibleUnresolvable.length === 1
            ? "relationship references"
            : "relationships reference"}{" "}
          an unknown entity and {visibleUnresolvable.length === 1 ? "was" : "were"}{" "}
          omitted from the canvas rather than guessed.
        </p>
      ) : null}

      {mode === "replay" ? (
        <section className="replay-panel" aria-labelledby="replay-title">
          <div className="replay-panel__heading">
            <div>
              <h3 id="replay-title">Attack replay</h3>
              <p>Chronological reconstruction of linked observed evidence.</p>
            </div>
            <p className="replay-panel__status" aria-live="polite">
              {currentStep
                ? `Step ${replayIndex + 1} of ${replay.steps.length} · ${formatReplayTime(currentStep.signal.timestamp)}`
                : "No replay steps available"}
            </p>
          </div>

          {replay.steps.length > 0 ? (
            <div
              className="replay-rail"
              role="group"
              aria-label="Replay timeline"
              style={{ ["--replay-progress" as string]: `${progress}%` }}
            >
              <span className="replay-rail__track" aria-hidden="true">
                <i />
              </span>
              <div
                className="replay-rail__steps"
                style={{
                  gridTemplateColumns: `repeat(${replay.steps.length}, minmax(88px, 1fr))`,
                }}
              >
                {replay.steps.map((step, index) => (
                  <button
                    type="button"
                    key={step.stepId}
                    className={
                      index === replayIndex
                        ? "replay-marker replay-marker--current"
                        : index < replayIndex
                          ? "replay-marker replay-marker--past"
                          : "replay-marker"
                    }
                    aria-pressed={index === replayIndex}
                    aria-label={`Go to step ${index + 1} of ${replay.steps.length}: ${step.signal.title}, ${formatReplayTime(step.signal.timestamp)}`}
                    onClick={() => goToStep(index)}
                  >
                    <span aria-hidden="true" />
                    <time dateTime={step.signal.timestamp}>
                      {formatReplayTime(step.signal.timestamp).replace(" UTC", "")}
                    </time>
                    <small>{index + 1}</small>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="replay-empty" role="status">
              <strong>No replayable evidence</strong>
              <p>
                The graph may still be inspected in Full Graph, but no incident
                timeline observations are available for deterministic playback.
              </p>
            </div>
          )}

          {currentStep ? (
            <div className="replay-evidence" aria-live="polite">
              <div className="replay-evidence__summary">
                <time dateTime={currentStep.signal.timestamp}>
                  {formatReplayTime(currentStep.signal.timestamp)}
                </time>
                <h4>{currentStep.signal.title}</h4>
                <p>{currentStep.signal.reason}</p>
                <span className="rule-chip">{currentStep.signal.rule_id}</span>
              </div>
              <div className="replay-evidence__relationships">
                <strong>
                  {currentResolvedEdges.length === 1
                    ? "Newly observed relationship"
                    : "Newly observed relationships"}
                </strong>
                {currentResolvedEdges.length > 0 ? (
                  <ul>
                    {currentResolvedEdges.map((edge) => (
                      <li key={edge.edge.edge_id}>{relationshipText(edge)}</li>
                    ))}
                  </ul>
                ) : (
                  <p>
                    This signal introduces no renderable graph relationship.
                    Its timeline evidence remains part of the replay.
                  </p>
                )}
                {currentUnresolvableCount > 0 ? (
                  <p className="replay-evidence__warning">
                    {currentUnresolvableCount}{" "}
                    {currentUnresolvableCount === 1
                      ? "relationship references"
                      : "relationships reference"}{" "}
                    an unknown entity and cannot be drawn.
                  </p>
                ) : null}
                <button
                  type="button"
                  onClick={() => onViewTimeline(currentStep.signal.signal_id)}
                >
                  View in timeline
                </button>
              </div>
            </div>
          ) : null}

          <div className="replay-controls" aria-label="Replay playback controls">
            <button
              type="button"
              disabled={!currentStep || isFirstStep}
              onClick={() => goToStep(0)}
            >
              Restart
            </button>
            <button
              type="button"
              disabled={!currentStep || isFirstStep}
              onClick={() => goToStep(replayIndex - 1)}
            >
              Previous step
            </button>
            <button
              type="button"
              className="replay-controls__primary"
              disabled={
                !currentStep || replay.steps.length <= 1 || (!playing && isFinalStep)
              }
              aria-label={playing ? "Pause attack replay" : "Play attack replay"}
              onClick={() => setPlaying((current) => !current)}
            >
              {playing ? "Pause" : "Play"}
            </button>
            <button
              type="button"
              disabled={!currentStep || isFinalStep}
              onClick={() => goToStep(replayIndex + 1)}
            >
              Next step
            </button>
          </div>

          {replay.unlinkedEdgeIds.length > 0 ? (
            <p className="replay-linkage-warning" role="note">
              {replay.unlinkedEdgeIds.length}{" "}
              {replay.unlinkedEdgeIds.length === 1
                ? "observed relationship remains"
                : "observed relationships remain"}{" "}
              available in Full Graph but cannot be placed in replay because
              timeline evidence linkage is unavailable.
            </p>
          ) : null}
        </section>
      ) : null}

      <section className="graph-text" aria-label="Observed relationships as text">
        <h3>
          {mode === "replay"
            ? "Relationships observed through this step"
            : "Observed relationships"}
        </h3>
        {visibleResolved.length === 0 ? (
          <p>
            {mode === "replay"
              ? "No graph relationships are visible at this replay step."
              : "No observed relationships connect these entities. Nothing was invented to fill the gap."}
          </p>
        ) : (
          <ol>
            {visibleResolved.map((item) => {
              const timelineEntry = findTimelineEntryForEdge(item.edge, timeline);
              const current =
                mode === "replay" && currentEdgeIds.has(item.edge.edge_id);
              return (
                <li
                  key={item.edge.edge_id}
                  className={current ? "graph-text__current" : undefined}
                >
                  <strong>
                    {item.source.label}
                    {item.selfLoop
                      ? " → itself (same observed entity)"
                      : ` → ${item.target.label}`}
                  </strong>
                  <span>
                    {humanizeRelationship(item.edge.relationship)} ·{" "}
                    {formatTimestamp(item.edge.timestamp)} · evidence{" "}
                    {item.edge.signal_id}
                    {timelineEntry ? ` · “${timelineEntry.title}”` : ""}
                    {current ? " · Current step" : ""}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
        <p className="graph-semantics">
          Observed relationships only. Potential reachability over known assets is
          context, not evidence, and lives under Potential impact — never in this
          graph or replay.
        </p>
      </section>
    </div>
  );
}
