import { useCallback, useMemo, useState } from "react";
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
} from "../graph/attackGraph";
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

function displayForNodeType(nodeType: string): NodeTypeDisplay {
  return NODE_TYPE_DISPLAY[nodeType] ?? { label: nodeType, icon: "server", dot: "#aeb6b3" };
}

/** Short context line from data the backend actually returned. */
function nodeContext(node: GraphNode): string {
  const metadata = node.metadata;
  const account = typeof metadata["account_id"] === "string" ? metadata["account_id"] : null;
  const region = typeof metadata["region"] === "string" ? metadata["region"] : null;
  const parts = [node.provider];
  if (account) parts.push(`acct ${account}`);
  if (region) parts.push(region);
  return parts.join(" · ");
}

type AttackFlowNode = Node<
  { graphNode: GraphNode; display: NodeTypeDisplay; context: string },
  "attackNode"
>;

type AttackFlowEdge = Edge<{
  relationship: string;
  humanLabel: string;
  timestamp: string;
  signalId: string;
  selfLoop: boolean;
  /** Stable zero-based order of this loop among its node's self-loops. */
  loopIndex: number;
  sourceLabel: string;
  targetLabel: string;
}>;

const flowNodeTypes = { attackNode: AttackGraphNode };
const flowEdgeTypes = { selfLoop: SelfLoopEdge };

/** Base lift of the first self-loop arch above its node, in canvas pixels. */
const SELF_LOOP_LIFT = 150;
/** Extra lift per additional self-loop on the same node. */
const SELF_LOOP_LIFT_STEP = 60;
/** Base horizontal bow of a self-loop arch. */
const SELF_LOOP_SPREAD = 60;
/** Extra bow per additional self-loop on the same node. */
const SELF_LOOP_SPREAD_STEP = 24;

function AttackGraphNode({
  data,
  selected,
}: {
  data: AttackFlowNode["data"];
  selected?: boolean;
}) {
  const { graphNode, display, context } = data;
  return (
    <div
      className={`graph-node${selected ? " graph-node--selected" : ""}`}
      style={{ ["--node-dot" as string]: display.dot }}
    >
      <Handle type="target" position={Position.Left} id="in" aria-label={`Incoming relationships for ${graphNode.label}`} />
      <p className="graph-node__type">
        <span className="graph-node__dot" aria-hidden="true" />
        {display.label}
      </p>
      <p className="graph-node__label">
        <Icon name={display.icon} />
        <span>{graphNode.label}</span>
      </p>
      <p className="graph-node__context">{context}</p>
      <Handle type="source" position={Position.Right} id="out" aria-label={`Outgoing relationships for ${graphNode.label}`} />
    </div>
  );
}

/**
 * Focused self-loop renderer: React Flow's stock smoothstep collapses
 * same-node edges into the node card, so each observed self-loop gets an
 * arch above its node instead. The arch height and bow grow with the
 * deterministic per-node loop index, keeping multiple loops on one node
 * separately visible and labeled. No intermediate nodes are invented and
 * the canonical edge identity is untouched.
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
  // Exact cubic midpoint keeps the label glued to the arch apex.
  const labelX = (sourceX + 3 * control1X + 3 * control2X + targetX) / 8;
  const labelY = (sourceY + 3 * control1Y + 3 * control2Y + targetY) / 8 - 14;
  return (
    <>
      <BaseEdge id={id} path={path} />
      <EdgeLabelRenderer>
        <div
          className={`graph-loop-label${selected ? " graph-loop-label--selected" : ""}`}
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
    if (typeof value === "string" && value.trim()) rows.push({ key: label, value });
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

export function AttackGraphView({
  graph,
  timeline,
}: {
  graph: GraphResponse;
  timeline: TimelineEntry[];
}) {
  const [instance, setInstance] =
    useState<ReactFlowInstance<AttackFlowNode, AttackFlowEdge> | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  const positions = useMemo(() => layoutAttackGraph(graph.nodes), [graph]);
  const { resolved, unresolvable } = useMemo(
    () => partitionGraphEdges(graph.nodes, graph.edges),
    [graph],
  );

  // The parent remounts this view per incident (key={incidentId}), so the
  // graph prop is fixed for the life of the component: initializers below
  // run once, and React Flow owns positions/selection from there.
  const [flowNodes, setFlowNodes] = useState<AttackFlowNode[]>(() =>
    graph.nodes.map((node) => ({
      id: node.node_id,
      type: "attackNode",
      position: positions.get(node.node_id) ?? { x: 0, y: 0 },
      data: {
        graphNode: node,
        display: displayForNodeType(node.node_type),
        context: nodeContext(node),
      },
    })),
  );

  const [flowEdges, setFlowEdges] = useState<AttackFlowEdge[]>(() => {
    // Deterministic per-node loop order: resolved edges follow backend
    // chronology, so the first self-loop encountered sits lowest.
    const loopsSeen = new Map<string, number>();
    return resolved.map(({ edge, selfLoop, source, target }) => {
      const loopIndex = selfLoop ? (loopsSeen.get(edge.source_node_id) ?? 0) : 0;
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
        },
      };
    });
  });

  const onNodesChange: OnNodesChange<AttackFlowNode> = useCallback(
    (changes) => {
      setFlowNodes((current) => applyNodeChanges(changes, current));
    },
    [],
  );
  const onEdgesChange: OnEdgesChange<AttackFlowEdge> = useCallback(
    (changes) => {
      setFlowEdges((current) => applyEdgeChanges(changes, current));
    },
    [],
  );

  const selectedNode = graph.nodes.find((node) => node.node_id === selectedNodeId) ?? null;
  const selectedResolvedEdge = resolved.find(({ edge }) => edge.edge_id === selectedEdgeId) ?? null;
  const selectedEdgeTimeline = selectedResolvedEdge
    ? findTimelineEntryForEdge(selectedResolvedEdge.edge, timeline)
    : null;

  const presentTypes = useMemo(() => {
    const seen = new Map<string, NodeTypeDisplay>();
    for (const node of graph.nodes) {
      if (!seen.has(node.node_type)) seen.set(node.node_type, displayForNodeType(node.node_type));
    }
    return [...seen.entries()];
  }, [graph]);

  const clearSelection = () => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    setFlowNodes((current) => current.map((node) => ({ ...node, selected: false })));
    setFlowEdges((current) => current.map((edge) => ({ ...edge, selected: false })));
  };

  return (
    <div className="graph-workspace">
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
          {graph.nodes.length} {graph.nodes.length === 1 ? "entity" : "entities"} ·{" "}
          {resolved.length}{" "}
          {resolved.length === 1 ? "observed relationship" : "observed relationships"}
        </p>
        <div className="graph-actions">
          <button type="button" onClick={() => instance?.fitView({ padding: 0.3, maxZoom: 1, duration: 200 })}>
            Fit to view
          </button>
          <button
            type="button"
            onClick={() => {
              clearSelection();
              instance?.fitView({ padding: 0.3, maxZoom: 1, duration: 200 });
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
          aria-label={`Observed attack graph with ${graph.nodes.length} entities and ${resolved.length} relationships. Use the relationship list below for an equivalent text representation.`}
        >
          <ReactFlow<AttackFlowNode, AttackFlowEdge>
            nodes={flowNodes}
            edges={flowEdges}
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
            onSelectionChange={({ nodes: selectedNodes, edges: selectedEdges }) => {
              const node = selectedNodes[0];
              const edge = selectedEdges[0];
              setSelectedNodeId(node ? node.id : null);
              setSelectedEdgeId(edge ? edge.id : null);
            }}
            onPaneClick={clearSelection}
            proOptions={{ hideAttribution: false }}
            colorMode="dark"
          >
            <Background gap={28} size={1} />
            <Controls showInteractive={false} aria-label="Graph pan and zoom controls" />
          </ReactFlow>
        </div>

        <aside
          className="graph-inspector"
          aria-label={selectedNode ? "Selected entity details" : selectedResolvedEdge ? "Selected relationship evidence" : "Graph inspector"}
          aria-live="polite"
          tabIndex={-1}
        >
          {!selectedNode && !selectedResolvedEdge ? (
            <div className="graph-inspector__empty">
              <span className="graph-inspector__empty-icon" aria-hidden="true">
                <Icon name="search" />
              </span>
              <strong>Inspector</strong>
              <p>Select an entity or relationship to inspect its observed evidence.</p>
            </div>
          ) : null}

          {selectedNode ? (
            <div className="graph-inspector__section">
              <p className="graph-inspector__kicker">Observed entity · part of this incident</p>
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
              <p className="graph-inspector__kicker">Observed relationship → evidence</p>
              <h3>{humanizeRelationship(selectedResolvedEdge.edge.relationship)}</h3>
              <p className="graph-inspector__flow">
                {selectedResolvedEdge.source.label}
                {selectedResolvedEdge.selfLoop ? " → itself (same observed entity)" : ` → ${selectedResolvedEdge.target.label}`}
              </p>
              <dl>
                <div>
                  <dt>Relationship</dt>
                  <dd>
                    {humanizeRelationship(selectedResolvedEdge.edge.relationship)}{" "}
                    <span className="graph-inspector__canonical">({selectedResolvedEdge.edge.relationship})</span>
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
                  <strong>Observed signal (matched by timestamp)</strong>
                  <p>{selectedEdgeTimeline.title}</p>
                  <p>{selectedEdgeTimeline.reason}</p>
                  <span className="rule-chip">{selectedEdgeTimeline.rule_id}</span>
                </div>
              ) : (
                <p className="graph-inspector__no-evidence">
                  No timeline entry shares this relationship&apos;s timestamp. The signal ID above remains the authoritative evidence reference.
                </p>
              )}
              <button type="button" onClick={clearSelection}>
                Clear selection
              </button>
            </div>
          ) : null}
        </aside>
      </div>

      {unresolvable.length > 0 ? (
        <p className="graph-warning" role="note">
          {unresolvable.length}{" "}
          {unresolvable.length === 1 ? "relationship references" : "relationships reference"} an
          unknown entity and {unresolvable.length === 1 ? "was" : "were"} omitted rather than
          guessed.
        </p>
      ) : null}

      <section className="graph-text" aria-label="Observed relationships as text">
        <h3>Observed relationships</h3>
        {resolved.length === 0 ? (
          <p>No observed relationships connect these entities. Nothing was invented to fill the gap.</p>
        ) : (
          <ol>
            {resolved.map(({ edge, source, target, selfLoop }) => {
              const timelineEntry = findTimelineEntryForEdge(edge, timeline);
              return (
                <li key={edge.edge_id}>
                  <strong>
                    {source.label}
                    {selfLoop ? " → itself (same observed entity)" : ` → ${target.label}`}
                  </strong>
                  <span>
                    {humanizeRelationship(edge.relationship)} · {formatTimestamp(edge.timestamp)} · evidence {edge.signal_id}
                    {timelineEntry ? ` · “${timelineEntry.title}”` : ""}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
        <p className="graph-semantics">
          Observed relationships only. Potential reachability over known assets is context, not
          evidence, and lives under Potential impact — never in this graph.
        </p>
      </section>
    </div>
  );
}
