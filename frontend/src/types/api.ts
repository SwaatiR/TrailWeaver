export type Severity = string;

export interface HealthResponse {
  status: "ok";
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: Severity;
  started_at: string;
  ended_at: string;
}

export interface Actor {
  actor_type: string | null;
  identifier: string | null;
  name: string | null;
  arn: string | null;
  account_id: string | null;
}

export interface TimelineEntry {
  timestamp: string;
  rule_id: string;
  title: string;
  reason: string;
}

export interface IncidentDetail {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  summary: string;
  created_at: string;
  started_at: string;
  ended_at: string;
  primary_actor: Actor | null;
  timeline: TimelineEntry[];
}

export interface RiskFactor {
  identifier: string;
  description: string;
  points: number;
}

export interface RiskResponse {
  score: number;
  level: string;
  factors: RiskFactor[];
  explanation: string;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactics: string[];
  description: string;
}

export interface MitreResponse {
  techniques: MitreTechnique[];
  tactics: string[];
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface CloudAsset {
  asset_id: string;
  asset_type: string;
  provider: string;
  account_id: string | null;
  region: string | null;
  name: string | null;
  arn: string | null;
  native_identifier: string | null;
  metadata: Record<string, JsonValue>;
}

export interface PermissionGrant {
  subject: string;
  actions: string[];
  resources: string[];
  effect: string;
  source: string;
}

export interface BlastRadiusAvailable {
  available: true;
  subject: string | null;
  reachable_assets: CloudAsset[];
  matched_grants: PermissionGrant[];
  total_reachable_assets: number;
  summary: string;
}

export interface BlastRadiusUnavailable {
  available: false;
  reason: string;
}

export type BlastRadiusResponse =
  | BlastRadiusAvailable
  | BlastRadiusUnavailable;

export interface Recommendation {
  recommendation_id: string;
  title: string;
  description: string;
  priority: string;
  rationale: string;
}

export interface GuidanceResponse {
  recommendations: Recommendation[];
  summary: string;
}

export interface GraphNode {
  node_id: string;
  node_type: string;
  label: string;
  provider: string;
  metadata: Record<string, JsonValue>;
}

export interface GraphEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship: string;
  timestamp: string;
  signal_id: string;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
