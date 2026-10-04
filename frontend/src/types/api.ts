export type Severity = string;

export interface HealthResponse {
  status: "ok";
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: Severity;
  created_at: string;
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
  signal_id: string;
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

export interface CapabilitiesResponse {
  file_analysis: boolean;
  s3_analysis: boolean;
  demo_mode: boolean;
}

export interface ProvenanceSummary {
  evidence_signal_count: number;
  identified_event_count: number;
  identified_events_with_recorded_observations: number;
  unidentified_signal_count: number;
  observing_run_count: number;
  source_types: string[];
  event_time_start: string | null;
  event_time_end: string | null;
}

export interface ObservingRun {
  analysis_run_id: string;
  source_type: string;
  source_label: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
}

export type ObservationState =
  | "recorded"
  | "history_unavailable"
  | "identity_unavailable";

export interface EvidenceProvenance {
  signal_id: string;
  rule_id: string;
  title: string;
  provider: string;
  event_id: string | null;
  event_time: string;
  observation_state: ObservationState;
  first_recorded_at: string | null;
  observed_run_ids: string[];
}

export interface IncidentProvenance {
  incident_id: string;
  summary: ProvenanceSummary;
  observing_runs: ObservingRun[];
  evidence: EvidenceProvenance[];
}

export interface AnalysisIssue {
  record_index: number;
  code: string;
  event_id: string | null;
}

export interface AnalysisResponse {
  analysis_run_id: string;
  source_type: "local_file" | "web_upload" | "s3_object" | "direct_input";
  started_at: string;
  completed_at: string;
  source_label: string | null;
  total_records: number;
  accepted_records: number;
  failed_records: number;
  duplicate_records: number;
  events_analyzed: number;
  signals: number;
  correlations: number;
  incidents_created: number;
  persisted_incidents: number;
  incident_ids: string[];
  issues: AnalysisIssue[];
}

export interface S3AnalysisRequest {
  bucket: string;
  key: string;
  version_id?: string;
  region?: string;
  source_label?: string;
}

export interface DemoResetResponse {
  status: "ok";
  incidents: number;
}

export interface ClearWorkspaceResponse {
  status: "ok";
  incidents: number;
}
