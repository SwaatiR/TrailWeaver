"""Explicit JSON response schemas and domain-to-API conversions."""

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from trailweaver.api.execution import InvestigationExecutionResult
from trailweaver.attack_graph import AttackGraph
from trailweaver.blast_radius import BlastRadiusResult
from trailweaver.incidents import Incident
from trailweaver.investigation import InvestigationGuidance
from trailweaver.mitre import MitreMapping
from trailweaver.models import Actor
from trailweaver.risk import RiskAssessment

ApiJsonValue: TypeAlias = JsonValue


class HealthResponse(BaseModel):
    """Service health response."""

    status: Literal["ok"]


class IncidentSummaryResponse(BaseModel):
    """Compact incident representation for collection responses."""

    incident_id: str
    title: str
    severity: str
    created_at: datetime
    started_at: datetime
    ended_at: datetime

    @classmethod
    def from_domain(cls, incident: Incident) -> "IncidentSummaryResponse":
        """Build a summary without traversing incident evidence."""

        return cls(
            incident_id=incident.incident_id,
            title=incident.title,
            severity=incident.severity.value,
            created_at=incident.created_at,
            started_at=incident.started_at,
            ended_at=incident.ended_at,
        )


class ActorResponse(BaseModel):
    """Normalized primary actor fields safe for API consumers."""

    actor_type: str | None
    identifier: str | None
    name: str | None
    arn: str | None
    account_id: str | None

    @classmethod
    def from_domain(cls, actor: Actor) -> "ActorResponse":
        """Convert a normalized actor without accessing source evidence."""

        return cls(
            actor_type=actor.actor_type,
            identifier=actor.identifier,
            name=actor.name,
            arn=actor.arn,
            account_id=actor.account_id,
        )


class TimelineEntryResponse(BaseModel):
    """One evidence-safe incident timeline entry."""

    signal_id: str
    timestamp: datetime
    rule_id: str
    title: str
    reason: str


class IncidentDetailResponse(BaseModel):
    """Incident detail without nested signals or raw CloudTrail evidence."""

    incident_id: str
    title: str
    description: str
    severity: str
    summary: str
    created_at: datetime
    started_at: datetime
    ended_at: datetime
    primary_actor: ActorResponse | None
    timeline: list[TimelineEntryResponse]

    @classmethod
    def from_domain(cls, incident: Incident) -> "IncidentDetailResponse":
        """Build an API detail view from explicitly selected domain fields."""

        actor = incident.primary_actor
        return cls(
            incident_id=incident.incident_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity.value,
            summary=incident.summary,
            created_at=incident.created_at,
            started_at=incident.started_at,
            ended_at=incident.ended_at,
            primary_actor=None if actor is None else ActorResponse.from_domain(actor),
            timeline=[
                TimelineEntryResponse(
                    signal_id=entry.signal_id,
                    timestamp=entry.timestamp,
                    rule_id=entry.rule_id,
                    title=entry.title,
                    reason=entry.reason,
                )
                for entry in incident.timeline
            ],
        )


class RiskFactorResponse(BaseModel):
    """One explainable contribution to risk."""

    identifier: str
    description: str
    points: int


class RiskResponse(BaseModel):
    """Explainable incident risk response."""

    score: int
    level: str
    factors: list[RiskFactorResponse]
    explanation: str

    @classmethod
    def from_domain(cls, assessment: RiskAssessment) -> "RiskResponse":
        """Convert an existing risk assessment to its API form."""

        return cls(
            score=assessment.score,
            level=assessment.level.value,
            factors=[
                RiskFactorResponse(
                    identifier=factor.identifier,
                    description=factor.description,
                    points=factor.points,
                )
                for factor in assessment.factors
            ],
            explanation=assessment.explanation,
        )


class TechniqueResponse(BaseModel):
    """Concise MITRE ATT&CK technique representation."""

    technique_id: str
    name: str
    tactics: list[str]
    description: str


class MitreResponse(BaseModel):
    """Deduplicated MITRE ATT&CK mapping response."""

    techniques: list[TechniqueResponse]
    tactics: list[str]

    @classmethod
    def from_domain(cls, mapping: MitreMapping) -> "MitreResponse":
        """Convert the existing mapping without inspecting evidence."""

        return cls(
            techniques=[
                TechniqueResponse(
                    technique_id=technique.technique_id,
                    name=technique.name,
                    tactics=list(technique.tactics),
                    description=technique.description,
                )
                for technique in mapping.techniques
            ],
            tactics=list(mapping.tactics),
        )


class GraphNodeResponse(BaseModel):
    """JSON-safe attack-graph node."""

    node_id: str
    node_type: str
    label: str
    provider: str
    metadata: dict[str, ApiJsonValue]


class GraphEdgeResponse(BaseModel):
    """JSON-safe attack-graph edge."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship: str
    timestamp: datetime
    signal_id: str


class GraphResponse(BaseModel):
    """Attack graph response."""

    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]

    @classmethod
    def from_domain(cls, graph: AttackGraph) -> "GraphResponse":
        """Convert graph entities to selected JSON-safe fields."""

        return cls(
            nodes=[
                GraphNodeResponse(
                    node_id=node.node_id,
                    node_type=node.node_type.value,
                    label=node.label,
                    provider=node.provider,
                    metadata=_json_object(node.metadata),
                )
                for node in graph.nodes
            ],
            edges=[
                GraphEdgeResponse(
                    edge_id=edge.edge_id,
                    source_node_id=edge.source_node_id,
                    target_node_id=edge.target_node_id,
                    relationship=edge.relationship.value,
                    timestamp=edge.timestamp,
                    signal_id=edge.signal_id,
                )
                for edge in graph.edges
            ],
        )


class CloudAssetResponse(BaseModel):
    """Known cloud asset included in a blast-radius estimate."""

    asset_id: str
    asset_type: str
    provider: str
    account_id: str | None
    region: str | None
    name: str | None
    arn: str | None
    native_identifier: str | None
    metadata: dict[str, ApiJsonValue]


class PermissionGrantResponse(BaseModel):
    """Permission fact explaining a blast-radius estimate."""

    subject: str
    actions: list[str]
    resources: list[str]
    effect: str
    source: str


class BlastRadiusAnalysisResponse(BaseModel):
    """Available blast-radius analysis, including valid empty results."""

    available: Literal[True] = True
    subject: str | None
    reachable_assets: list[CloudAssetResponse]
    matched_grants: list[PermissionGrantResponse]
    total_reachable_assets: int
    summary: str

    @classmethod
    def from_domain(
        cls, result: BlastRadiusResult
    ) -> "BlastRadiusAnalysisResponse":
        """Convert an existing blast-radius result to its API form."""

        return cls(
            subject=result.subject,
            reachable_assets=[
                CloudAssetResponse(
                    asset_id=asset.asset_id,
                    asset_type=asset.asset_type.value,
                    provider=asset.provider,
                    account_id=asset.account_id,
                    region=asset.region,
                    name=asset.name,
                    arn=asset.arn,
                    native_identifier=asset.native_identifier,
                    metadata=_json_object(asset.metadata),
                )
                for asset in result.reachable_assets
            ],
            matched_grants=[
                PermissionGrantResponse(
                    subject=grant.subject,
                    actions=list(grant.actions),
                    resources=list(grant.resources),
                    effect=grant.effect.value,
                    source=grant.source,
                )
                for grant in result.matched_grants
            ],
            total_reachable_assets=result.total_reachable_assets,
            summary=result.summary,
        )


class BlastRadiusUnavailableResponse(BaseModel):
    """Explicit indication that no cloud context is configured."""

    available: Literal[False] = False
    reason: str


BlastRadiusResponse: TypeAlias = (
    BlastRadiusAnalysisResponse | BlastRadiusUnavailableResponse
)


class RecommendationResponse(BaseModel):
    """One deterministic investigation recommendation."""

    recommendation_id: str
    title: str
    description: str
    priority: str
    rationale: str


class GuidanceResponse(BaseModel):
    """Deterministic investigation guidance response."""

    recommendations: list[RecommendationResponse]
    summary: str

    @classmethod
    def from_domain(cls, guidance: InvestigationGuidance) -> "GuidanceResponse":
        """Convert existing guidance to selected response fields."""

        return cls(
            recommendations=[
                RecommendationResponse(
                    recommendation_id=recommendation.recommendation_id,
                    title=recommendation.title,
                    description=recommendation.description,
                    priority=recommendation.priority.value,
                    rationale=recommendation.rationale,
                )
                for recommendation in guidance.recommendations
            ],
            summary=guidance.summary,
        )


def _json_object(value: Mapping[str, object]) -> dict[str, ApiJsonValue]:
    return {key: _json_value(item) for key, item in value.items()}


def _json_value(value: object) -> ApiJsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return _json_object(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    raise TypeError(f"Unsupported API metadata value: {type(value).__name__}")


class CapabilitiesResponse(BaseModel):
    """Web-analysis capabilities of this API instance."""

    file_analysis: bool
    s3_analysis: bool
    demo_mode: bool = False


class S3AnalysisRequest(BaseModel):
    """Explicit S3 CloudTrail object to analyze.

    Authentication always uses the backend's boto3 provider chain; this
    request carries no AWS credentials and any extra fields are rejected.
    """

    model_config = ConfigDict(extra="forbid")

    bucket: str = Field(min_length=1, max_length=253)
    key: str = Field(min_length=1, max_length=1024)
    version_id: str | None = Field(default=None, max_length=256)
    region: str | None = Field(default=None, max_length=64)
    source_label: str | None = Field(default=None, max_length=256)


class IngestionIssueResponse(BaseModel):
    """One safe per-record diagnostic from an analysis operation."""

    record_index: int
    code: str
    event_id: str | None = None


class AnalysisResponse(BaseModel):
    """Safe stage counts for one completed web analysis operation.

    Raw CloudTrail events are never included; only counts, stable issue
    diagnostics, and the identifiers of persisted incidents are exposed.
    """

    source_label: str | None = None
    total_records: int
    accepted_records: int
    failed_records: int
    duplicate_records: int
    events_analyzed: int
    signals: int
    correlations: int
    incidents_created: int
    persisted_incidents: int
    incident_ids: list[str]
    issues: list[IngestionIssueResponse]

    @classmethod
    def from_result(cls, result: InvestigationExecutionResult) -> "AnalysisResponse":
        """Convert a pipeline result to safe response counts."""

        ingestion = result.ingestion_result
        return cls(
            source_label=ingestion.source_label,
            total_records=ingestion.total_records,
            accepted_records=ingestion.accepted_records,
            failed_records=ingestion.failed_records,
            duplicate_records=ingestion.duplicate_records,
            events_analyzed=result.analyzed_event_count,
            signals=result.signal_count,
            correlations=result.correlation_count,
            incidents_created=result.incident_count,
            persisted_incidents=result.persisted_incident_count,
            incident_ids=[
                incident.incident_id for incident in result.persisted_incidents
            ],
            issues=[
                IngestionIssueResponse(
                    record_index=issue.record_index,
                    code=issue.code.value,
                    event_id=issue.event_id,
                )
                for issue in ingestion.issues
            ],
        )


class DemoResetResponse(BaseModel):
    """Result of resetting the local demo workspace.

    Only served by the opt-in demo application; the production API never
    exposes a reset capability.
    """

    status: Literal["ok"]
    incidents: int


class ClearWorkspaceResponse(BaseModel):
    """Result of clearing the current TrailWeaver investigation workspace.

    Only persisted incidents and their related investigation rows are
    removed. Source files, AWS resources, and the database file itself are
    never affected.
    """

    status: Literal["ok"]
    incidents: int
