"""Application services and incident repository contracts for the HTTP API."""

from collections.abc import Iterable
from typing import Protocol

from trailweaver.attack_graph import AttackGraph, AttackGraphBuilder
from trailweaver.blast_radius import BlastRadiusAnalyzer, BlastRadiusResult
from trailweaver.cloud_context import CloudContext
from trailweaver.incidents import Incident
from trailweaver.investigation import InvestigationAdvisor, InvestigationGuidance
from trailweaver.mitre import MitreMapper, MitreMapping
from trailweaver.risk import RiskAssessment, RiskScorer


class IncidentRepository(Protocol):
    """Access to existing incidents and insert-only incident storage."""

    def list_incidents(self) -> tuple[Incident, ...]:
        """Return the available incidents in stable order."""

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an incident by exact ID, if it exists."""

    def save_incident(self, incident: Incident) -> None:
        """Insert an incident, failing if its ID already exists."""


class IncidentAlreadyExistsError(ValueError):
    """Raised when a repository is asked to insert an existing incident ID."""


class InMemoryIncidentRepository:
    """An explicit process-local incident source with insert-only save semantics."""

    def __init__(self, incidents: Iterable[Incident] = ()) -> None:
        incident_items = tuple(incidents)
        incidents_by_id = {incident.incident_id: incident for incident in incident_items}
        if len(incidents_by_id) != len(incident_items):
            raise ValueError("Incident IDs must be unique")
        self._incidents = incident_items
        self._incidents_by_id = incidents_by_id

    def list_incidents(self) -> tuple[Incident, ...]:
        """Return the incident snapshot supplied during construction."""

        return self._incidents

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an incident by exact ID, if it exists."""

        return self._incidents_by_id.get(incident_id)

    def save_incident(self, incident: Incident) -> None:
        """Append a new incident without replacing any existing evidence."""

        if incident.incident_id in self._incidents_by_id:
            raise IncidentAlreadyExistsError(
                f"Incident {incident.incident_id!r} already exists"
            )
        self._incidents = (*self._incidents, incident)
        self._incidents_by_id[incident.incident_id] = incident


class IncidentNotFoundError(LookupError):
    """Raised when an application request references an unknown incident."""


class IncidentAnalysisService:
    """Compose existing TrailWeaver analysis components for API consumers."""

    def __init__(
        self,
        repository: IncidentRepository,
        *,
        cloud_context: CloudContext | None = None,
        risk_scorer: RiskScorer | None = None,
        mitre_mapper: MitreMapper | None = None,
        graph_builder: AttackGraphBuilder | None = None,
        blast_radius_analyzer: BlastRadiusAnalyzer | None = None,
        investigation_advisor: InvestigationAdvisor | None = None,
    ) -> None:
        self._repository = repository
        self._cloud_context = cloud_context
        self._risk_scorer = risk_scorer if risk_scorer is not None else RiskScorer()
        self._mitre_mapper = mitre_mapper if mitre_mapper is not None else MitreMapper()
        self._graph_builder = (
            graph_builder if graph_builder is not None else AttackGraphBuilder()
        )
        self._blast_radius_analyzer = (
            blast_radius_analyzer
            if blast_radius_analyzer is not None
            else BlastRadiusAnalyzer()
        )
        self._investigation_advisor = (
            investigation_advisor
            if investigation_advisor is not None
            else InvestigationAdvisor()
        )

    @property
    def has_cloud_context(self) -> bool:
        """Return whether blast-radius analysis is configured."""

        return self._cloud_context is not None

    def list_incidents(self) -> tuple[Incident, ...]:
        """Return all incidents from the configured source."""

        return self._repository.list_incidents()

    def get_incident(self, incident_id: str) -> Incident:
        """Return one incident or raise a transport-neutral lookup error."""

        incident = self._repository.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        return incident

    def assess_risk(self, incident_id: str) -> RiskAssessment:
        """Delegate risk assessment to the existing deterministic scorer."""

        return self._risk_scorer.score(self.get_incident(incident_id))

    def map_mitre(self, incident_id: str) -> MitreMapping:
        """Delegate ATT&CK mapping to the existing deterministic mapper."""

        return self._mitre_mapper.map(self.get_incident(incident_id))

    def build_graph(self, incident_id: str) -> AttackGraph:
        """Delegate graph construction to the existing attack-graph builder."""

        return self._graph_builder.build(self.get_incident(incident_id))

    def analyze_blast_radius(self, incident_id: str) -> BlastRadiusResult | None:
        """Return analysis when context is configured, otherwise return unavailable."""

        incident = self.get_incident(incident_id)
        if self._cloud_context is None:
            return None
        return self._blast_radius_analyzer.analyze(incident, self._cloud_context)

    def provide_guidance(self, incident_id: str) -> InvestigationGuidance:
        """Return existing deterministic guidance with available derived context."""

        incident = self.get_incident(incident_id)
        risk_assessment = self._risk_scorer.score(incident)
        blast_radius = (
            None
            if self._cloud_context is None
            else self._blast_radius_analyzer.analyze(incident, self._cloud_context)
        )
        return self._investigation_advisor.advise(
            incident,
            risk_assessment=risk_assessment,
            blast_radius=blast_radius,
        )
