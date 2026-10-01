"""Synchronous application orchestration for CloudTrail investigations."""

from dataclasses import dataclass
from os import PathLike

from trailweaver.api.service import IncidentRepository
from trailweaver.cloudtrail_ingestion import (
    DEFAULT_MAX_SOURCE_BYTES,
    CloudTrailIngestionResult,
    ingest_cloudtrail_file,
    ingest_cloudtrail_json,
)
from trailweaver.correlation import CorrelationEngine, CorrelationMatch
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.models import NormalizedEvent
from trailweaver.rules import AWS_RULES
from trailweaver.signals import Signal


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationExecutionResult:
    """Evidence and stage outputs from one completed investigation execution."""

    ingestion_result: CloudTrailIngestionResult
    analyzed_events: tuple[NormalizedEvent, ...]
    signals: tuple[Signal, ...]
    correlations: tuple[CorrelationMatch, ...]
    incidents: tuple[Incident, ...]
    persisted_incidents: tuple[Incident, ...]

    @property
    def analyzed_event_count(self) -> int:
        return len(self.analyzed_events)

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def correlation_count(self) -> int:
        return len(self.correlations)

    @property
    def incident_count(self) -> int:
        return len(self.incidents)

    @property
    def persisted_incident_count(self) -> int:
        return len(self.persisted_incidents)


class InvestigationRunner:
    """Coordinate ingestion, analysis, incident creation, and persistence."""

    def __init__(
        self,
        *,
        detection_engine: DetectionEngine,
        correlation_engine: CorrelationEngine,
        incident_factory: IncidentFactory,
        incident_repository: IncidentRepository,
    ) -> None:
        self._detection_engine = detection_engine
        self._correlation_engine = correlation_engine
        self._incident_factory = incident_factory
        self._incident_repository = incident_repository

    def run_cloudtrail_json(
        self,
        source: str | bytes,
        *,
        source_label: str | None = None,
        max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    ) -> InvestigationExecutionResult:
        """Ingest JSON text or bytes and run the accepted events through the pipeline."""

        ingestion_result = ingest_cloudtrail_json(
            source,
            source_label=source_label,
            max_source_bytes=max_source_bytes,
        )
        return self.run_ingestion_result(ingestion_result)

    def run_cloudtrail_file(
        self,
        path: str | PathLike[str],
        *,
        source_label: str | None = None,
        max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    ) -> InvestigationExecutionResult:
        """Ingest one read-only file and run the accepted events through the pipeline."""

        ingestion_result = ingest_cloudtrail_file(
            path,
            source_label=source_label,
            max_source_bytes=max_source_bytes,
        )
        return self.run_ingestion_result(ingestion_result)

    def run_ingestion_result(
        self, ingestion_result: CloudTrailIngestionResult
    ) -> InvestigationExecutionResult:
        """Analyze and persist the accepted events from an existing M20 result."""

        analyzed_events = _order_events_for_analysis(ingestion_result.events)
        signals = tuple(
            signal
            for event in analyzed_events
            for signal in self._detection_engine.evaluate(event)
        )
        correlations = self._correlation_engine.evaluate(signals)
        incidents = tuple(
            self._incident_factory.create(correlation)
            for correlation in correlations
        )

        persisted_incidents: list[Incident] = []
        for incident in incidents:
            self._incident_repository.save_incident(incident)
            persisted_incidents.append(incident)

        return InvestigationExecutionResult(
            ingestion_result=ingestion_result,
            analyzed_events=analyzed_events,
            signals=signals,
            correlations=correlations,
            incidents=incidents,
            persisted_incidents=tuple(persisted_incidents),
        )


def create_default_investigation_runner(
    incident_repository: IncidentRepository,
) -> InvestigationRunner:
    """Return the canonical runner configured with TrailWeaver's AWS rule packs."""

    return InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incident_repository,
    )


def _order_events_for_analysis(
    events: tuple[NormalizedEvent, ...],
) -> tuple[NormalizedEvent, ...]:
    """Order by evidence time while retaining source order for equal timestamps."""

    return tuple(
        event
        for _, event in sorted(
            enumerate(events),
            key=lambda item: (item[1].timestamp, item[0]),
        )
    )
