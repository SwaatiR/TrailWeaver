"""Synchronous application orchestration for CloudTrail investigations."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from os import PathLike

from trailweaver.analysis_runs import AnalysisRun, AnalysisSourceType
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
from trailweaver.observability import log_event, safe_source_label
from trailweaver.rules import AWS_RULES
from trailweaver.signals import Signal

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationExecutionResult:
    """Evidence and stage outputs from one completed investigation execution."""

    analysis_run: AnalysisRun
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
        source_type: AnalysisSourceType = AnalysisSourceType.DIRECT_INPUT,
    ) -> InvestigationExecutionResult:
        """Ingest JSON text or bytes and run the accepted events through the pipeline."""

        ingestion_result = ingest_cloudtrail_json(
            source,
            source_label=source_label,
            max_source_bytes=max_source_bytes,
        )
        return self.run_ingestion_result(ingestion_result, source_type=source_type)

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
        return self.run_ingestion_result(
            ingestion_result,
            source_type=AnalysisSourceType.LOCAL_FILE,
        )

    def run_ingestion_result(
        self,
        ingestion_result: CloudTrailIngestionResult,
        *,
        source_type: AnalysisSourceType = AnalysisSourceType.DIRECT_INPUT,
    ) -> InvestigationExecutionResult:
        """Analyze and persist accepted events from an existing ingestion result.

        Analysis-run timing begins here, after source transport and document parsing,
        and completes only after the existing incident persistence sequence succeeds.
        """

        started_at = datetime.now(UTC)
        source = safe_source_label(ingestion_result.source_label)
        if source is not None and not source.strip():
            source = None
        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_started",
            source=source,
            source_records=ingestion_result.total_records,
            accepted=ingestion_result.accepted_records,
            failed=ingestion_result.failed_records,
            duplicates=ingestion_result.duplicate_records,
        )
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

        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_analyzed",
            source=source,
            events=len(analyzed_events),
            signals=len(signals),
            correlations=len(correlations),
            incidents=len(incidents),
        )

        persisted_incidents: list[Incident] = []
        try:
            for incident in incidents:
                self._incident_repository.save_incident(incident)
                persisted_incidents.append(incident)
        except Exception as error:
            log_event(
                _LOGGER,
                logging.ERROR,
                "incident_persistence_failed",
                source=source,
                persisted=len(persisted_incidents),
                expected=len(incidents),
                error_type=type(error).__name__,
            )
            raise

        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_completed",
            source=source,
            persisted=len(persisted_incidents),
        )

        analysis_run = AnalysisRun(
            source_type=source_type,
            source_label=source,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            records_seen=ingestion_result.total_records,
            records_accepted=ingestion_result.accepted_records,
            signals_created=len(signals),
            correlations_created=len(correlations),
            incidents_created=len(incidents),
        )

        return InvestigationExecutionResult(
            analysis_run=analysis_run,
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
