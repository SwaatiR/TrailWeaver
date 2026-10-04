"""Synchronous application orchestration for CloudTrail investigations."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from os import PathLike
from uuid import uuid4

from trailweaver.analysis_ledger import (
    AnalysisRunRepository,
    InMemoryAnalysisRunRepository,
)
from trailweaver.analysis_runs import (
    AnalysisFailurePhase,
    AnalysisRun,
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.service import IncidentRepository, SaveIncidentOutcome
from trailweaver.cloudtrail_ingestion import (
    DEFAULT_MAX_SOURCE_BYTES,
    CloudTrailIngestionResult,
    ingest_cloudtrail_file,
    ingest_cloudtrail_json,
)
from trailweaver.correlation import (
    CorrelationEngine,
    CorrelationMatch,
    actor_correlation_key,
    correlation_evidence_key,
)
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.event_ledger import (
    EventIdentity,
    EventLedgerRepository,
    InMemoryEventLedger,
)
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.models import NormalizedEvent
from trailweaver.observability import log_event, safe_source_label
from trailweaver.rules import AWS_RULES
from trailweaver.signal_history import InMemorySignalHistory, SignalHistoryRepository
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
        analysis_run_repository: AnalysisRunRepository | None = None,
        event_ledger_repository: EventLedgerRepository | None = None,
        signal_history_repository: SignalHistoryRepository | None = None,
    ) -> None:
        self._detection_engine = detection_engine
        self._correlation_engine = correlation_engine
        self._incident_factory = incident_factory
        self._incident_repository = incident_repository
        self._analysis_run_repository = (
            analysis_run_repository
            if analysis_run_repository is not None
            else InMemoryAnalysisRunRepository()
        )
        self._event_ledger_repository = (
            event_ledger_repository
            if event_ledger_repository is not None
            else InMemoryEventLedger()
        )
        self._signal_history_repository = (
            signal_history_repository
            if signal_history_repository is not None
            else InMemorySignalHistory()
        )

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
        analysis_run_id = str(uuid4())
        source = safe_source_label(ingestion_result.source_label)
        if source is not None and not source.strip():
            source = None
        self._analysis_run_repository.start_run(
            AnalysisRunRecord(
                analysis_run_id=analysis_run_id,
                source_type=source_type,
                source_label=source,
                status=AnalysisRunStatus.RUNNING,
                started_at=started_at,
                finished_at=None,
                records_seen=ingestion_result.total_records,
                records_accepted=ingestion_result.accepted_records,
                signals_created=None,
                correlations_created=None,
                incidents_created=None,
                failure_phase=None,
            )
        )
        # Persistent cross-run deduplication happens here, after the RUNNING
        # row exists and before any duplicate event can create new signals.
        # Events without a trustworthy provider ID are always processed and
        # never recorded. A ledger read failure propagates with no FAILED
        # row, mirroring a start_run failure: processing never began.
        identified = tuple(
            (event, EventIdentity.from_event(event))
            for event in ingestion_result.events
        )
        observed_identities = tuple(
            identity for _, identity in identified if identity is not None
        )
        known_identities = self._event_ledger_repository.known_identities(
            observed_identities
        )
        processable_events = tuple(
            event
            for event, identity in identified
            if identity is None or identity not in known_identities
        )
        events_new = sum(
            1
            for _, identity in identified
            if identity is not None and identity not in known_identities
        )
        events_duplicate = sum(
            1 for _, identity in identified if identity in known_identities
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_started",
            source=source,
            source_records=ingestion_result.total_records,
            accepted=ingestion_result.accepted_records,
            failed=ingestion_result.failed_records,
            duplicates=ingestion_result.duplicate_records,
            events_new=events_new,
            events_duplicate=events_duplicate,
        )
        try:
            analyzed_events = _order_events_for_analysis(processable_events)
        except Exception:
            self._record_failure(
                analysis_run_id,
                failure_phase=AnalysisFailurePhase.EVENT_ORDERING,
            )
            raise
        try:
            signals = tuple(
                signal
                for event in analyzed_events
                for signal in self._detection_engine.evaluate(event)
            )
        except Exception:
            self._record_failure(
                analysis_run_id,
                failure_phase=AnalysisFailurePhase.DETECTION,
            )
            raise
        # Cross-run correlation: historical candidates bounded by actor keys
        # and the rules' temporal window join this run's fresh signals. A
        # history read failure propagates with no FAILED row, mirroring a
        # ledger read failure: correlation never meaningfully began.
        historical_signals = self._load_historical_signals(signals)
        historical_ids = {id(signal) for signal in historical_signals}
        combined_signals = _deduplicate_signals(historical_signals, signals)
        try:
            correlations = self._correlation_engine.evaluate(combined_signals)
        except Exception:
            self._record_failure(
                analysis_run_id,
                failure_phase=AnalysisFailurePhase.CORRELATION,
                signals_created=len(signals),
            )
            raise
        try:
            incidents = tuple(
                self._incident_factory.create(correlation)
                for correlation in correlations
            )
        except Exception:
            self._record_failure(
                analysis_run_id,
                failure_phase=AnalysisFailurePhase.INCIDENT_CREATION,
                signals_created=len(signals),
                correlations_created=len(correlations),
            )
            raise

        persisted_incidents: list[Incident] = []
        novel_correlations: list[CorrelationMatch] = []
        try:
            for correlation, incident in zip(correlations, incidents):
                outcome = self._incident_repository.save_incident_if_correlation_new(
                    incident,
                    correlation_evidence_key(
                        correlation.rule_id, correlation.signals
                    ),
                )
                if outcome is SaveIncidentOutcome.CREATED:
                    persisted_incidents.append(incident)
                    novel_correlations.append(correlation)
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
            self._record_failure(
                analysis_run_id,
                failure_phase=AnalysisFailurePhase.INCIDENT_PERSISTENCE,
                signals_created=len(signals),
                correlations_created=len(correlations),
                incidents_created=len(incidents),
            )
            raise

        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_analyzed",
            source=source,
            events=len(analyzed_events),
            signals=len(signals),
            correlations=len(correlations),
            incidents=len(incidents),
            current_signals=len(signals),
            historical_candidates=len(historical_signals),
            cross_run_correlations=sum(
                1
                for match in novel_correlations
                if any(
                    id(signal) in historical_ids for signal in match.signals
                )
            ),
        )

        # Durable signal history covers this run's identified signals only
        # after incidents persist. A failure here propagates with no FAILED
        # row: the run did not fail in any M30 phase, persisted incidents
        # remain, and unacknowledged evidence stays retryable.
        self._signal_history_repository.store_signals(signals)

        analysis_run = AnalysisRun(
            analysis_run_id=analysis_run_id,
            source_type=source_type,
            source_label=source,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            records_seen=ingestion_result.total_records,
            records_accepted=ingestion_result.accepted_records,
            signals_created=len(signals),
            correlations_created=len(novel_correlations),
            incidents_created=len(persisted_incidents),
        )
        self._analysis_run_repository.complete_run(analysis_run)
        # Event identities are acknowledged only after successful processing:
        # observation provenance covers every identity-bearing event this run
        # observed, including ones already known and skipped. A failure here
        # propagates with no successful result; persisted incidents remain and
        # unacknowledged evidence stays retryable.
        self._event_ledger_repository.acknowledge_run_events(
            analysis_run_id=analysis_run_id,
            finished_at=analysis_run.completed_at,
            observed=observed_identities,
        )

        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_completed",
            source=source,
            persisted=len(persisted_incidents),
            events_new=events_new,
            events_duplicate=events_duplicate,
        )

        return InvestigationExecutionResult(
            analysis_run=analysis_run,
            ingestion_result=ingestion_result,
            analyzed_events=analyzed_events,
            signals=signals,
            correlations=tuple(novel_correlations),
            incidents=tuple(persisted_incidents),
            persisted_incidents=tuple(persisted_incidents),
        )

    def _load_historical_signals(
        self, signals: tuple[Signal, ...]
    ) -> tuple[Signal, ...]:
        """Load bounded historical candidates for the current signals.

        The lookup spans each rule's temporal window symmetrically around the
        current signals' event times, restricted to the actors those signals
        implicate, so out-of-order file arrival still completes sequences
        without scanning the whole history.
        """

        if not signals:
            return ()
        timestamps = [signal.timestamp for signal in signals]
        window = self._correlation_engine.history_window
        actors = {
            key
            for signal in signals
            if (key := actor_correlation_key(signal.source_event)) is not None
        }
        return self._signal_history_repository.candidate_signals(
            actors=actors,
            start=min(timestamps) - window,
            end=max(timestamps) + window,
        )

    def _record_failure(
        self,
        analysis_run_id: str,
        *,
        failure_phase: AnalysisFailurePhase,
        signals_created: int | None = None,
        correlations_created: int | None = None,
        incidents_created: int | None = None,
    ) -> None:
        """Best-effort terminal recording that never masks processing failures."""

        try:
            self._analysis_run_repository.fail_run(
                analysis_run_id,
                failed_at=datetime.now(UTC),
                failure_phase=failure_phase,
                signals_created=signals_created,
                correlations_created=correlations_created,
                incidents_created=incidents_created,
            )
        except Exception as error:  # noqa: BLE001 - secondary failure must never escape
            log_event(
                _LOGGER,
                logging.ERROR,
                "analysis_run_failure_recording_failed",
                analysis_run_id=analysis_run_id,
                failure_phase=failure_phase.value,
                error_type=type(error).__name__,
            )


def create_default_investigation_runner(
    incident_repository: IncidentRepository,
    analysis_run_repository: AnalysisRunRepository | None = None,
    event_ledger_repository: EventLedgerRepository | None = None,
    signal_history_repository: SignalHistoryRepository | None = None,
) -> InvestigationRunner:
    """Return the canonical runner configured with TrailWeaver's AWS rule packs."""

    return InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incident_repository,
        analysis_run_repository=(
            analysis_run_repository
            if analysis_run_repository is not None
            else InMemoryAnalysisRunRepository()
        ),
        event_ledger_repository=(
            event_ledger_repository
            if event_ledger_repository is not None
            else InMemoryEventLedger()
        ),
        signal_history_repository=(
            signal_history_repository
            if signal_history_repository is not None
            else InMemorySignalHistory()
        ),
    )


def _logical_signal_key(signal: Signal) -> tuple[str, str, str] | None:
    """Return the stable identity shared by re-detections of one signal."""

    event = signal.source_event
    if (
        event.event_id is None
        or not event.event_id.strip()
        or not event.provider
        or not event.provider.strip()
    ):
        return None
    return (event.provider, event.event_id, signal.rule_id)


def _deduplicate_signals(
    historical: tuple[Signal, ...], current: tuple[Signal, ...]
) -> tuple[Signal, ...]:
    """Combine history with fresh signals without duplicating logical copies.

    A retried run redetects events whose identities were never acknowledged;
    when the historical representation already exists, it wins because its
    signal ID may already participate in durable evidence. Signals without a
    trustworthy event ID can never collide and are always kept.
    """

    seen: set[tuple[str, str, str]] = set()
    combined: list[Signal] = []
    for signal in (*historical, *current):
        key = _logical_signal_key(signal)
        if key is None or key not in seen:
            combined.append(signal)
            if key is not None:
                seen.add(key)
    return tuple(combined)


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
