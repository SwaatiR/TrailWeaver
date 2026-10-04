"""Read-only evidence provenance for investigations.

Provenance answers where the evidence in an incident was recorded: which
recorded analysis runs observed the identified events behind each signal.
It never claims which run created or owns an incident; no such persistent
relationship exists.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from trailweaver.analysis_runs import (
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.incidents import Incident
from trailweaver.signals import Signal


class _IncidentSource(Protocol):
    """Narrow read surface an incident store provides for provenance."""

    def get_incident(self, incident_id: str) -> Incident | None: ...


class _RunSource(Protocol):
    """Narrow read surface a run store provides for provenance."""

    def get_run(self, analysis_run_id: str) -> AnalysisRunRecord | None: ...

    def list_runs(self) -> tuple[AnalysisRunRecord, ...]: ...


class _LedgerSnapshot(Protocol):
    """Narrow read surface an event ledger provides for provenance."""

    def recorded_observations(
        self,
    ) -> dict[tuple[str, str], tuple[datetime | None, tuple[str, ...]]]: ...


class ObservationState(StrEnum):
    """How much recorded observation history exists for one evidence item."""

    RECORDED = "recorded"
    HISTORY_UNAVAILABLE = "history_unavailable"
    IDENTITY_UNAVAILABLE = "identity_unavailable"


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservingRun:
    """One recorded analysis run associated with incident evidence."""

    analysis_run_id: str
    source_type: AnalysisSourceType
    source_label: str | None
    status: AnalysisRunStatus
    started_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceProvenance:
    """Recorded observation history for one incident evidence signal."""

    signal_id: str
    rule_id: str
    title: str
    provider: str
    event_id: str | None
    event_time: datetime
    observation_state: ObservationState
    first_recorded_at: datetime | None
    observed_run_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProvenanceSummary:
    """Aggregate counts describing an incident's recorded provenance."""

    evidence_signal_count: int
    identified_event_count: int
    identified_events_with_recorded_observations: int
    unidentified_signal_count: int
    observing_run_count: int
    source_types: tuple[str, ...] = ()
    event_time_start: datetime | None = None
    event_time_end: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class IncidentProvenance:
    """Read-only recorded provenance for one incident's evidence."""

    incident_id: str
    summary: ProvenanceSummary
    observing_runs: tuple[ObservingRun, ...] = ()
    evidence: tuple[EvidenceProvenance, ...] = ()


class IncidentProvenanceRepository(Protocol):
    """Read-only recorded provenance for incident evidence."""

    def get_incident_provenance(
        self, incident_id: str
    ) -> IncidentProvenance | None:
        """Return provenance, or None only when the incident itself is absent."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ProvenanceObservation:
    """Durable observation facts for one identified event."""

    first_recorded_at: datetime | None = None
    run_ids: tuple[str, ...] = field(default_factory=tuple)


def build_incident_provenance(
    incident: Incident,
    run_records: Mapping[str, AnalysisRunRecord],
    observations: Mapping[tuple[str, str], ProvenanceObservation],
    run_sequence: Mapping[str, int] | None = None,
) -> IncidentProvenance:
    """Fold ordered incident signals with observation facts into provenance.

    Signals keep persisted position order; observing runs order by run
    start time with the durable insertion sequence as tie-breaker. Runs
    referenced by observations but missing from ``run_records`` are
    skipped without failing the whole response. ``run_sequence`` carries
    the durable insertion order (SQLite ``analysis_runs.sequence`` or the
    in-memory ledger order); callers must provide it so ordering never
    depends on lexical run-ID comparison.

    ``first_recorded_at`` is the durable first-seen fact and is reported
    whenever an events row exists — including when no run association
    survives (``history_unavailable``). It never implies a first observing
    run.
    """

    evidence_sketches: list[tuple[Signal, ObservationState, datetime | None, set[str]]] = []
    event_times: list[datetime] = []
    identified = 0
    identified_recorded = 0

    for signal in incident.correlation_match.signals:
        event = signal.source_event
        event_times.append(event.timestamp)
        observation = _lookup_observation(observations, event.provider, event.event_id)
        first_recorded: datetime | None = None
        run_ids: set[str] = set()
        if event.event_id is None:
            state = ObservationState.IDENTITY_UNAVAILABLE
        elif observation is None:
            state = ObservationState.HISTORY_UNAVAILABLE
        elif not observation.run_ids:
            # An events row exists but no run association survives:
            # recorded run history is unavailable, yet the first-recorded
            # fact itself remains reportable.
            state = ObservationState.HISTORY_UNAVAILABLE
            first_recorded = observation.first_recorded_at
        else:
            state = ObservationState.RECORDED
            first_recorded = observation.first_recorded_at
            run_ids = set(observation.run_ids)
            identified_recorded += 1
        if event.event_id is not None:
            identified += 1
        evidence_sketches.append((signal, state, first_recorded, run_ids))

    # Global observing-run order first: by run start time, then the
    # durable insertion sequence. Runs referenced by observations but
    # missing from run records are skipped without failing the whole
    # response. Sequenced runs always sort before unsequenced ones with
    # an equal start time; the trailing run ID only breaks exact ties
    # deterministically and is never semantic ordering.
    sequence = run_sequence or {}

    def _run_order_key(run_id: str) -> tuple[datetime, int, int, str]:
        if run_id in sequence:
            return (run_records[run_id].started_at, 0, sequence[run_id], run_id)
        return (run_records[run_id].started_at, 1, 0, run_id)

    global_run_order = sorted(
        {
            run_id
            for _, _, _, run_ids in evidence_sketches
            for run_id in run_ids
            if run_id in run_records
        },
        key=_run_order_key,
    )
    observing_runs = tuple(
        ObservingRun(
            analysis_run_id=run_id,
            source_type=run_records[run_id].source_type,
            source_label=run_records[run_id].source_label,
            status=run_records[run_id].status,
            started_at=run_records[run_id].started_at,
            finished_at=run_records[run_id].finished_at,
        )
        for run_id in global_run_order
    )
    source_types: list[str] = []
    for run_id in global_run_order:
        source_value = run_records[run_id].source_type.value
        if source_value not in source_types:
            source_types.append(source_value)

    evidence_items: list[EvidenceProvenance] = []
    for signal, state, first_recorded, run_ids in evidence_sketches:
        event = signal.source_event
        ordered_ids = [run_id for run_id in global_run_order if run_id in run_ids]
        ordered_ids.extend(sorted(run_ids - set(global_run_order)))
        evidence_items.append(
            EvidenceProvenance(
                signal_id=signal.signal_id,
                rule_id=signal.rule_id,
                title=signal.title,
                provider=event.provider,
                event_id=event.event_id,
                event_time=event.timestamp,
                observation_state=state,
                first_recorded_at=first_recorded,
                observed_run_ids=tuple(ordered_ids),
            )
        )
    return IncidentProvenance(
        incident_id=incident.incident_id,
        summary=ProvenanceSummary(
            evidence_signal_count=len(evidence_items),
            identified_event_count=identified,
            identified_events_with_recorded_observations=identified_recorded,
            unidentified_signal_count=len(evidence_items) - identified,
            observing_run_count=len(observing_runs),
            source_types=tuple(source_types),
            event_time_start=min(event_times) if event_times else None,
            event_time_end=max(event_times) if event_times else None,
        ),
        observing_runs=observing_runs,
        evidence=tuple(evidence_items),
    )


def _lookup_observation(
    observations: Mapping[tuple[str, str], ProvenanceObservation],
    provider: str,
    event_id: str | None,
) -> ProvenanceObservation | None:
    if event_id is None:
        return None
    return observations.get((provider, event_id))


class InMemoryProvenanceReader:
    """Compose incident provenance from in-memory incident/run/ledger state.

    Mirrors the SQLite read without duplicating its SQL: the incident comes
    from the incident repository, run records resolve by ID, and observation
    facts come from the event ledger snapshot.
    """

    def __init__(
        self,
        incidents: _IncidentSource,
        runs: _RunSource,
        ledger: _LedgerSnapshot,
    ) -> None:
        self._incidents = incidents
        self._runs = runs
        self._ledger = ledger

    def get_incident_provenance(
        self, incident_id: str
    ) -> IncidentProvenance | None:
        """Return provenance, or None only when the incident itself is absent."""

        incident = self._incidents.get_incident(incident_id)
        if incident is None:
            return None
        # Scope the ledger snapshot to this incident's identified events so
        # surviving-but-unrelated run history can never leak into the
        # response (demo replay depends on this).
        wanted_keys = {
            (signal.source_event.provider, signal.source_event.event_id)
            for signal in incident.correlation_match.signals
            if signal.source_event.event_id is not None
        }
        snapshot = self._ledger.recorded_observations()
        observations = {
            key: ProvenanceObservation(
                first_recorded_at=first_seen, run_ids=run_ids
            )
            for key, (first_seen, run_ids) in snapshot.items()
            if key in wanted_keys
        }
        wanted_runs = {
            run_id
            for observation in observations.values()
            for run_id in observation.run_ids
        }
        run_records = {}
        for run_id in wanted_runs:
            record = self._runs.get_run(run_id)
            if record is not None:
                run_records[run_id] = record
        # Durable insertion order from the run ledger is the deterministic
        # tie-breaker after run start time; it never depends on run-ID text.
        run_sequence = {
            record.analysis_run_id: index
            for index, record in enumerate(self._runs.list_runs())
            if record.analysis_run_id in run_records
        }
        return build_incident_provenance(
            incident,
            run_records=run_records,
            observations=observations,
            run_sequence=run_sequence,
        )
