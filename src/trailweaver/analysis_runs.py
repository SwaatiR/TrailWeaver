"""Completed analysis-run identity and safe provenance."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import uuid4


class AnalysisSourceType(StrEnum):
    """The supported source categories for an analysis invocation."""

    LOCAL_FILE = "local_file"
    WEB_UPLOAD = "web_upload"
    S3_OBJECT = "s3_object"
    DIRECT_INPUT = "direct_input"


class AnalysisRunStatus(StrEnum):
    """The durable lifecycle states of a normalized-analysis attempt."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class AnalysisFailurePhase(StrEnum):
    """The normalized-analysis phase in which an attempt failed."""

    EVENT_ORDERING = "event_ordering"
    DETECTION = "detection"
    CORRELATION = "correlation"
    INCIDENT_CREATION = "incident_creation"
    INCIDENT_PERSISTENCE = "incident_persistence"


def _generate_analysis_run_id() -> str:
    return str(uuid4())


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisRun:
    """An immutable summary of one successfully completed analysis invocation."""

    source_type: AnalysisSourceType
    source_label: str | None
    started_at: datetime
    completed_at: datetime
    records_seen: int
    records_accepted: int
    signals_created: int
    correlations_created: int
    incidents_created: int
    analysis_run_id: str = field(default_factory=_generate_analysis_run_id)

    def __post_init__(self) -> None:
        if not self.analysis_run_id.strip():
            raise ValueError("analysis_run_id must be non-empty")
        if self.source_label is not None and not self.source_label.strip():
            raise ValueError("source_label must be non-empty when provided")
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("started_at must be timezone-aware")
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("completed_at must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not be before started_at")

        counts = (
            self.records_seen,
            self.records_accepted,
            self.signals_created,
            self.correlations_created,
            self.incidents_created,
        )
        if any(count < 0 for count in counts):
            raise ValueError("analysis run counts must be non-negative")
        if self.records_accepted > self.records_seen:
            raise ValueError("records_accepted must not exceed records_seen")


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisRunRecord:
    """An immutable durable lifecycle snapshot of one normalized-analysis attempt.

    ``source_label`` is bounded display provenance. It may contain operational
    naming information, but never source evidence, credentials, or transport metadata.
    """

    analysis_run_id: str
    source_type: AnalysisSourceType
    source_label: str | None
    status: AnalysisRunStatus
    started_at: datetime
    finished_at: datetime | None
    records_seen: int
    records_accepted: int
    signals_created: int | None
    correlations_created: int | None
    incidents_created: int | None
    failure_phase: AnalysisFailurePhase | None

    def __post_init__(self) -> None:
        if not isinstance(self.source_type, AnalysisSourceType):
            raise TypeError("source_type must be an AnalysisSourceType")
        if not isinstance(self.status, AnalysisRunStatus):
            raise TypeError("status must be an AnalysisRunStatus")
        if self.failure_phase is not None and not isinstance(
            self.failure_phase, AnalysisFailurePhase
        ):
            raise TypeError("failure_phase must be an AnalysisFailurePhase")
        if not self.analysis_run_id.strip():
            raise ValueError("analysis_run_id must be non-empty")
        if self.source_label is not None:
            if not self.source_label.strip():
                raise ValueError("source_label must be non-empty when provided")
            if len(self.source_label) > 256:
                raise ValueError("source_label must not exceed 256 characters")
            if not self.source_label.isprintable():
                raise ValueError("source_label must contain only printable characters")
        _require_aware(self.started_at, "started_at")
        if self.finished_at is not None:
            _require_aware(self.finished_at, "finished_at")
            if self.finished_at < self.started_at:
                raise ValueError("finished_at must not be before started_at")

        counts = (
            self.records_seen,
            self.records_accepted,
            self.signals_created,
            self.correlations_created,
            self.incidents_created,
        )
        if any(count is not None and count < 0 for count in counts):
            raise ValueError("analysis run counts must be non-negative")
        if self.records_accepted > self.records_seen:
            raise ValueError("records_accepted must not exceed records_seen")

        outputs = (
            self.signals_created,
            self.correlations_created,
            self.incidents_created,
        )
        if self.status is AnalysisRunStatus.RUNNING:
            if self.finished_at is not None or any(count is not None for count in outputs):
                raise ValueError("running analysis runs cannot contain terminal outputs")
            if self.failure_phase is not None:
                raise ValueError("running analysis runs cannot contain a failure phase")
        elif self.status is AnalysisRunStatus.COMPLETED:
            if self.finished_at is None or any(count is None for count in outputs):
                raise ValueError("completed analysis runs require terminal output counts")
            if self.failure_phase is not None:
                raise ValueError("completed analysis runs cannot contain a failure phase")
        elif self.status is AnalysisRunStatus.FAILED:
            if self.finished_at is None or self.failure_phase is None:
                raise ValueError("failed analysis runs require a finish time and failure phase")
            expected_outputs = {
                AnalysisFailurePhase.EVENT_ORDERING: (None, None, None),
                AnalysisFailurePhase.DETECTION: (None, None, None),
                AnalysisFailurePhase.CORRELATION: (self.signals_created, None, None),
                AnalysisFailurePhase.INCIDENT_CREATION: (
                    self.signals_created,
                    self.correlations_created,
                    None,
                ),
                AnalysisFailurePhase.INCIDENT_PERSISTENCE: outputs,
            }[self.failure_phase]
            if outputs != expected_outputs:
                raise ValueError("failed analysis run counts do not match its failure phase")
            required_count = {
                AnalysisFailurePhase.EVENT_ORDERING: 0,
                AnalysisFailurePhase.DETECTION: 0,
                AnalysisFailurePhase.CORRELATION: 1,
                AnalysisFailurePhase.INCIDENT_CREATION: 2,
                AnalysisFailurePhase.INCIDENT_PERSISTENCE: 3,
            }[self.failure_phase]
            if any(count is None for count in outputs[:required_count]):
                raise ValueError("failed analysis run is missing a known stage count")
        elif self.status is AnalysisRunStatus.INTERRUPTED:
            # INTERRUPTED classifies an inherited unfinished lifecycle; it is
            # not proof of a crash, and the classification time is not the
            # interruption time. Output counts and failure phase are unknown
            # and must never be reconstructed or inferred.
            if self.finished_at is None:
                raise ValueError("interrupted analysis runs require a classification time")
            if any(count is not None for count in outputs):
                raise ValueError("interrupted analysis runs cannot contain output counts")
            if self.failure_phase is not None:
                raise ValueError("interrupted analysis runs cannot contain a failure phase")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
