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
