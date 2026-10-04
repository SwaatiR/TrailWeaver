"""Repository contract and process-local storage for analysis-run lifecycle records."""

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from trailweaver.analysis_runs import (
    AnalysisFailurePhase,
    AnalysisRun,
    AnalysisRunRecord,
    AnalysisRunStatus,
)


class AnalysisRunRepository(Protocol):
    """Persist lifecycle snapshots for normalized-analysis attempts."""

    def start_run(self, record: AnalysisRunRecord) -> None:
        """Insert a new RUNNING record and reject duplicate IDs."""

    def complete_run(self, run: AnalysisRun) -> None:
        """Atomically transition the matching RUNNING record to COMPLETED."""

    def fail_run(
        self,
        analysis_run_id: str,
        *,
        failed_at: datetime,
        failure_phase: AnalysisFailurePhase,
        signals_created: int | None = None,
        correlations_created: int | None = None,
        incidents_created: int | None = None,
    ) -> None:
        """Atomically transition the matching RUNNING record to FAILED."""

    def get_run(self, analysis_run_id: str) -> AnalysisRunRecord | None:
        """Return one lifecycle record by exact ID."""

    def list_runs(self) -> tuple[AnalysisRunRecord, ...]:
        """Return lifecycle records in stable insertion order."""


class DuplicateAnalysisRunError(ValueError):
    """Raised when a ledger already contains the requested analysis-run ID."""


class InvalidAnalysisRunTransitionError(ValueError):
    """Raised when a lifecycle transition is missing, incompatible, or terminal."""


class AnalysisRunRepositoryError(RuntimeError):
    """Raised when durable analysis-run storage is unavailable."""


class InvalidStoredAnalysisRunError(AnalysisRunRepositoryError):
    """Raised when stored lifecycle data cannot reconstruct a valid record."""


class InMemoryAnalysisRunRepository:
    """Process-local ledger with the same lifecycle semantics as durable storage."""

    def __init__(self, records: Iterable[AnalysisRunRecord] = ()) -> None:
        items = tuple(records)
        records_by_id = {record.analysis_run_id: record for record in items}
        if len(records_by_id) != len(items):
            raise ValueError("Analysis run IDs must be unique")
        self._records = items
        self._records_by_id = records_by_id

    def start_run(self, record: AnalysisRunRecord) -> None:
        if record.status is not AnalysisRunStatus.RUNNING:
            raise InvalidAnalysisRunTransitionError("start_run requires a RUNNING record")
        if record.analysis_run_id in self._records_by_id:
            raise DuplicateAnalysisRunError(
                f"Analysis run {record.analysis_run_id!r} already exists"
            )
        self._records = (*self._records, record)
        self._records_by_id[record.analysis_run_id] = record

    def complete_run(self, run: AnalysisRun) -> None:
        current = self._running_record(run.analysis_run_id)
        _validate_completion_identity(current, run)
        self._replace(
            AnalysisRunRecord(
                analysis_run_id=run.analysis_run_id,
                source_type=run.source_type,
                source_label=run.source_label,
                status=AnalysisRunStatus.COMPLETED,
                started_at=run.started_at,
                finished_at=run.completed_at,
                records_seen=run.records_seen,
                records_accepted=run.records_accepted,
                signals_created=run.signals_created,
                correlations_created=run.correlations_created,
                incidents_created=run.incidents_created,
                failure_phase=None,
            )
        )

    def fail_run(
        self,
        analysis_run_id: str,
        *,
        failed_at: datetime,
        failure_phase: AnalysisFailurePhase,
        signals_created: int | None = None,
        correlations_created: int | None = None,
        incidents_created: int | None = None,
    ) -> None:
        current = self._running_record(analysis_run_id)
        self._replace(
            AnalysisRunRecord(
                analysis_run_id=current.analysis_run_id,
                source_type=current.source_type,
                source_label=current.source_label,
                status=AnalysisRunStatus.FAILED,
                started_at=current.started_at,
                finished_at=failed_at,
                records_seen=current.records_seen,
                records_accepted=current.records_accepted,
                signals_created=signals_created,
                correlations_created=correlations_created,
                incidents_created=incidents_created,
                failure_phase=failure_phase,
            )
        )

    def get_run(self, analysis_run_id: str) -> AnalysisRunRecord | None:
        return self._records_by_id.get(analysis_run_id)

    def list_runs(self) -> tuple[AnalysisRunRecord, ...]:
        return self._records

    def _running_record(self, analysis_run_id: str) -> AnalysisRunRecord:
        current = self._records_by_id.get(analysis_run_id)
        if current is None:
            raise InvalidAnalysisRunTransitionError(
                f"Analysis run {analysis_run_id!r} does not exist"
            )
        if current.status is not AnalysisRunStatus.RUNNING:
            raise InvalidAnalysisRunTransitionError(
                f"Analysis run {analysis_run_id!r} is already terminal"
            )
        return current

    def _replace(self, record: AnalysisRunRecord) -> None:
        self._records = tuple(
            record if item.analysis_run_id == record.analysis_run_id else item
            for item in self._records
        )
        self._records_by_id[record.analysis_run_id] = record


def validate_completion_identity(record: AnalysisRunRecord, run: AnalysisRun) -> None:
    """Validate that a completed fact belongs to its original RUNNING record."""

    _validate_completion_identity(record, run)


def _validate_completion_identity(record: AnalysisRunRecord, run: AnalysisRun) -> None:
    if (
        record.analysis_run_id != run.analysis_run_id
        or record.source_type is not run.source_type
        or record.source_label != run.source_label
        or record.started_at != run.started_at
        or record.records_seen != run.records_seen
        or record.records_accepted != run.records_accepted
    ):
        raise InvalidAnalysisRunTransitionError(
            "Completed analysis run is incompatible with its RUNNING record"
        )
