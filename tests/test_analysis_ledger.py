import sqlite3
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trailweaver.analysis_ledger import (
    DuplicateAnalysisRunError,
    InMemoryAnalysisRunRepository,
    InvalidAnalysisRunTransitionError,
)
from trailweaver.analysis_runs import (
    AnalysisFailurePhase,
    AnalysisRun,
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.demo import create_demo_incident
from trailweaver.api.sqlite_repository import (
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)

STARTED = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
FINISHED = STARTED + timedelta(seconds=2)


def _running(run_id: str = "run-1") -> AnalysisRunRecord:
    return AnalysisRunRecord(
        analysis_run_id=run_id,
        source_type=AnalysisSourceType.LOCAL_FILE,
        source_label="export.json",
        status=AnalysisRunStatus.RUNNING,
        started_at=STARTED,
        finished_at=None,
        records_seen=3,
        records_accepted=2,
        signals_created=None,
        correlations_created=None,
        incidents_created=None,
        failure_phase=None,
    )


def _completed(run_id: str = "run-1") -> AnalysisRun:
    return AnalysisRun(
        analysis_run_id=run_id,
        source_type=AnalysisSourceType.LOCAL_FILE,
        source_label="export.json",
        started_at=STARTED,
        completed_at=FINISHED,
        records_seen=3,
        records_accepted=2,
        signals_created=2,
        correlations_created=1,
        incidents_created=1,
    )


def test_analysis_run_record_valid_shapes_are_immutable() -> None:
    running = _running()
    completed = replace(
        running,
        status=AnalysisRunStatus.COMPLETED,
        finished_at=FINISHED,
        signals_created=2,
        correlations_created=1,
        incidents_created=1,
    )
    failed = replace(
        running,
        status=AnalysisRunStatus.FAILED,
        finished_at=FINISHED,
        signals_created=2,
        failure_phase=AnalysisFailurePhase.CORRELATION,
    )

    assert completed.status is AnalysisRunStatus.COMPLETED
    assert failed.failure_phase is AnalysisFailurePhase.CORRELATION
    with pytest.raises(FrozenInstanceError):
        running.status = AnalysisRunStatus.FAILED  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    (
        {"analysis_run_id": " "},
        {"started_at": datetime(2026, 10, 4, 10, 0)},  # noqa: DTZ001
        {"records_seen": -1},
        {"records_seen": 1, "records_accepted": 2},
        {"finished_at": FINISHED},
        {"signals_created": 0},
        {"failure_phase": AnalysisFailurePhase.DETECTION},
        {"source_label": "x" * 257},
        {"source_label": "line\nbreak"},
    ),
)
def test_running_record_rejects_invalid_values_and_terminal_fields(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(_running(), **changes)


def test_terminal_record_shapes_are_strict() -> None:
    with pytest.raises(ValueError, match="terminal output counts"):
        replace(_running(), status=AnalysisRunStatus.COMPLETED, finished_at=FINISHED)
    with pytest.raises(ValueError, match="failure phase"):
        replace(_running(), status=AnalysisRunStatus.FAILED, finished_at=FINISHED)
    with pytest.raises(ValueError, match="known stage count"):
        replace(
            _running(),
            status=AnalysisRunStatus.FAILED,
            finished_at=FINISHED,
            failure_phase=AnalysisFailurePhase.CORRELATION,
        )


def test_in_memory_lifecycle_order_get_duplicates_and_terminal_transitions() -> None:
    repository = InMemoryAnalysisRunRepository()
    repository.start_run(_running("z-first"))
    repository.start_run(_running("a-second"))

    assert tuple(record.analysis_run_id for record in repository.list_runs()) == (
        "z-first",
        "a-second",
    )
    assert repository.get_run("missing") is None
    with pytest.raises(DuplicateAnalysisRunError):
        repository.start_run(_running("z-first"))

    repository.complete_run(_completed("z-first"))
    repository.fail_run(
        "a-second",
        failed_at=FINISHED,
        failure_phase=AnalysisFailurePhase.DETECTION,
    )
    assert repository.get_run("z-first").status is AnalysisRunStatus.COMPLETED
    assert repository.get_run("a-second").status is AnalysisRunStatus.FAILED
    with pytest.raises(InvalidAnalysisRunTransitionError):
        repository.complete_run(_completed("z-first"))
    with pytest.raises(InvalidAnalysisRunTransitionError):
        repository.fail_run(
            "a-second",
            failed_at=FINISHED,
            failure_phase=AnalysisFailurePhase.DETECTION,
        )


def test_sqlite_run_round_trip_order_and_stale_running_survives_reopen(tmp_path) -> None:
    database = tmp_path / "ledger.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.start_run(_running("running"))
    repository.start_run(_running("completed"))
    repository.complete_run(_completed("completed"))

    reopened = SQLiteIncidentRepository(database)

    assert reopened.get_run("running") == _running("running")
    assert tuple(record.analysis_run_id for record in reopened.list_runs()) == (
        "running",
        "completed",
    )
    completed = reopened.get_run("completed")
    assert completed is not None
    assert completed.status is AnalysisRunStatus.COMPLETED
    assert completed.finished_at == FINISHED
    assert completed.signals_created == 2


def test_v1_database_migrates_atomically_and_preserves_incident_evidence(tmp_path) -> None:
    database = tmp_path / "v1.sqlite3"
    incident = create_demo_incident()
    original = SQLiteIncidentRepository(database)
    original.save_incident(incident)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE signal_history")
        connection.execute("DROP TABLE emitted_correlations")
        connection.execute("DROP TABLE analysis_run_events")
        connection.execute("DROP TABLE events")
        connection.execute("DROP TABLE analysis_runs")
        connection.execute("PRAGMA user_version = 1")

    migrated = SQLiteIncidentRepository(database)

    assert migrated.get_incident(incident.incident_id) is not None
    assert migrated.get_incident(incident.incident_id).timeline
    assert migrated.list_runs() == ()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
    assert SQLiteIncidentRepository(database).list_runs() == ()


def test_failed_v1_migration_does_not_advance_version(tmp_path) -> None:
    database = tmp_path / "broken-v1.sqlite3"
    SQLiteIncidentRepository(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE analysis_runs")
        connection.execute("CREATE VIEW analysis_runs AS SELECT 1 AS value")
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(IncidentRepositoryError):
        SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert connection.execute(
            "SELECT type FROM sqlite_master WHERE name = 'analysis_runs'"
        ).fetchone() == ("view",)


def test_ledger_persists_only_sanitized_provenance_without_raw_evidence(
    tmp_path,
) -> None:
    from trailweaver.api.execution import create_default_investigation_runner

    database = tmp_path / "provenance.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository, analysis_run_repository=repository
    )
    fixture = (
        Path(__file__).parents[1]
        / "samples"
        / "cloudtrail"
        / "account-compromise-sequence.json"
    )

    result = runner.run_cloudtrail_file(
        fixture, source_label="/private/aws/accounts/export.json"
    )

    record = repository.get_run(result.analysis_run.analysis_run_id)
    assert record is not None
    assert record.source_label == "export.json"
    with sqlite3.connect(database) as connection:
        columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(analysis_runs)").fetchall()
        ]
        assert set(columns) == {
            "sequence",
            "analysis_run_id",
            "source_type",
            "source_label",
            "status",
            "started_at",
            "finished_at",
            "records_seen",
            "records_accepted",
            "signals_created",
            "correlations_created",
            "incidents_created",
            "failure_phase",
        }
        row = connection.execute("SELECT * FROM analysis_runs").fetchone()
        values = " ".join(str(value) for value in row if value is not None)
    assert "requestParameters" not in values
    assert "userIdentity" not in values
    assert "/private/aws/accounts" not in values
