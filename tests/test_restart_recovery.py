"""Restart/recovery behavior: lifecycle classification only (M35).

INTERRUPTED never proves a crash. It means a new exclusive database owner
inherited an AnalysisRun in a nonterminal RUNNING state and classified that
unfinished lifecycle as interrupted. Recovery replays, resumes, or
reconstructs nothing.
"""

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest
from fastapi import FastAPI

from trailweaver.analysis_ledger import (
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
from trailweaver.api.app import create_app, create_persistent_app
from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import (
    AnalysisRunRepositoryError,
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)
from trailweaver.cli import EXIT_RUNTIME_ERROR, main
from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.event_ledger import EventLedgerError, InMemoryEventLedger
from trailweaver.incidents import IncidentFactory
from trailweaver.recovery import AnalysisRunRecoveryError, recover_interrupted_runs
from trailweaver.rules import AWS_RULES
from trailweaver.signal_history import InMemorySignalHistory, SignalHistoryError

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"

STARTED = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
STAMP = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


def _running_record(
    run_id: str = "run-inherited",
    *,
    started_at: datetime = STARTED,
    source_label: str | None = "export.json",
    source_type: AnalysisSourceType = AnalysisSourceType.LOCAL_FILE,
) -> AnalysisRunRecord:
    return AnalysisRunRecord(
        analysis_run_id=run_id,
        source_type=source_type,
        source_label=source_label,
        status=AnalysisRunStatus.RUNNING,
        started_at=started_at,
        finished_at=None,
        records_seen=3,
        records_accepted=2,
        signals_created=None,
        correlations_created=None,
        incidents_created=None,
        failure_phase=None,
    )


def _completed_record(run_id: str = "run-done") -> AnalysisRunRecord:
    return AnalysisRunRecord(
        analysis_run_id=run_id,
        source_type=AnalysisSourceType.LOCAL_FILE,
        source_label="export.json",
        status=AnalysisRunStatus.COMPLETED,
        started_at=STARTED,
        finished_at=STARTED + timedelta(seconds=5),
        records_seen=3,
        records_accepted=3,
        signals_created=3,
        correlations_created=1,
        incidents_created=1,
        failure_phase=None,
    )


def _failed_record(run_id: str = "run-broken") -> AnalysisRunRecord:
    return AnalysisRunRecord(
        analysis_run_id=run_id,
        source_type=AnalysisSourceType.LOCAL_FILE,
        source_label="export.json",
        status=AnalysisRunStatus.FAILED,
        started_at=STARTED,
        finished_at=STARTED + timedelta(seconds=5),
        records_seen=3,
        records_accepted=3,
        signals_created=3,
        correlations_created=None,
        incidents_created=None,
        failure_phase=AnalysisFailurePhase.CORRELATION,
    )


def _sqlite_runner(database: Path):  # type: ignore[no-untyped-def]
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    return repository, runner


def _strip_event_ids(payload: bytes) -> bytes:
    document = json.loads(payload.decode("utf-8"))
    for record in document["Records"]:
        del record["eventID"]
    return json.dumps(document).encode("utf-8")


# ---------------------------------------------------------------------------
# Domain: INTERRUPTED record invariants (§31)
# ---------------------------------------------------------------------------


def test_interrupted_status_value_is_stable_and_terminal() -> None:
    assert AnalysisRunStatus.INTERRUPTED.value == "interrupted"
    assert {status.value for status in AnalysisRunStatus} == {
        "running",
        "completed",
        "failed",
        "interrupted",
    }


def test_valid_interrupted_record_preserves_identity_and_inputs() -> None:
    record = AnalysisRunRecord(
        analysis_run_id="run-old",
        source_type=AnalysisSourceType.S3_OBJECT,
        source_label="s3://bucket/key.json",
        status=AnalysisRunStatus.INTERRUPTED,
        started_at=STARTED,
        finished_at=STAMP,
        records_seen=3,
        records_accepted=2,
        signals_created=None,
        correlations_created=None,
        incidents_created=None,
        failure_phase=None,
    )

    assert record.status is AnalysisRunStatus.INTERRUPTED
    assert record.finished_at == STAMP
    assert record.source_label == "s3://bucket/key.json"


@pytest.mark.parametrize("field", ("signals_created", "correlations_created", "incidents_created"))
def test_interrupted_record_rejects_output_counts(field: str) -> None:
    base = {
        "analysis_run_id": "run-old",
        "source_type": AnalysisSourceType.LOCAL_FILE,
        "source_label": None,
        "status": AnalysisRunStatus.INTERRUPTED,
        "started_at": STARTED,
        "finished_at": STAMP,
        "records_seen": 3,
        "records_accepted": 2,
        "signals_created": None,
        "correlations_created": None,
        "incidents_created": None,
        "failure_phase": None,
    }
    base[field] = 0

    with pytest.raises(ValueError, match="output counts"):
        AnalysisRunRecord(**base)  # type: ignore[arg-type]


def test_interrupted_record_rejects_failure_phase() -> None:
    with pytest.raises(ValueError, match="failure phase"):
        AnalysisRunRecord(
            analysis_run_id="run-old",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.INTERRUPTED,
            started_at=STARTED,
            finished_at=STAMP,
            records_seen=3,
            records_accepted=2,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=AnalysisFailurePhase.DETECTION,
        )


def test_interrupted_record_requires_classification_time() -> None:
    with pytest.raises(ValueError, match="classification time"):
        AnalysisRunRecord(
            analysis_run_id="run-old",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.INTERRUPTED,
            started_at=STARTED,
            finished_at=None,
            records_seen=3,
            records_accepted=2,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )


def test_interrupted_record_rejects_naive_or_predating_classification_time() -> None:
    naive = datetime(2026, 10, 5, 9, 0)  # noqa: DTZ001
    with pytest.raises(ValueError, match="timezone-aware"):
        AnalysisRunRecord(
            analysis_run_id="run-old",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.INTERRUPTED,
            started_at=STARTED,
            finished_at=naive,  # type: ignore[arg-type]
            records_seen=3,
            records_accepted=2,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )
    with pytest.raises(ValueError, match="must not be before started_at"):
        AnalysisRunRecord(
            analysis_run_id="run-old",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.INTERRUPTED,
            started_at=STARTED,
            finished_at=STARTED - timedelta(seconds=1),
            records_seen=3,
            records_accepted=2,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )


def test_completed_and_failed_record_semantics_are_unchanged() -> None:
    _completed_record()
    _failed_record()
    # Completed still demands output counts and no phase; failed still
    # demands a phase. Interrupted support changed neither branch.
    with pytest.raises(ValueError, match="terminal output counts"):
        AnalysisRunRecord(
            analysis_run_id="run-x",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.COMPLETED,
            started_at=STARTED,
            finished_at=STAMP,
            records_seen=3,
            records_accepted=3,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )


def test_analysis_run_remains_a_completed_only_fact() -> None:
    from dataclasses import fields

    field_names = {field.name for field in fields(AnalysisRun)}

    assert "status" not in field_names
    assert "failure_phase" not in field_names
    run = AnalysisRun(
        source_type=AnalysisSourceType.LOCAL_FILE,
        source_label=None,
        started_at=STARTED,
        completed_at=STAMP,
        records_seen=3,
        records_accepted=3,
        signals_created=0,
        correlations_created=0,
        incidents_created=0,
    )
    assert run.completed_at == STAMP


def test_failure_phase_enum_is_unchanged() -> None:
    assert {phase.value for phase in AnalysisFailurePhase} == {
        "event_ordering",
        "detection",
        "correlation",
        "incident_creation",
        "incident_persistence",
    }


# ---------------------------------------------------------------------------
# Migration: SQLite v4 -> v5 (§32)
# ---------------------------------------------------------------------------

_V4_ANALYSIS_RUNS_TABLE_SQL = """CREATE TABLE analysis_runs (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id TEXT NOT NULL UNIQUE CHECK (length(trim(analysis_run_id)) > 0),
    source_type TEXT NOT NULL CHECK (
        source_type IN ('local_file', 'web_upload', 's3_object', 'direct_input')
    ),
    source_label TEXT CHECK (
        source_label IS NULL OR (
            length(trim(source_label)) > 0 AND length(source_label) <= 256
        )
    ),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    started_at TEXT NOT NULL CHECK (length(started_at) > 0),
    finished_at TEXT,
    records_seen INTEGER NOT NULL CHECK (records_seen >= 0),
    records_accepted INTEGER NOT NULL CHECK (
        records_accepted >= 0 AND records_accepted <= records_seen
    ),
    signals_created INTEGER CHECK (signals_created >= 0),
    correlations_created INTEGER CHECK (correlations_created >= 0),
    incidents_created INTEGER CHECK (incidents_created >= 0),
    failure_phase TEXT CHECK (failure_phase IN (
        'event_ordering', 'detection', 'correlation',
        'incident_creation', 'incident_persistence'
    )),
    CHECK (finished_at IS NULL OR finished_at >= started_at),
    CHECK (
        (status = 'running' AND finished_at IS NULL
            AND signals_created IS NULL AND correlations_created IS NULL
            AND incidents_created IS NULL AND failure_phase IS NULL)
        OR
        (status = 'completed' AND finished_at IS NOT NULL
            AND signals_created IS NOT NULL AND correlations_created IS NOT NULL
            AND incidents_created IS NOT NULL AND failure_phase IS NULL)
        OR
        (status = 'failed' AND finished_at IS NOT NULL AND failure_phase IS NOT NULL
            AND (
                (failure_phase IN ('event_ordering', 'detection')
                    AND signals_created IS NULL AND correlations_created IS NULL
                    AND incidents_created IS NULL)
                OR (failure_phase = 'correlation' AND signals_created IS NOT NULL
                    AND correlations_created IS NULL AND incidents_created IS NULL)
                OR (failure_phase = 'incident_creation' AND signals_created IS NOT NULL
                    AND correlations_created IS NOT NULL AND incidents_created IS NULL)
                OR (failure_phase = 'incident_persistence'
                    AND signals_created IS NOT NULL AND correlations_created IS NOT NULL
                    AND incidents_created IS NOT NULL)
            ))
    )
)"""

_EXPECTED_TABLES = frozenset(
    {
        "analysis_run_events",
        "analysis_runs",
        "correlation_matches",
        "emitted_correlations",
        "events",
        "incidents",
        "signal_history",
        "signals",
    }
)


def _table_set(database: Path) -> frozenset[str]:
    with sqlite3.connect(database) as connection:
        return frozenset(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )


def _seed_full_database(database: Path):  # type: ignore[no-untyped-def]
    """Populate every durable store: incident, completed/failed/RUNNING runs."""

    repository, runner = _sqlite_runner(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE, source_label="seed.json")
    assert result.incident_count == 1
    repository.start_run(_running_record("run-inherited"))
    repository.start_run(_running_record("run-doomed"))
    repository.fail_run(
        "run-doomed",
        failed_at=STARTED + timedelta(seconds=9),
        failure_phase=AnalysisFailurePhase.DETECTION,
    )
    return repository, result


def _downgrade_runs_to_old_v4(database: Path) -> None:
    """Rebuild analysis_runs with the pre-v5 CHECK and stamp version 4."""

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            _V4_ANALYSIS_RUNS_TABLE_SQL.replace(
                "analysis_runs (", "analysis_runs_old (", 1
            )
        )
        connection.execute(
            "INSERT INTO analysis_runs_old SELECT * FROM analysis_runs ORDER BY sequence"
        )
        connection.execute("DROP TABLE analysis_runs")
        connection.execute("ALTER TABLE analysis_runs_old RENAME TO analysis_runs")
        connection.execute("PRAGMA user_version = 4")
        connection.commit()


def _live_foreign_keys(repository: SQLiteIncidentRepository) -> int:
    """Read the enforcement pragma on a live repository connection."""

    connection = repository._connect()
    try:
        row = connection.execute("PRAGMA foreign_keys").fetchone()
        assert row is not None
        return int(row[0])
    finally:
        connection.close()


def _assert_invalid_child_insert_rejected(
    repository: SQLiteIncidentRepository, database: Path
) -> None:
    """Prove FK enforcement is real with a bogus child row, then roll back."""

    connection = repository._connect()
    try:
        with sqlite3.connect(database) as probe:
            before = probe.execute("SELECT COUNT(*) FROM analysis_run_events").fetchone()
            event = probe.execute(
                "SELECT provider, event_identity FROM events LIMIT 1"
            ).fetchone()
        if event is None:
            provider, identity = "aws", "no-such-event"
        else:
            provider, identity = str(event[0]), str(event[1])
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO analysis_run_events (analysis_run_id, provider, event_identity)"
                " VALUES ('no-such-run', ?, ?)",
                (provider, identity),
            )
        connection.rollback()
        with sqlite3.connect(database) as probe:
            assert probe.execute("SELECT COUNT(*) FROM analysis_run_events").fetchone() == before
            assert probe.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_fresh_database_is_created_directly_as_v5(tmp_path: Path) -> None:
    database = tmp_path / "fresh.sqlite3"
    SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'analysis_runs'"
        ).fetchone()[0]
        assert "'interrupted'" in ddl
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        leftovers = connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'analysis_runs_%'"
        ).fetchall()
        assert leftovers == []
    assert _table_set(database) == _EXPECTED_TABLES


def test_v1_database_upgrades_to_v5_preserving_incidents(tmp_path: Path) -> None:
    database = tmp_path / "v1.sqlite3"
    _, result = _seed_full_database(database)
    incident_id = result.incidents[0].incident_id
    with sqlite3.connect(database) as connection:
        for table in (
            "signal_history",
            "emitted_correlations",
            "analysis_run_events",
            "events",
            "analysis_runs",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()

    migrated = SQLiteIncidentRepository(database)

    assert migrated.get_incident(incident_id) is not None
    assert migrated.list_runs() == ()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert _table_set(database) == _EXPECTED_TABLES


def test_fresh_v5_repository_has_enforcement_enabled(tmp_path: Path) -> None:
    database = tmp_path / "fresh-enforce.sqlite3"
    repository = SQLiteIncidentRepository(database)

    assert _live_foreign_keys(repository) == 1
    _assert_invalid_child_insert_rejected(repository, database)


def test_migrated_v4_repository_has_enforcement_enabled(tmp_path: Path) -> None:
    database = tmp_path / "v4-enforce.sqlite3"
    _seed_full_database(database)
    _downgrade_runs_to_old_v4(database)

    migrated = SQLiteIncidentRepository(database)

    assert _live_foreign_keys(migrated) == 1
    _assert_invalid_child_insert_rejected(migrated, database)


def test_migrated_v1_repository_has_enforcement_enabled(tmp_path: Path) -> None:
    database = tmp_path / "v1-enforce.sqlite3"
    _seed_full_database(database)
    with sqlite3.connect(database) as connection:
        for table in (
            "signal_history",
            "emitted_correlations",
            "analysis_run_events",
            "events",
            "analysis_runs",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()

    migrated = SQLiteIncidentRepository(database)

    assert _live_foreign_keys(migrated) == 1
    _assert_invalid_child_insert_rejected(migrated, database)


def test_v2_database_upgrades_to_v5_preserving_runs(tmp_path: Path) -> None:
    database = tmp_path / "v2.sqlite3"
    _, result = _seed_full_database(database)
    run_id = result.analysis_run.analysis_run_id
    with sqlite3.connect(database) as connection:
        for table in (
            "signal_history",
            "emitted_correlations",
            "analysis_run_events",
            "events",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()

    migrated = SQLiteIncidentRepository(database)

    assert migrated.get_run(run_id) is not None
    assert migrated.get_run("run-inherited") is not None
    assert migrated.get_run("run-inherited").status is AnalysisRunStatus.RUNNING
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert _table_set(database) == _EXPECTED_TABLES


def test_v3_database_upgrades_to_v5_preserving_runs_and_events(tmp_path: Path) -> None:
    database = tmp_path / "v3.sqlite3"
    _, result = _seed_full_database(database)
    run_id = result.analysis_run.analysis_run_id
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE signal_history")
        connection.execute("DROP TABLE emitted_correlations")
        connection.execute("PRAGMA user_version = 3")
        connection.commit()
        event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert event_count == 3

    migrated = SQLiteIncidentRepository(database)

    assert migrated.get_run(run_id) is not None
    assert migrated.get_run("run-inherited").status is AnalysisRunStatus.RUNNING
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (3,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert _table_set(database) == _EXPECTED_TABLES


def test_v4_database_with_old_check_migrates_preserving_everything(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v4.sqlite3"
    _, result = _seed_full_database(database)
    run_id = result.analysis_run.analysis_run_id
    incident_id = result.incidents[0].incident_id
    _downgrade_runs_to_old_v4(database)
    with sqlite3.connect(database) as connection:
        old_ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'analysis_runs'"
        ).fetchone()[0]
    assert "'interrupted'" not in old_ddl

    migrated = SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        new_ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'analysis_runs'"
        ).fetchone()[0]
        assert "'interrupted'" in new_ddl
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        sequences = connection.execute(
            "SELECT sequence, analysis_run_id FROM analysis_runs ORDER BY sequence"
        ).fetchall()
        assert [row[1] for row in sequences] == [
            run_id,
            "run-inherited",
            "run-doomed",
        ]
        assert [row[0] for row in sequences] == [1, 2, 3]
        assert connection.execute(
            "SELECT COUNT(*) FROM analysis_run_events"
        ).fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM signal_history").fetchone() == (3,)
        assert connection.execute(
            "SELECT COUNT(*) FROM emitted_correlations"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT * FROM sqlite_sequence WHERE name = 'analysis_runs'"
        ).fetchone() is not None
        leftovers = connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'analysis_runs_%'"
        ).fetchall()
        assert leftovers == []
    assert _table_set(database) == _EXPECTED_TABLES
    assert migrated.get_incident(incident_id) is not None
    assert migrated.get_run(run_id).status is AnalysisRunStatus.COMPLETED
    assert migrated.get_run("run-doomed").status is AnalysisRunStatus.FAILED
    # Migration classifies nothing: the inherited row is still RUNNING.
    assert migrated.get_run("run-inherited").status is AnalysisRunStatus.RUNNING
    # The AUTOINCREMENT counter followed the preserved maximum.
    migrated.start_run(_running_record("run-next"))
    assert [run.analysis_run_id for run in migrated.list_runs()][3] == "run-next"


def test_running_row_migrates_before_explicit_recovery_classifies_it(
    tmp_path: Path,
) -> None:
    database = tmp_path / "order.sqlite3"
    _seed_full_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 4")
        connection.commit()

    migrated = SQLiteIncidentRepository(database)
    assert migrated.get_run("run-inherited").status is AnalysisRunStatus.RUNNING

    transitioned = recover_interrupted_runs(migrated, interrupted_at=STAMP)

    assert transitioned == 1
    assert migrated.get_run("run-inherited").status is AnalysisRunStatus.INTERRUPTED


def test_failed_migration_rolls_back_without_touching_data(tmp_path: Path) -> None:
    database = tmp_path / "broken-v4.sqlite3"
    _, result = _seed_full_database(database)
    run_id = result.analysis_run.analysis_run_id
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE analysis_runs_new (value TEXT)")
        connection.execute("PRAGMA user_version = 4")
        connection.commit()

    with pytest.raises(IncidentRepositoryError):
        SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (3,)
    # After removing the sabotage, migration succeeds on intact data.
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE analysis_runs_new")
        connection.commit()
    assert SQLiteIncidentRepository(database).get_run(run_id) is not None


# ---------------------------------------------------------------------------
# Recovery operation: atomic, idempotent lifecycle classification (§33)
# ---------------------------------------------------------------------------


def test_recovery_with_no_running_rows_returns_zero(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "empty.sqlite3")
    assert repository.mark_running_runs_interrupted(interrupted_at=STAMP) == 0

    memory = InMemoryAnalysisRunRepository()
    assert memory.mark_running_runs_interrupted(interrupted_at=STAMP) == 0


def test_recovery_classifies_one_running_row_preserving_inputs(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "one.sqlite3")
    repository.start_run(_running_record("run-old", source_label="s3://bucket/key.json"))

    transitioned = recover_interrupted_runs(repository, interrupted_at=STAMP)

    assert transitioned == 1
    record = repository.get_run("run-old")
    assert record is not None
    assert record.status is AnalysisRunStatus.INTERRUPTED
    assert record.started_at == STARTED
    assert record.finished_at == STAMP
    assert record.records_seen == 3
    assert record.records_accepted == 2
    assert record.source_label == "s3://bucket/key.json"
    assert record.source_type is AnalysisSourceType.LOCAL_FILE
    assert record.signals_created is None
    assert record.correlations_created is None
    assert record.incidents_created is None
    assert record.failure_phase is None


def test_recovery_applies_one_timestamp_to_every_candidate(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "multi.sqlite3")
    repository.start_run(_running_record("run-a", started_at=STARTED))
    repository.start_run(_running_record("run-b", started_at=STARTED + timedelta(hours=1)))
    repository.start_run(_running_record("run-done"))
    repository.complete_run(
        AnalysisRun(
            analysis_run_id="run-done",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label="export.json",
            started_at=STARTED,
            completed_at=STARTED + timedelta(seconds=5),
            records_seen=3,
            records_accepted=2,
            signals_created=2,
            correlations_created=1,
            incidents_created=1,
        )
    )

    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 2

    assert repository.get_run("run-a").finished_at == STAMP  # type: ignore[union-attr]
    assert repository.get_run("run-b").finished_at == STAMP  # type: ignore[union-attr]
    assert [run.analysis_run_id for run in repository.list_runs()] == [
        "run-a",
        "run-b",
        "run-done",
    ]
    assert repository.get_run("run-done").status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]


def test_recovery_leaves_every_terminal_row_untouched(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRunRepository(
        [_completed_record("run-done"), _failed_record("run-broken")]
    )

    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 0

    assert repository.get_run("run-done").status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]
    assert repository.get_run("run-broken").status is AnalysisRunStatus.FAILED  # type: ignore[union-attr]


def test_recovery_is_idempotent(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "idem.sqlite3")
    repository.start_run(_running_record())

    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1
    assert recover_interrupted_runs(repository, interrupted_at=STAMP + timedelta(hours=1)) == 0
    record = repository.get_run("run-inherited")
    assert record is not None
    assert record.status is AnalysisRunStatus.INTERRUPTED
    assert record.finished_at == STAMP


def test_recovery_aborts_everything_when_stamp_predates_a_candidate(
    tmp_path: Path,
) -> None:
    repository = InMemoryAnalysisRunRepository(
        [
            _running_record("run-early", started_at=STARTED),
            _running_record("run-late", started_at=STARTED + timedelta(hours=1)),
        ]
    )

    with pytest.raises(AnalysisRunRecoveryError):
        recover_interrupted_runs(repository, interrupted_at=STARTED)

    assert repository.get_run("run-early").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert repository.get_run("run-late").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]


def test_sqlite_recovery_aborts_everything_on_predating_stamp(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "predate.sqlite3")
    repository.start_run(_running_record("run-early", started_at=STARTED))
    repository.start_run(_running_record("run-late", started_at=STARTED + timedelta(hours=1)))

    with pytest.raises(AnalysisRunRecoveryError):
        recover_interrupted_runs(repository, interrupted_at=STARTED)

    assert repository.get_run("run-early").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert repository.get_run("run-late").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]


def test_recovery_rejects_naive_timestamp_without_side_effects(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "naive.sqlite3")
    repository.start_run(_running_record())

    with pytest.raises(ValueError, match="timezone-aware"):
        repository.mark_running_runs_interrupted(
            interrupted_at=datetime(2026, 10, 5, 9, 0)  # noqa: DTZ001
        )

    assert repository.get_run("run-inherited").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]


def test_malformed_candidate_aborts_the_whole_recovery(tmp_path: Path) -> None:
    database = tmp_path / "malformed.sqlite3"
    repository, _ = _sqlite_runner(database)
    repository.start_run(_running_record("run-good"))
    repository.start_run(_running_record("run-bad"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'x' WHERE analysis_run_id = 'run-bad'"
        )
        connection.commit()

    with pytest.raises(AnalysisRunRecoveryError):
        recover_interrupted_runs(repository, interrupted_at=STAMP)

    assert repository.get_run("run-good").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]

    # Retry after repairing the stored row succeeds.
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = ? WHERE analysis_run_id = 'run-bad'",
            ("2026-10-04T10:00:00.000000+00:00",),
        )
        connection.commit()
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 2


def test_sql_write_failure_aborts_the_whole_recovery(tmp_path: Path) -> None:
    database = tmp_path / "writefail.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.start_run(_running_record("run-a"))
    repository.start_run(_running_record("run-b"))

    real_connect = repository._connect

    class _FailingUpdateConnection:
        def __init__(self, delegate: sqlite3.Connection) -> None:
            self._delegate = delegate

        def execute(self, statement: object, parameters: object = ()) -> object:
            if isinstance(statement, str) and statement.lstrip().upper().startswith("UPDATE"):
                raise sqlite3.OperationalError("injected write failure")
            return self._delegate.execute(statement, parameters)  # type: ignore[arg-type]

        def commit(self) -> None:
            self._delegate.commit()

        def rollback(self) -> None:
            self._delegate.rollback()

        def close(self) -> None:
            self._delegate.close()

    repository._connect = lambda: _FailingUpdateConnection(real_connect())  # type: ignore[method-assign]
    try:
        with pytest.raises(AnalysisRunRecoveryError):
            recover_interrupted_runs(repository, interrupted_at=STAMP)
    finally:
        repository._connect = real_connect  # type: ignore[method-assign]

    assert repository.get_run("run-a").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert repository.get_run("run-b").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    # Retry on a healthy connection converges.
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 2


def test_repeated_recovery_converges_after_crash_ambiguity(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "converge.sqlite3")
    repository.start_run(_running_record())

    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1
    # Whether the previous owner crashed before or after commit, repeating
    # the same operation converges: rows are INTERRUPTED exactly once.
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 0
    record = repository.get_run("run-inherited")
    assert record is not None
    assert (record.status, record.finished_at) == (
        AnalysisRunStatus.INTERRUPTED,
        STAMP,
    )


def test_in_memory_recovery_matches_sqlite_semantics() -> None:
    repository = InMemoryAnalysisRunRepository(
        [
            _completed_record("run-done"),
            _running_record("run-a", started_at=STARTED),
            _running_record("run-b", started_at=STARTED + timedelta(minutes=30)),
        ]
    )

    assert repository.mark_running_runs_interrupted(interrupted_at=STAMP) == 2
    assert repository.mark_running_runs_interrupted(interrupted_at=STAMP) == 0
    assert [run.analysis_run_id for run in repository.list_runs()] == [
        "run-done",
        "run-a",
        "run-b",
    ]
    assert repository.get_run("run-a").finished_at == STAMP  # type: ignore[union-attr]
    assert repository.get_run("run-done").status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]

    with pytest.raises(InvalidAnalysisRunTransitionError):
        InMemoryAnalysisRunRepository(
            [_running_record("run-future", started_at=STAMP + timedelta(seconds=1))]
        ).mark_running_runs_interrupted(interrupted_at=STAMP)


# ---------------------------------------------------------------------------
# Composition: explicit recovery at persistent roots only (§34)
# ---------------------------------------------------------------------------


class _ApiClient:
    def __init__(self, application: FastAPI) -> None:
        self._application = application

    def get(self, path: str):  # type: ignore[no-untyped-def]
        import asyncio

        import httpx

        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.get(path)

        return asyncio.run(request())

    def post_file(self, path: str, content: bytes):  # type: ignore[no-untyped-def]
        import asyncio

        import httpx

        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.post(
                    path,
                    content=content,
                    headers={"Content-Type": "application/json"},
                )

        return asyncio.run(request())


def test_persistent_app_recovers_before_serving_analyses(tmp_path: Path) -> None:
    database = tmp_path / "persistent.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))

    application = create_persistent_app(database)

    assert SQLiteIncidentRepository(database).get_run("run-inherited").status is (
        AnalysisRunStatus.INTERRUPTED
    )
    created = _ApiClient(application).post_file(
        "/api/v1/analyses/file", ATTACK_FIXTURE.read_bytes()
    )
    assert created.status_code == 200
    assert created.json()["incidents_created"] == 1


def test_persistent_app_migrates_then_recovers_in_order(tmp_path: Path) -> None:
    database = tmp_path / "v4recover.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 4")
        connection.commit()

    create_persistent_app(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
    # INTERRUPTED is only storable after the v5 migration committed, so this
    # proves migration ran before recovery classified the inherited row.
    assert SQLiteIncidentRepository(database).get_run("run-inherited").status is (
        AnalysisRunStatus.INTERRUPTED
    )


def test_persistent_app_startup_fails_when_recovery_fails(tmp_path: Path) -> None:
    database = tmp_path / "unrecoverable.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-bad"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'x' WHERE analysis_run_id = 'run-bad'"
        )
        connection.commit()

    with pytest.raises(AnalysisRunRepositoryError):
        create_persistent_app(database)


def test_serve_command_fails_without_starting_when_recovery_fails(
    tmp_path: Path,
) -> None:
    database = tmp_path / "serve-broken.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-bad"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'x' WHERE analysis_run_id = 'run-bad'"
        )
        connection.commit()
    calls: list[object] = []

    exit_code = main(
        ["--database", str(database), "serve", "--port", "9000"],
        environment={},
        stdout=StringIO(),
        stderr=StringIO(),
        server_runner=lambda application, **kwargs: calls.append(kwargs),
    )

    assert exit_code == EXIT_RUNTIME_ERROR
    assert calls == []


def test_cli_file_analysis_recovers_before_processing(tmp_path: Path) -> None:
    database = tmp_path / "cli.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))
    output, errors = StringIO(), StringIO()

    exit_code = main(
        ["--database", str(database), "analyze-file", str(ATTACK_FIXTURE)],
        environment={},
        stdout=output,
        stderr=errors,
    )

    assert exit_code == 0
    events = [
        json.loads(line)["event"] for line in errors.getvalue().splitlines() if line.startswith("{")
    ]
    assert events[0] == "analysis_run_recovery_completed"
    assert "investigation_started" in events
    assert SQLiteIncidentRepository(database).get_run("run-inherited").status is (
        AnalysisRunStatus.INTERRUPTED
    )
    assert "incidents: 1" in output.getvalue()


def test_cli_s3_analysis_recovers_before_processing(tmp_path: Path) -> None:
    from io import BytesIO

    class _FakeS3Client:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def get_object(self, **kwargs: object) -> dict[str, object]:
            return {"Body": BytesIO(self.content), "ContentLength": len(self.content)}

    database = tmp_path / "s3.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))

    exit_code = main(
        [
            "--database",
            str(database),
            "analyze-s3",
            "--bucket",
            "fictional-bucket",
            "--key",
            "AWSLogs/export.json",
        ],
        environment={},
        stdout=StringIO(),
        stderr=StringIO(),
        s3_client=_FakeS3Client(ATTACK_FIXTURE.read_bytes()),  # type: ignore[arg-type]
    )

    assert exit_code == 0
    assert SQLiteIncidentRepository(database).get_run("run-inherited").status is (
        AnalysisRunStatus.INTERRUPTED
    )


def test_cli_prefix_analysis_recovers_before_processing(tmp_path: Path) -> None:
    from io import BytesIO

    class _FakePrefixClient:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def get_object(self, **kwargs: object) -> dict[str, object]:
            return {"Body": BytesIO(self.content), "ContentLength": len(self.content)}

        def list_objects_v2(self, **kwargs: object) -> dict[str, object]:
            return {
                "Contents": [{"Key": "logs/export.json", "Size": len(self.content)}],
                "IsTruncated": False,
            }

    database = tmp_path / "prefix.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))

    exit_code = main(
        [
            "--database",
            str(database),
            "analyze-s3-prefix",
            "--bucket",
            "fictional-bucket",
            "--prefix",
            "logs/",
        ],
        environment={},
        stdout=StringIO(),
        stderr=StringIO(),
        s3_client=_FakePrefixClient(ATTACK_FIXTURE.read_bytes()),  # type: ignore[arg-type]
    )

    assert exit_code == 0
    assert SQLiteIncidentRepository(database).get_run("run-inherited").status is (
        AnalysisRunStatus.INTERRUPTED
    )


def test_cli_analysis_is_blocked_when_recovery_fails(tmp_path: Path) -> None:
    database = tmp_path / "cli-broken.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-bad"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'x' WHERE analysis_run_id = 'run-bad'"
        )
        connection.commit()
    output, errors = StringIO(), StringIO()

    exit_code = main(
        ["--database", str(database), "analyze-file", str(ATTACK_FIXTURE)],
        environment={},
        stdout=output,
        stderr=errors,
    )

    assert exit_code == EXIT_RUNTIME_ERROR
    assert errors.getvalue().endswith("Runtime error: incident storage is unavailable\n")
    assert "Traceback" not in errors.getvalue()
    assert str(database) not in errors.getvalue()
    assert "analysis run: " not in output.getvalue()
    assert SQLiteIncidentRepository(database).list_incidents() == ()


def test_generic_injected_app_performs_no_hidden_recovery(tmp_path: Path) -> None:
    database = tmp_path / "injected.sqlite3"
    seed = SQLiteIncidentRepository(database)
    seed.start_run(_running_record("run-inherited"))

    application = create_app(
        repository=seed,
        analysis_run_repository=seed,
        event_ledger_repository=seed,
        signal_history_repository=seed,
    )
    created = _ApiClient(application).post_file(
        "/api/v1/analyses/file", ATTACK_FIXTURE.read_bytes()
    )

    assert created.status_code == 200
    assert seed.get_run("run-inherited").status is AnalysisRunStatus.RUNNING


def test_in_memory_composition_performs_no_startup_recovery() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository([_running_record("run-inherited")])
    ledger = InMemoryEventLedger()

    application = create_app(
        repository=incidents,
        analysis_run_repository=runs,
        event_ledger_repository=ledger,
        signal_history_repository=InMemorySignalHistory(),
    )
    created = _ApiClient(application).post_file(
        "/api/v1/analyses/file", ATTACK_FIXTURE.read_bytes()
    )

    assert created.status_code == 200
    assert runs.get_run("run-inherited").status is AnalysisRunStatus.RUNNING


def test_repository_construction_performs_no_hidden_recovery(tmp_path: Path) -> None:
    database = tmp_path / "reopened.sqlite3"
    SQLiteIncidentRepository(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO analysis_runs (analysis_run_id, source_type, source_label,"
            " status, started_at, finished_at, records_seen, records_accepted,"
            " signals_created, correlations_created, incidents_created, failure_phase)"
            " VALUES ('run-inherited', 'local_file', 'export.json', 'running',"
            " '2026-10-04T10:00:00.000000+00:00', NULL, 3, 2,"
            " NULL, NULL, NULL, NULL)"
        )
        connection.commit()

    reopened = SQLiteIncidentRepository(database)

    assert reopened.get_run("run-inherited").status is AnalysisRunStatus.RUNNING


# ---------------------------------------------------------------------------
# Crash/replay at durable boundaries via deterministic fault injection (§35)
# ---------------------------------------------------------------------------


class _FailingLedger:
    """Event-ledger double failing one boundary exactly once."""

    def __init__(self, delegate: InMemoryEventLedger, method: str, error: Exception) -> None:
        self._delegate = delegate
        self._method = method
        self._error = error
        self.calls: dict[str, int] = {}

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self._delegate, name)

    def _once(self, method: str) -> bool:
        count = self.calls.get(method, 0) + 1
        self.calls[method] = count
        return self._method == method and count == 1

    def known_identities(self, identities):  # type: ignore[no-untyped-def]
        if self._once("known_identities"):
            raise self._error
        return self._delegate.known_identities(identities)

    def acknowledge_run_events(self, **kwargs):  # type: ignore[no-untyped-def]
        if self._once("acknowledge_run_events"):
            raise self._error
        return self._delegate.acknowledge_run_events(**kwargs)


class _FailingHistory:
    """Signal-history double failing the first store exactly once."""

    def __init__(self, delegate: InMemorySignalHistory) -> None:
        self._delegate = delegate
        self.stored = 0

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self._delegate, name)

    def store_signals(self, signals) -> None:  # type: ignore[no-untyped-def]
        self.stored += 1
        if self.stored == 1:
            raise SignalHistoryError("injected store failure")
        return self._delegate.store_signals(signals)


class _FailingRuns:
    """Run-ledger double failing the first completion exactly once."""

    def __init__(self, delegate: InMemoryAnalysisRunRepository) -> None:
        self._delegate = delegate
        self.completed = 0

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self._delegate, name)

    def complete_run(self, run) -> None:  # type: ignore[no-untyped-def]
        self.completed += 1
        if self.completed == 1:
            raise AnalysisRunRepositoryError("injected completion failure")
        return self._delegate.complete_run(run)


def _in_memory_runner(  # type: ignore[no-untyped-def]
    incidents=None,
    runs=None,
    ledger=None,
    history=None,
):
    return InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents or InMemoryIncidentRepository(),
        analysis_run_repository=runs or InMemoryAnalysisRunRepository(),
        event_ledger_repository=ledger or InMemoryEventLedger(),
        signal_history_repository=history or InMemorySignalHistory(),
    )


def test_restart_after_start_run_only_leaves_an_interruptible_row() -> None:
    runs = InMemoryAnalysisRunRepository()
    runs.start_run(_running_record("run-crashed"))

    assert recover_interrupted_runs(runs, interrupted_at=STAMP) == 1
    assert runs.get_run("run-crashed").status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]


def test_ledger_read_failure_leaves_running_for_later_recovery() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = _FailingLedger(
        InMemoryEventLedger(), "known_identities", EventLedgerError("injected read failure")
    )
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=ledger)

    with pytest.raises(EventLedgerError):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert runs.list_runs()[0].status is AnalysisRunStatus.RUNNING
    assert recover_interrupted_runs(runs) == 1


def test_history_failure_keeps_tombstone_and_replay_repairs_without_duplicate() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    history = _FailingHistory(InMemorySignalHistory())
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=ledger, history=history)

    with pytest.raises(SignalHistoryError):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert len(incidents.list_incidents()) == 1
    old_run_id = runs.list_runs()[0].analysis_run_id
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert recover_interrupted_runs(runs) == 1

    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert replayed.incident_count == 0
    assert len(incidents.list_incidents()) == 1
    new_run_id = replayed.analysis_run.analysis_run_id
    assert runs.get_run(new_run_id).status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]
    assert len(history._signals) == 3


def test_completion_failure_keeps_history_and_replay_does_not_duplicate() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    history = InMemorySignalHistory()
    failing_runs = _FailingRuns(runs)
    runner = _in_memory_runner(
        incidents=incidents, runs=failing_runs, ledger=ledger, history=history
    )

    with pytest.raises(AnalysisRunRepositoryError):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    old_run_id = runs.list_runs()[0].analysis_run_id
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert len(history._signals) == 3
    assert recover_interrupted_runs(runs) == 1

    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert replayed.incident_count == 0
    assert len(history._signals) == 3
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]


def test_acknowledgement_failure_keeps_completed_and_replay_acknowledges_new() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    failing_ledger = _FailingLedger(
        ledger, "acknowledge_run_events", EventLedgerError("injected ack failure")
    )
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=failing_ledger)

    with pytest.raises(EventLedgerError):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    old_run_id = runs.list_runs()[0].analysis_run_id
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]
    assert recover_interrupted_runs(runs, interrupted_at=STAMP) == 0

    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert replayed.incident_count == 0
    assert len(incidents.list_incidents()) == 1
    new_run_id = replayed.analysis_run.analysis_run_id
    observed = ledger.recorded_observations()
    assert {run for _, run_ids in observed.values() for run in run_ids} == {new_run_id}


def test_committed_acknowledgement_makes_replay_skip_identified_events() -> None:
    incidents = InMemoryIncidentRepository()
    runner = _in_memory_runner(incidents=incidents)

    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert first.incident_count == 1
    second = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert second.analyzed_event_count == 0
    assert second.incident_count == 0


def _two_actor_document() -> bytes:
    document = json.loads(ATTACK_FIXTURE.read_bytes().decode("utf-8"))
    records = document["Records"]
    clones = []
    replacements = (
        ("aaaaaaaa", "dddddddd"),
        ("bbbbbbbb", "eeeeeeee"),
        ("cccccccc", "ffffffff"),
    )
    for record, (old, new) in zip(records, replacements):
        clone = json.loads(json.dumps(record))
        clone["eventID"] = record["eventID"].replace(old, new)
        identity = dict(clone["userIdentity"])
        identity["principalId"] = "AIDAEXAMPLEATTACKER"
        identity["arn"] = "arn:aws:iam::111122223333:user/attacker"
        identity["userName"] = "attacker"
        clone["userIdentity"] = identity
        clones.append(clone)
    document["Records"] = records + clones
    return json.dumps(document).encode("utf-8")


class _FailOnceIncidentRepository(InMemoryIncidentRepository):
    """Persist the first correlation, then fail the second exactly once."""

    def __init__(self) -> None:
        super().__init__()
        self.saves = 0

    def save_incident_if_correlation_new(self, incident, correlation_key):  # type: ignore[no-untyped-def]
        self.saves += 1
        if self.saves == 2:
            raise IncidentRepositoryError("injected persistence failure")
        return super().save_incident_if_correlation_new(incident, correlation_key)


def test_partial_correlation_commit_suppresses_committed_and_emits_missing() -> None:
    incidents = _FailOnceIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    runner = _in_memory_runner(incidents=incidents, runs=runs)
    payload = _two_actor_document()

    with pytest.raises(IncidentRepositoryError):
        runner.run_cloudtrail_json(payload)

    assert len(incidents.list_incidents()) == 1
    old_run_id = runs.list_runs()[0].analysis_run_id
    assert runs.get_run(old_run_id).status is AnalysisRunStatus.FAILED  # type: ignore[union-attr]

    replayed = runner.run_cloudtrail_json(payload)

    assert replayed.incident_count == 1
    assert len(incidents.list_incidents()) == 2
    assert incidents.list_incidents()[0].incident_id != replayed.incidents[0].incident_id


# ---------------------------------------------------------------------------
# M31 / M32 interaction: recovery repairs nothing, preserves everything (§36)
# ---------------------------------------------------------------------------


def test_recovery_acknowledges_no_events_and_preserves_known_identities() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=ledger)
    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert first.incident_count == 1
    known_before = ledger.recorded_observations()
    assert len(known_before) == 3
    runs.start_run(_running_record("run-inherited"))

    assert recover_interrupted_runs(runs, interrupted_at=STAMP) == 1

    assert ledger.recorded_observations() == known_before
    # A fresh replay still recognizes the acknowledged evidence as known.
    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert replayed.analyzed_event_count == 0
    assert runs.get_run("run-inherited").status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]


def test_recovery_leaves_tombstones_untouched_and_without_run_links(tmp_path: Path) -> None:
    database = tmp_path / "tombstones.sqlite3"
    repository, runner = _sqlite_runner(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert result.incident_count == 1
    repository.start_run(_running_record("run-inherited"))
    with sqlite3.connect(database) as connection:
        tombstones_before = connection.execute(
            "SELECT correlation_key, rule_id FROM emitted_correlations ORDER BY correlation_key"
        ).fetchall()

    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1

    with sqlite3.connect(database) as connection:
        tombstones_after = connection.execute(
            "SELECT correlation_key, rule_id FROM emitted_correlations ORDER BY correlation_key"
        ).fetchall()
        for table in ("incidents", "correlation_matches", "signals", "emitted_correlations"):
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            assert "analysis_run_id" not in columns
            assert "recovered_by" not in columns
            assert "retry_of" not in columns
    assert tombstones_before == tombstones_after
    assert len(tombstones_after) == 1

    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert replayed.incident_count == 0
    assert len(repository.list_incidents()) == 1


# ---------------------------------------------------------------------------
# None-ID evidence: at-least-once behavior survives recovery (§37)
# ---------------------------------------------------------------------------


def test_none_id_evidence_creates_no_identity_and_replays_after_recovery() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    history = InMemorySignalHistory()
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=ledger, history=history)
    payload = _strip_event_ids(ATTACK_FIXTURE.read_bytes())

    first = runner.run_cloudtrail_json(payload)
    assert first.incident_count == 1
    assert ledger.recorded_observations() == {}
    assert len(history._signals) == 0

    runs.start_run(_running_record("run-inherited"))
    assert recover_interrupted_runs(runs, interrupted_at=STAMP) == 1
    assert ledger.recorded_observations() == {}
    assert len(history._signals) == 0

    # No identity exists to suppress anything: the replay is processed again
    # and may produce another incident. Recovery fabricated no suppression.
    second = runner.run_cloudtrail_json(payload)
    assert second.incident_count == 1
    assert len(incidents.list_incidents()) == 2


# ---------------------------------------------------------------------------
# M33 prefix interruption: ordinary per-object runs, no batch state (§38)
# ---------------------------------------------------------------------------


def test_prefix_interruption_recovers_only_the_active_object_run() -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    history = InMemorySignalHistory()
    runner = _in_memory_runner(incidents=incidents, runs=runs, ledger=ledger, history=history)
    login = json.loads(ATTACK_FIXTURE.read_bytes().decode("utf-8"))["Records"][1]
    login_doc = json.dumps({"Records": [login]}).encode("utf-8")

    first = runner.run_cloudtrail_json(
        login_doc,
        source_type=AnalysisSourceType.S3_OBJECT,
        source_label="s3://bucket/logs/a-login.json",
    )
    first_run_id = first.analysis_run.analysis_run_id
    active = AnalysisRunRecord(
        analysis_run_id="run-object-b",
        source_type=AnalysisSourceType.S3_OBJECT,
        source_label="s3://bucket/logs/b-key.json",
        status=AnalysisRunStatus.RUNNING,
        started_at=STARTED,
        finished_at=None,
        records_seen=1,
        records_accepted=1,
        signals_created=None,
        correlations_created=None,
        incidents_created=None,
        failure_phase=None,
    )
    runs.start_run(active)

    assert recover_interrupted_runs(runs, interrupted_at=STAMP) == 1

    assert runs.get_run(first_run_id).status is AnalysisRunStatus.COMPLETED  # type: ignore[union-attr]
    interrupted = runs.get_run("run-object-b")
    assert interrupted is not None
    assert interrupted.status is AnalysisRunStatus.INTERRUPTED
    assert interrupted.finished_at == STAMP
    # Later objects have no rows; no batch/aggregate persistence exists.
    assert {run.analysis_run_id for run in runs.list_runs()} == {
        first_run_id,
        "run-object-b",
    }

    # Explicit replay is ordinary per-object analysis with new run rows.
    replayed = runner.run_cloudtrail_json(
        login_doc,
        source_type=AnalysisSourceType.S3_OBJECT,
        source_label="s3://bucket/logs/b-key.json",
    )
    assert replayed.analysis_run.analysis_run_id != "run-object-b"
    assert runs.get_run("run-object-b").status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# M34 provenance with interrupted runs (§39)
# ---------------------------------------------------------------------------


def test_provenance_omits_unassociated_interrupted_run(tmp_path: Path) -> None:
    database = tmp_path / "prov.sqlite3"
    repository, runner = _sqlite_runner(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    repository.start_run(_running_record("run-inherited"))
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        result.analysis_run.analysis_run_id
    ]


def test_replay_provenance_shows_new_run_not_the_interrupted_one(tmp_path: Path) -> None:
    database = tmp_path / "provreplay.sqlite3"
    repository, runner = _sqlite_runner(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    old_run_id = result.analysis_run.analysis_run_id
    repository.start_run(_running_record("run-inherited"))
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1

    replayed = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert replayed.incident_count == 0
    new_run_id = replayed.analysis_run.analysis_run_id

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        old_run_id,
        new_run_id,
    ]
    for item in provenance.evidence:
        assert "run-inherited" not in item.observed_run_ids


def test_associated_interrupted_run_serializes_truthfully(tmp_path: Path) -> None:
    from trailweaver.api.app import create_app as _create_app

    database = tmp_path / "provassoc.sqlite3"
    repository, runner = _sqlite_runner(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    repository.start_run(_running_record("run-inherited"))
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO analysis_run_events (analysis_run_id, provider, event_identity)"
            " SELECT 'run-inherited', provider, event_identity FROM events LIMIT 1"
        )
        connection.commit()

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    by_id = {run.analysis_run_id: run for run in provenance.observing_runs}
    assert by_id["run-inherited"].status is AnalysisRunStatus.INTERRUPTED
    assert by_id["run-inherited"].started_at == STARTED
    assert by_id["run-inherited"].finished_at == STAMP

    client = _ApiClient(_create_app(repository=repository))
    payload = client.get(
        f"/api/v1/incidents/{result.incidents[0].incident_id}/provenance"
    ).json()
    statuses = {
        run["analysis_run_id"]: run["status"] for run in payload["observing_runs"]
    }
    assert statuses["run-inherited"] == "interrupted"
    assert set(payload) == {"incident_id", "summary", "observing_runs", "evidence"}
    assert set(payload["observing_runs"][0]) == {
        "analysis_run_id",
        "source_type",
        "source_label",
        "status",
        "started_at",
        "finished_at",
    }
    assert "analysis_run_id" not in set(payload["evidence"][0])


# ---------------------------------------------------------------------------
# Concurrency and single-owner boundary (§40)
# ---------------------------------------------------------------------------


def test_recovery_conflicting_writer_fails_safely_then_succeeds(tmp_path: Path) -> None:
    database = tmp_path / "locked.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.start_run(_running_record("run-inherited"))

    holder = sqlite3.connect(database, timeout=5.0)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(AnalysisRunRepositoryError):
            recover_interrupted_runs(repository, interrupted_at=STAMP)
    finally:
        holder.rollback()
        holder.close()

    assert repository.get_run("run-inherited").status is AnalysisRunStatus.RUNNING  # type: ignore[union-attr]
    assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1


def test_no_lease_heartbeat_or_stale_age_mechanism_exists(tmp_path: Path) -> None:
    database = tmp_path / "nomech.sqlite3"
    SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'analysis_runs'"
        ).fetchone()[0]
        columns = [row[1] for row in connection.execute("PRAGMA table_info(analysis_runs)")]
        tables = _table_set(database)

    lowered = ddl.lower()
    for marker in ("lease", "heartbeat", "owner", "epoch", "process", "host", "session", "stale"):
        assert marker not in lowered
        assert marker not in [column.lower() for column in columns]
    assert tables == _EXPECTED_TABLES


# ---------------------------------------------------------------------------
# Security: recovery exposes and logs nothing sensitive (§41)
# ---------------------------------------------------------------------------


def test_recovery_logging_carries_only_safe_fields(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repository, _ = _sqlite_runner(tmp_path / "logs.sqlite3")
    repository.start_run(_running_record("run-inherited"))

    with caplog.at_level(logging.INFO, logger="trailweaver.recovery"):
        assert recover_interrupted_runs(repository, interrupted_at=STAMP) == 1

    completed = [record for record in caplog.records if record.getMessage() == "analysis_run_recovery_completed"]
    assert len(completed) == 1
    assert completed[0].trailweaver_fields == {"interrupted_runs": 1}


def test_recovery_failure_logging_carries_only_error_type(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    database = tmp_path / "logfail.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.start_run(_running_record("run-bad"))
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'x' WHERE analysis_run_id = 'run-bad'"
        )
        connection.commit()

    with caplog.at_level(logging.INFO, logger="trailweaver.recovery"), pytest.raises(
        AnalysisRunRecoveryError
    ):
        recover_interrupted_runs(repository, interrupted_at=STAMP)

    failed = [record for record in caplog.records if record.getMessage() == "analysis_run_recovery_failed"]
    assert len(failed) == 1
    assert failed[0].trailweaver_fields == {"error_type": "InvalidStoredAnalysisRunError"}
