"""v0.2 release gate: multi-epoch integration across ownership restarts (M36).

Each epoch constructs NEW repository/runner instances against the SAME SQLite
file; only the database carries state between epochs. This proves M29-M35
compose correctly across real persistent ownership restarts.
"""

import json
import sqlite3
from datetime import UTC, datetime
from io import BytesIO, StringIO
from pathlib import Path

from trailweaver.analysis_runs import (
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository
from trailweaver.aws_s3 import S3CloudTrailAdapter
from trailweaver.cli import main
from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.incidents import IncidentFactory
from trailweaver.recovery import recover_interrupted_runs
from trailweaver.rules import AWS_RULES
from trailweaver.signal_history import SignalHistoryError

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"

EXPECTED_TABLES = frozenset(
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


def _split_canonical() -> tuple[bytes, bytes, bytes]:
    """Return the proven login-only, key-only, admin-only documents by event name."""

    records = json.loads(ATTACK_FIXTURE.read_bytes().decode("utf-8"))["Records"]
    by_name = {record["eventName"]: record for record in records}
    assert set(by_name) == {"ConsoleLogin", "CreateAccessKey", "AttachUserPolicy"}

    def _doc(name: str) -> bytes:
        return json.dumps({"Records": [by_name[name]]}).encode("utf-8")

    return (
        _doc("ConsoleLogin"),
        _doc("CreateAccessKey"),
        _doc("AttachUserPolicy"),
    )


def _open_epoch(database: Path):  # type: ignore[no-untyped-def]
    """Construct fresh persistent repository and runner instances for one epoch."""

    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    return repository, runner


def _counts(database: Path) -> dict[str, int]:
    """Read exact durable cardinalities for the stores under review."""

    with sqlite3.connect(database) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "analysis_runs",
                "events",
                "analysis_run_events",
                "signal_history",
                "incidents",
                "correlation_matches",
                "emitted_correlations",
            )
        }


def _first_seen(database: Path) -> dict[tuple[str, str], str]:
    with sqlite3.connect(database) as connection:
        return {
            (row[0], row[1]): row[2]
            for row in connection.execute(
                "SELECT provider, event_identity, first_seen_at FROM events"
            ).fetchall()
        }


def _statuses(database: Path) -> list[tuple[str, str]]:
    with sqlite3.connect(database) as connection:
        return [
            (row[0], row[1])
            for row in connection.execute(
                "SELECT analysis_run_id, status FROM analysis_runs ORDER BY sequence"
            ).fetchall()
        ]


class _FailOnceSignalHistory:
    """Signal-history double failing the first store exactly once (crash boundary)."""

    def __init__(self, delegate: object) -> None:
        self._delegate = delegate
        self.stores = 0

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self._delegate, name)

    def store_signals(self, signals) -> None:  # type: ignore[no-untyped-def]
        self.stores += 1
        if self.stores == 1:
            raise SignalHistoryError("injected store failure")
        return self._delegate.store_signals(signals)


def _epoch_runner(repository: SQLiteIncidentRepository, **overrides):  # type: ignore[no-untyped-def]
    """Build a runner bound to one epoch's persistent repository with overrides."""

    return InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=repository,
        analysis_run_repository=overrides.get("analysis_run_repository", repository),
        event_ledger_repository=overrides.get("event_ledger_repository", repository),
        signal_history_repository=overrides.get("signal_history_repository", repository),
    )


def test_release_workflow_across_four_ownership_epochs(tmp_path: Path) -> None:
    database = tmp_path / "release.sqlite3"
    login_doc, key_doc, admin_doc = _split_canonical()

    # ---------------- Epoch 1: login-only analysis ----------------
    repository, runner = _open_epoch(database)
    login_result = runner.run_cloudtrail_json(login_doc, source_label="epoch1-login.json")
    login_run_id = login_result.analysis_run.analysis_run_id
    assert login_result.analysis_run.records_seen == 1
    assert login_result.analysis_run.records_accepted == 1
    assert login_result.analysis_run.signals_created == 1
    assert login_result.analysis_run.correlations_created == 0
    assert login_result.incident_count == 0
    assert _counts(database) == {
        "analysis_runs": 1,
        "events": 1,
        "analysis_run_events": 1,
        "signal_history": 1,
        "incidents": 0,
        "correlation_matches": 0,
        "emitted_correlations": 0,
    }
    login_first_seen = _first_seen(database)
    assert len(login_first_seen) == 1
    del repository, runner

    # ---------------- Epoch 2: restart, recover, key-only ----------------
    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    key_result = runner.run_cloudtrail_json(key_doc, source_label="epoch2-key.json")
    key_run_id = key_result.analysis_run.analysis_run_id
    assert key_run_id != login_run_id
    assert key_result.incident_count == 0
    # Historical correlation candidates came from durable SQLite history,
    # not from any retained Epoch-1 Python object.
    assert _counts(database) == {
        "analysis_runs": 2,
        "events": 2,
        "analysis_run_events": 2,
        "signal_history": 2,
        "incidents": 0,
        "correlation_matches": 0,
        "emitted_correlations": 0,
    }

    # ---------------- Epoch 2B: deliberate interruption ----------------
    failing_history = _FailOnceSignalHistory(repository)
    interrupted_runner = _epoch_runner(
        repository, signal_history_repository=failing_history
    )
    try:
        interrupted_runner.run_cloudtrail_json(admin_doc, source_label="epoch2-admin.json")
        raise AssertionError("store_signals fault did not trigger")
    except SignalHistoryError:
        pass
    assert _counts(database) == {
        "analysis_runs": 3,
        "events": 2,
        "analysis_run_events": 2,
        "signal_history": 2,
        "incidents": 1,
        "correlation_matches": 1,
        "emitted_correlations": 1,
    }
    with sqlite3.connect(database) as connection:
        admin_run_id = connection.execute(
            "SELECT analysis_run_id FROM analysis_runs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0]
        admin_status = connection.execute(
            "SELECT status FROM analysis_runs WHERE analysis_run_id = ?",
            (admin_run_id,),
        ).fetchone()[0]
    assert admin_status == "running"
    assert admin_run_id not in {login_run_id, key_run_id}
    del repository, runner, interrupted_runner, failing_history

    # ---------------- Epoch 3: recovery then explicit replay ----------------
    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 1
    recovered = repository.get_run(admin_run_id)
    assert recovered is not None
    assert recovered.status is AnalysisRunStatus.INTERRUPTED
    assert recovered.records_seen == 1
    assert recovered.records_accepted == 1
    assert recovered.signals_created is None
    assert recovered.correlations_created is None
    assert recovered.incidents_created is None
    assert recovered.failure_phase is None

    replay_result = runner.run_cloudtrail_json(admin_doc, source_label="epoch3-admin.json")
    replay_run_id = replay_result.analysis_run.analysis_run_id
    assert replay_run_id not in {login_run_id, key_run_id, admin_run_id}
    assert replay_result.incident_count == 0
    assert _counts(database) == {
        "analysis_runs": 4,
        "events": 3,
        "analysis_run_events": 3,
        "signal_history": 3,
        "incidents": 1,
        "correlation_matches": 1,
        "emitted_correlations": 1,
    }
    assert repository.get_run(admin_run_id).status is AnalysisRunStatus.INTERRUPTED  # type: ignore[union-attr]
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        assert "recovered_by" not in str(rows)
        assert "retry_of" not in str(rows)
    incident_id = repository.list_incidents()[0].incident_id
    del repository, runner

    # ---------------- Epoch 4: full replay of identified evidence ----------------
    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    seen_before = _first_seen(database)
    replay_ids: list[str] = []
    for label, document in (
        ("epoch4-login.json", login_doc),
        ("epoch4-key.json", key_doc),
        ("epoch4-admin.json", admin_doc),
    ):
        outcome = runner.run_cloudtrail_json(document, source_label=label)
        replay_ids.append(outcome.analysis_run.analysis_run_id)
        assert outcome.analysis_run.signals_created == 0
        assert outcome.analysis_run.correlations_created == 0
        assert outcome.incident_count == 0
    assert len(set(replay_ids)) == 3
    assert not (set(replay_ids) & {login_run_id, key_run_id, admin_run_id, replay_run_id})
    assert _counts(database) == {
        "analysis_runs": 7,
        "events": 3,
        "analysis_run_events": 6,
        "signal_history": 3,
        "incidents": 1,
        "correlation_matches": 1,
        "emitted_correlations": 1,
    }
    assert _first_seen(database) == seen_before

    # ---------------- Final release state ----------------
    final_statuses = _statuses(database)
    assert [status for _, status in final_statuses] == [
        "completed",
        "completed",
        "interrupted",
        "completed",
        "completed",
        "completed",
        "completed",
    ]
    assert [run_id for run_id, _ in final_statuses] == [
        login_run_id,
        key_run_id,
        admin_run_id,
        replay_run_id,
        *replay_ids,
    ]
    assert repository.list_incidents()[0].incident_id == incident_id
    assert len(repository.list_incidents()[0].correlation_match.signals) == 3

    provenance = repository.get_incident_provenance(incident_id)
    assert provenance is not None
    assert provenance.summary.identified_events_with_recorded_observations == 3
    assert provenance.summary.observing_run_count == 6
    for item in provenance.evidence:
        assert item.observation_state.value == "recorded"
        assert len(item.observed_run_ids) == 2
        assert admin_run_id not in item.observed_run_ids

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (5,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        tables = frozenset(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
    assert tables == EXPECTED_TABLES
    del repository, runner

    # Live repository connections keep enforcement enabled after everything.
    check_repository, _ = _open_epoch(database)
    enforcement = check_repository._connect()
    try:
        assert enforcement.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        enforcement.close()


def test_cross_run_correlation_survives_ownership_epochs(tmp_path: Path) -> None:
    database = tmp_path / "epochs.sqlite3"
    login_doc, key_doc, admin_doc = _split_canonical()

    repository, runner = _open_epoch(database)
    assert runner.run_cloudtrail_json(login_doc).incident_count == 0
    del repository, runner

    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    assert runner.run_cloudtrail_json(key_doc).incident_count == 0
    del repository, runner

    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    formed = runner.run_cloudtrail_json(admin_doc)
    assert formed.incident_count == 1
    assert _counts(database)["emitted_correlations"] == 1


def test_cli_two_invocations_share_only_the_database_file(tmp_path: Path) -> None:
    database = tmp_path / "cli-epochs.sqlite3"

    first_out, first_err = StringIO(), StringIO()
    first_run_line: str | None = None
    assert (
        main(
            ["--database", str(database), "analyze-file", str(ATTACK_FIXTURE)],
            environment={},
            stdout=first_out,
            stderr=first_err,
        )
        == 0
    )
    assert "incidents: 1" in first_out.getvalue()
    for line in first_out.getvalue().splitlines():
        if line.startswith("analysis run: "):
            first_run_line = line
    assert first_run_line is not None

    second_out, second_err = StringIO(), StringIO()
    assert (
        main(
            ["--database", str(database), "analyze-file", str(ATTACK_FIXTURE)],
            environment={},
            stdout=second_out,
            stderr=second_err,
        )
        == 0
    )
    second_run_line = next(
        line for line in second_out.getvalue().splitlines() if line.startswith("analysis run: ")
    )
    assert second_run_line != first_run_line
    assert "incidents: 0" in second_out.getvalue()
    assert "analysis_run_recovery_completed" in second_err.getvalue()

    repository, _ = _open_epoch(database)
    assert len(repository.list_incidents()) == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM emitted_correlations").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM signal_history").fetchone() == (3,)


def test_prefix_replay_across_epochs_without_batch_state(tmp_path: Path) -> None:
    login_doc, key_doc, admin_doc = _split_canonical()
    payloads = {
        "logs/a-login.json": login_doc,
        "logs/b-key.json": key_doc,
        "logs/c-admin.json": admin_doc,
    }

    class _EpochStore:
        def get_object(self, **kwargs: object):  # type: ignore[no-untyped-def]
            key = kwargs["Key"]
            assert isinstance(key, str)
            content = payloads[key]
            return {"Body": BytesIO(content), "ContentLength": len(content)}

        def list_objects_v2(self, **kwargs: object):  # type: ignore[no-untyped-def]
            prefix = kwargs["Prefix"]
            assert isinstance(prefix, str)
            keys = sorted(key for key in payloads if key.startswith(prefix))
            return {
                "Contents": [{"Key": key, "Size": len(payloads[key])} for key in keys],
                "IsTruncated": False,
            }

    database = tmp_path / "prefix-epochs.sqlite3"
    repository, runner = _open_epoch(database)
    adapter = S3CloudTrailAdapter(_EpochStore())  # type: ignore[arg-type]
    outcome = adapter.analyze_prefix(runner, bucket="example-bucket", prefix="logs/", max_objects=10)
    assert outcome.objects_succeeded == 3
    assert outcome.incidents_created == 1
    assert _table_set_for(database) == EXPECTED_TABLES
    del repository, runner

    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    replayed = adapter.analyze_prefix(
        runner, bucket="example-bucket", prefix="logs/", max_objects=10
    )
    assert replayed.objects_succeeded == 3
    assert replayed.incidents_created == 0
    counts = _counts(database)
    assert counts["incidents"] == 1
    assert counts["emitted_correlations"] == 1
    assert counts["signal_history"] == 3
    assert _table_set_for(database) == EXPECTED_TABLES


def _table_set_for(database: Path) -> frozenset[str]:
    with sqlite3.connect(database) as connection:
        return frozenset(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )


def test_none_id_replay_across_epochs_documents_the_boundary(tmp_path: Path) -> None:
    document = json.loads(ATTACK_FIXTURE.read_bytes().decode("utf-8"))
    for record in document["Records"]:
        del record["eventID"]
    payload = json.dumps(document).encode("utf-8")

    database = tmp_path / "noneid-epochs.sqlite3"
    repository, runner = _open_epoch(database)
    assert runner.run_cloudtrail_json(payload).incident_count == 1
    del repository, runner

    repository, runner = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 0
    assert runner.run_cloudtrail_json(payload).incident_count == 1
    counts = _counts(database)
    assert counts["events"] == 0
    assert counts["analysis_run_events"] == 0
    assert counts["signal_history"] == 0
    assert counts["incidents"] == 2
    provenance = repository.get_incident_provenance(
        repository.list_incidents()[0].incident_id
    )
    assert provenance is not None
    for item in provenance.evidence:
        assert item.observation_state.value == "identity_unavailable"


def test_interrupted_run_stays_out_of_epoch_provenance(tmp_path: Path) -> None:
    database = tmp_path / "prov-epochs.sqlite3"
    repository, runner = _open_epoch(database)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    repository.start_run(
        AnalysisRunRecord(
            analysis_run_id="run-inherited",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label=None,
            status=AnalysisRunStatus.RUNNING,
            started_at=datetime(2026, 10, 4, 10, 0, tzinfo=UTC),
            finished_at=None,
            records_seen=1,
            records_accepted=1,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )
    )
    del repository, runner

    repository, _ = _open_epoch(database)
    assert recover_interrupted_runs(repository) == 1
    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)
    assert provenance is not None
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        result.analysis_run.analysis_run_id
    ]
