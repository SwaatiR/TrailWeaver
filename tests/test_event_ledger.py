"""Focused tests for persistent event-level idempotency (M31).

M31 provides sequential/replay idempotency: an event identity successfully
processed by a completed run is recognized - but never reprocessed - by
later runs. It deliberately does NOT provide concurrent exactly-once
processing; two genuinely concurrent runs may both process the same event.
Duplicate work is acceptable; silent evidence suppression is not.
"""

import json
import sqlite3
from asyncio import run
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest

from trailweaver.analysis_runs import (
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.app import create_app
from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import (
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)
from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.event_ledger import (
    EventIdentity,
    EventLedgerError,
    InMemoryEventLedger,
)
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.observability import configure_logging
from trailweaver.rules import AWS_RULES

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"

STARTED = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
FINISHED = STARTED + timedelta(seconds=2)


def _attack_document() -> dict[str, Any]:
    return json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))


def _document_with(*event_names: str) -> str:
    records = [
        record
        for record in _attack_document()["Records"]
        if record["eventName"] in event_names
    ]
    assert records, "fixture must contain the requested records"
    return json.dumps({"Records": records})


def _document_without_ids() -> str:
    document = _attack_document()
    for record in document["Records"]:
        del record["eventID"]
    return json.dumps(document)


def _sqlite_runner(database: Path) -> tuple[
    SQLiteIncidentRepository, InvestigationRunner
]:
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    return repository, runner


def _associations(database: Path) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(database)
    try:
        return [
            (row[0], row[1], row[2])
            for row in connection.execute(
                "SELECT analysis_run_id, provider, event_identity "
                "FROM analysis_run_events ORDER BY rowid"
            ).fetchall()
        ]
    finally:
        connection.close()


def _event_rows(database: Path) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(database)
    try:
        return [
            (row[0], row[1], row[2])
            for row in connection.execute(
                "SELECT provider, event_identity, first_seen_at FROM events ORDER BY sequence"
            ).fetchall()
        ]
    finally:
        connection.close()


class _FailingDetectionEngine:
    def evaluate(self, _event: object) -> tuple[()]:
        raise RuntimeError("detection failed")


class _FailingCorrelationEngine:
    history_window = timedelta(minutes=15)

    def evaluate(self, _signals: object) -> tuple[()]:
        raise RuntimeError("correlation failed")


class _FailingIncidentFactory(IncidentFactory):
    def create(
        self,
        correlation_match: object,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
    ) -> Incident:
        del correlation_match, incident_id, created_at
        raise RuntimeError("incident creation failed")


class _FailingIncidentRepository(InMemoryIncidentRepository):
    def save_incident(self, incident: Incident) -> None:
        del incident
        raise RuntimeError("repository unavailable")


class _UnreadableLedger(InMemoryEventLedger):
    def known_identities(self, identities):  # type: ignore[no-untyped-def]
        del identities
        raise EventLedgerError("ledger read unavailable")


class _UnwritableLedger(InMemoryEventLedger):
    def acknowledge_run_events(self, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        raise EventLedgerError("ledger write unavailable")


def test_event_identity_requires_non_empty_provider_and_id() -> None:
    assert EventIdentity(provider="aws", event_id="abc") == EventIdentity(
        provider="aws", event_id="abc"
    )
    assert EventIdentity(provider="aws", event_id="abc") != EventIdentity(
        provider="gcp", event_id="abc"
    )
    assert hash(EventIdentity(provider="aws", event_id="abc")) == hash(
        EventIdentity(provider="aws", event_id="abc")
    )
    for provider, event_id in (
        ("", "abc"),
        ("   ", "abc"),
        ("aws", ""),
        ("aws", "   "),
    ):
        with pytest.raises(ValueError):
            EventIdentity(provider=provider, event_id=event_id)


def test_in_memory_membership_acknowledgement_and_multi_run_association() -> None:
    ledger = InMemoryEventLedger()
    identity = EventIdentity(provider="aws", event_id="abc")

    assert ledger.known_identities([]) == frozenset()
    assert ledger.known_identities([identity]) == frozenset()

    ledger.acknowledge_run_events(
        analysis_run_id="run-a", finished_at=FINISHED, observed=[identity]
    )
    ledger.acknowledge_run_events(
        analysis_run_id="run-a", finished_at=FINISHED, observed=[identity]
    )
    ledger.acknowledge_run_events(
        analysis_run_id="run-b", finished_at=FINISHED, observed=[identity]
    )

    assert ledger.known_identities([identity]) == frozenset({identity})
    assert len(ledger._associations) == 2


def test_in_memory_acknowledge_validates_its_arguments() -> None:
    ledger = InMemoryEventLedger()
    identity = EventIdentity(provider="aws", event_id="abc")

    with pytest.raises(ValueError):
        ledger.acknowledge_run_events(
            analysis_run_id="  ", finished_at=FINISHED, observed=[identity]
        )
    with pytest.raises(ValueError):
        ledger.acknowledge_run_events(
            analysis_run_id="run-a",
            finished_at=datetime(2026, 10, 4, 10, 0),  # noqa: DTZ001
            observed=[identity],
        )


def test_sqlite_event_tables_hold_identity_only_with_exact_columns(
    tmp_path: Path,
) -> None:
    database = tmp_path / "ledger.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    runner.run_cloudtrail_file(
        ATTACK_FIXTURE, source_label="/private/aws/accounts/export.json"
    )

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert {
            row[1]
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        } == {"sequence", "provider", "event_identity", "first_seen_at"}
        assert {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(analysis_run_events)"
            ).fetchall()
        } == {"analysis_run_id", "provider", "event_identity"}
        values = " ".join(
            str(value)
            for row in connection.execute(
                "SELECT provider, event_identity, first_seen_at FROM events"
            ).fetchall()
            for value in row
        )
    finally:
        connection.close()

    assert len(values.split()) == 9
    for forbidden in (
        "requestParameters",
        "userIdentity",
        "raw_event",
        "source_ip",
        "/private/aws/accounts",
        "arn:aws",
    ):
        assert forbidden not in values
    assert repository.known_identities(
        [EventIdentity(provider="aws", event_id="nope")]
    ) == frozenset()


def test_sqlite_reopen_preserves_identities_and_associations(
    tmp_path: Path,
) -> None:
    database = tmp_path / "reopen.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    associations_before = _associations(database)

    reopened = SQLiteIncidentRepository(database)
    identities = [
        EventIdentity(provider="aws", event_id=event_id)
        for event_id in (
            "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
            "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
            "cccccccc-3333-4333-8333-cccccccccccc",
        )
    ]
    assert reopened.known_identities(identities) == frozenset(identities)
    assert _associations(database) == associations_before
    assert len(_event_rows(database)) == 3

    second_runner = create_default_investigation_runner(
        reopened,
        analysis_run_repository=reopened,
        event_ledger_repository=reopened,
    )
    second = second_runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert second.signal_count == 0
    assert second.incident_count == 0
    assert first.analysis_run.analysis_run_id != second.analysis_run.analysis_run_id


def test_sqlite_acknowledge_for_unknown_run_is_a_storage_error(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "unknown.sqlite3")

    with pytest.raises(EventLedgerError):
        repository.acknowledge_run_events(
            analysis_run_id="missing-run",
            finished_at=FINISHED,
            observed=[EventIdentity(provider="aws", event_id="abc")],
        )


def test_sqlite_acknowledge_error_message_carries_no_user_data(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "message.sqlite3")

    with pytest.raises(EventLedgerError) as error:
        repository.acknowledge_run_events(
            analysis_run_id="missing-run",
            finished_at=FINISHED,
            observed=[EventIdentity(provider="aws", event_id="marker-secret-value")],
        )

    assert str(error.value) == "Unable to acknowledge run events"


def test_ledger_storage_failure_surfaces_as_ledger_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "unavailable.sqlite3")

    def _unavailable(*args: object, **kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("storage unavailable for this test")

    monkeypatch.setattr(sqlite3, "connect", _unavailable)
    with pytest.raises(EventLedgerError, match="Unable to check event identities"):
        repository.known_identities([EventIdentity(provider="aws", event_id="abc")])
    with pytest.raises(EventLedgerError, match="Unable to acknowledge run events"):
        repository.acknowledge_run_events(
            analysis_run_id="run-1",
            finished_at=FINISHED,
            observed=[EventIdentity(provider="aws", event_id="abc")],
        )


def test_v2_database_migrates_to_v4_preserving_all_existing_data(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v2.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    run_id = result.analysis_run.analysis_run_id
    incident_id = result.incidents[0].incident_id
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE signal_history")
        connection.execute("DROP TABLE emitted_correlations")
        connection.execute("DROP TABLE analysis_run_events")
        connection.execute("DROP TABLE events")
        connection.execute("PRAGMA user_version = 2")

    migrated = SQLiteIncidentRepository(database)

    assert migrated.get_incident(incident_id) is not None
    assert migrated.get_run(run_id) is not None
    assert migrated.list_runs()[0].analysis_run_id == run_id
    assert migrated.known_identities([]) == frozenset()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM analysis_run_events"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM signal_history"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM emitted_correlations"
        ).fetchone() == (0,)
    assert SQLiteIncidentRepository(database).list_runs()[0].analysis_run_id == run_id


def test_failed_v2_migration_leaves_version_and_data_untouched(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broken-v2.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    runner.run_cloudtrail_file(ATTACK_FIXTURE)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE IF EXISTS signal_history")
        connection.execute("DROP TABLE IF EXISTS emitted_correlations")
        connection.execute("DROP TABLE analysis_run_events")
        connection.execute("DROP TABLE events")
        connection.execute("CREATE VIEW events AS SELECT 1 AS value")
        connection.execute("PRAGMA user_version = 2")

    with pytest.raises(IncidentRepositoryError):
        SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert connection.execute(
            "SELECT type FROM sqlite_master WHERE name = 'events'"
        ).fetchone() == ("view",)
    reopened = sqlite3.connect(database)
    try:
        assert reopened.execute("SELECT COUNT(*) FROM incidents").fetchone() == (1,)
    finally:
        reopened.close()


def test_first_run_processes_and_acknowledges_everything(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "first.sqlite3")

    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert result.signal_count == 3
    assert result.incident_count == 1
    assert len(_event_rows(tmp_path / "first.sqlite3")) == 3
    associations = _associations(tmp_path / "first.sqlite3")
    assert len(associations) == 3
    assert {row[0] for row in associations} == {
        result.analysis_run.analysis_run_id
    }
    assert repository.known_identities([]) == frozenset()


def test_sequential_duplicate_run_skips_known_events_but_records_observation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "sequential.sqlite3"
    repository, runner = _sqlite_runner(database)

    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    second = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert first.analysis_run.analysis_run_id != second.analysis_run.analysis_run_id
    assert second.analyzed_event_count == 0
    assert second.signal_count == 0
    assert second.correlation_count == 0
    assert second.incident_count == 0
    assert second.analysis_run.records_seen == 3
    assert second.analysis_run.records_accepted == 3
    assert len(repository.list_incidents()) == 1
    associations = _associations(database)
    assert sorted({row[0] for row in associations}) == sorted(
        [
            first.analysis_run.analysis_run_id,
            second.analysis_run.analysis_run_id,
        ]
    )
    assert len(associations) == 6
    assert len(_event_rows(database)) == 3


def test_mixed_run_correlates_new_signals_with_history_without_redetecting(
    tmp_path: Path,
) -> None:
    database = tmp_path / "mixed.sqlite3"
    repository, runner = _sqlite_runner(database)

    only_attach = runner.run_cloudtrail_json(
        _document_with("AttachUserPolicy"), source_label="first.json"
    )
    assert only_attach.signal_count == 1
    assert only_attach.incident_count == 0

    combined = runner.run_cloudtrail_json(
        ATTACK_FIXTURE.read_text(encoding="utf-8"), source_label="second.json"
    )

    assert combined.analyzed_event_count == 2
    assert combined.signal_count == 2
    assert combined.correlation_count == 1
    assert combined.incident_count == 1
    assert [entry.rule_id for entry in combined.incidents[0].timeline] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]
    assert len(repository.list_incidents()) == 1
    associations = _associations(database)
    assert sorted(row[0] for row in associations).count(
        combined.analysis_run.analysis_run_id
    ) == 3
    assert len(_event_rows(database)) == 3


def test_events_without_ids_are_always_processed_and_never_stored(
    tmp_path: Path,
) -> None:
    database = tmp_path / "noid.sqlite3"
    _repository, runner = _sqlite_runner(database)
    document = _document_without_ids()

    first = runner.run_cloudtrail_json(document, source_label="first.json")
    second = runner.run_cloudtrail_json(document, source_label="second.json")

    assert first.signal_count == 3
    assert second.signal_count == 3
    assert first.incident_count == 1
    assert second.incident_count == 1
    assert len(_event_rows(database)) == 0
    assert _associations(database) == []


def test_failure_at_each_phase_marks_nothing_and_allows_retry(tmp_path: Path) -> None:
    import trailweaver.api.execution as execution_module

    database = tmp_path / "retry.sqlite3"
    repository = SQLiteIncidentRepository(database)
    original_ordering = execution_module._order_events_for_analysis

    def _failing_runner(stage: str) -> InvestigationRunner:
        return InvestigationRunner(
            detection_engine=(
                _FailingDetectionEngine() if stage == "detection" else DetectionEngine(AWS_RULES)  # type: ignore[arg-type]
            ),
            correlation_engine=(
                _FailingCorrelationEngine() if stage == "correlation" else CorrelationEngine(AWS_CORRELATION_RULES)  # type: ignore[arg-type]
            ),
            incident_factory=(
                _FailingIncidentFactory() if stage == "creation" else IncidentFactory()
            ),
            incident_repository=InMemoryIncidentRepository(),
            analysis_run_repository=repository,
            event_ledger_repository=repository,
        )

    def _fail_ordering(_events):  # type: ignore[no-untyped-def]
        raise RuntimeError("ordering failed")

    try:
        execution_module._order_events_for_analysis = _fail_ordering  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="ordering failed"):
            _failing_runner("ordering").run_cloudtrail_file(ATTACK_FIXTURE)
        assert len(_event_rows(database)) == 0
        assert _associations(database) == []
    finally:
        execution_module._order_events_for_analysis = original_ordering  # type: ignore[method-assign]

    for stage in ("detection", "correlation", "creation"):
        with pytest.raises(RuntimeError):
            _failing_runner(stage).run_cloudtrail_file(ATTACK_FIXTURE)
        assert len(_event_rows(database)) == 0
        assert _associations(database) == []

    healthy = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    result = healthy.run_cloudtrail_file(ATTACK_FIXTURE)
    assert result.signal_count == 3
    assert result.incident_count == 1
    assert len(_event_rows(database)) == 3


def test_incident_persistence_failure_marks_nothing_and_allows_retry(
    tmp_path: Path,
) -> None:
    database = tmp_path / "persist-retry.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=_FailingIncidentRepository(),
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )

    with pytest.raises(RuntimeError, match="repository unavailable"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert len(_event_rows(database)) == 0
    assert _associations(database) == []

    healthy = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
    )
    result = healthy.run_cloudtrail_file(ATTACK_FIXTURE)
    assert result.signal_count == 3
    assert result.incident_count == 1


def test_ledger_read_failure_stops_processing_without_failed_row(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "readfail.sqlite3")
    incidents = InMemoryIncidentRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents,
        analysis_run_repository=repository,
        event_ledger_repository=_UnreadableLedger(),
    )

    with pytest.raises(EventLedgerError, match="ledger read unavailable"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    runs = repository.list_runs()
    assert len(runs) == 1
    assert runs[0].status.value == "running"
    assert incidents.list_incidents() == ()


def test_acknowledgement_failure_returns_no_result_and_keeps_retry_possible(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "ackfail.sqlite3")
    incidents = InMemoryIncidentRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents,
        analysis_run_repository=repository,
        event_ledger_repository=_UnwritableLedger(),
    )

    with pytest.raises(EventLedgerError, match="ledger write unavailable"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    runs = repository.list_runs()
    assert len(runs) == 1
    assert runs[0].status.value == "completed"
    assert len(incidents.list_incidents()) == 1

    healthy = create_default_investigation_runner(
        incidents, event_ledger_repository=InMemoryEventLedger()
    )
    retry = healthy.run_cloudtrail_file(ATTACK_FIXTURE)
    # The retry redetects everything (nothing was acknowledged) but the
    # durable tombstone suppresses a second incident for the same evidence.
    assert retry.signal_count == 3
    assert retry.incident_count == 0
    assert len(incidents.list_incidents()) == 1


def test_crash_leaves_running_row_and_retryable_evidence(tmp_path: Path) -> None:
    database = tmp_path / "crash.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.start_run(
        AnalysisRunRecord(
            analysis_run_id="crashed-run",
            source_type=AnalysisSourceType.LOCAL_FILE,
            source_label="crash.json",
            status=AnalysisRunStatus.RUNNING,
            started_at=STARTED,
            finished_at=None,
            records_seen=3,
            records_accepted=3,
            signals_created=None,
            correlations_created=None,
            incidents_created=None,
            failure_phase=None,
        )
    )

    reopened = SQLiteIncidentRepository(database)
    assert reopened.get_run("crashed-run").status.value == "running"
    assert _associations(database) == []

    runner = create_default_investigation_runner(
        reopened,
        analysis_run_repository=reopened,
        event_ledger_repository=reopened,
    )
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert result.signal_count == 3
    assert result.incident_count == 1


def test_concurrent_acknowledgement_is_idempotent_without_single_winner(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "concurrent.sqlite3")
    identity = EventIdentity(provider="aws", event_id="shared-event")
    for run_id in ("run-a", "run-b"):
        repository.start_run(
            AnalysisRunRecord(
                analysis_run_id=run_id,
                source_type=AnalysisSourceType.LOCAL_FILE,
                source_label="concurrent.json",
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
        )

    repository.acknowledge_run_events(
        analysis_run_id="run-a", finished_at=STARTED, observed=[identity]
    )
    repository.acknowledge_run_events(
        analysis_run_id="run-b", finished_at=FINISHED, observed=[identity]
    )
    repository.acknowledge_run_events(
        analysis_run_id="run-b", finished_at=FINISHED, observed=[identity]
    )

    assert _event_rows(tmp_path / "concurrent.sqlite3") == [
        ("aws", "shared-event", STARTED.isoformat(timespec="microseconds"))
    ]
    assert sorted(_associations(tmp_path / "concurrent.sqlite3")) == [
        ("run-a", "aws", "shared-event"),
        ("run-b", "aws", "shared-event"),
    ]


def test_count_semantics_after_filtering(tmp_path: Path) -> None:
    _repository, runner = _sqlite_runner(tmp_path / "counts.sqlite3")

    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    second = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert (first.analysis_run.records_seen, first.analysis_run.records_accepted) == (
        3,
        3,
    )
    assert second.analysis_run.records_seen == 3
    assert second.analysis_run.records_accepted == 3
    assert second.analyzed_event_count == 0
    assert (
        second.analysis_run.signals_created,
        second.analysis_run.correlations_created,
        second.analysis_run.incidents_created,
    ) == (0, 0, 0)


def test_lifecycle_logs_report_new_and_duplicate_counts() -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)

    runner = create_default_investigation_runner(InMemoryIncidentRepository())
    runner.run_cloudtrail_file(ATTACK_FIXTURE)
    runner.run_cloudtrail_file(ATTACK_FIXTURE)

    import json as json_module

    records = [json_module.loads(line) for line in stream.getvalue().splitlines()]
    started = [record for record in records if record["event"] == "investigation_started"]
    assert [record["events_new"] for record in started] == [3, 0]
    assert [record["events_duplicate"] for record in started] == [0, 3]
    assert "requestParameters" not in stream.getvalue()
    assert "raw_event" not in stream.getvalue()


def test_analysis_response_schema_is_unchanged(tmp_path: Path) -> None:
    async def _post() -> httpx.Response:
        transport = httpx.ASGITransport(
            app=create_app(
                repository=SQLiteIncidentRepository(tmp_path / "schema.sqlite3")
            )
        )
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.post(
                "/api/v1/analyses/file",
                content=(SAMPLES / "account-compromise-sequence.json").read_bytes(),
                headers={"Content-Type": "application/json"},
            )

    body = run(_post()).json()

    assert set(body) == {
        "analysis_run_id",
        "source_type",
        "started_at",
        "completed_at",
        "source_label",
        "total_records",
        "accepted_records",
        "failed_records",
        "duplicate_records",
        "events_analyzed",
        "signals",
        "correlations",
        "incidents_created",
        "persisted_incidents",
        "incident_ids",
        "issues",
    }
