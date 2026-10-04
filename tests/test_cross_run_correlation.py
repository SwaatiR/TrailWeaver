"""Runner-level tests for persistent cross-run signal correlation (M32).

Signals produced by one successful run participate in correlations formed
by later runs. Duplicate durable output is impossible: deterministic
correlation evidence emits at most one incident through an atomic
persist-with-identity operation.
"""

import json
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.service import InMemoryIncidentRepository, SaveIncidentOutcome
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository
from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.observability import configure_logging
from trailweaver.rules import AWS_RULES
from trailweaver.signal_history import (
    InMemorySignalHistory,
    SignalHistoryError,
)

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"

LOGIN_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
KEY_ID = "cccccccc-3333-4333-8333-cccccccccccc"
ADMIN_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"

EXPECTED_TIMELINE_RULES = (
    "aws.auth.console_login_without_mfa",
    "aws.iam.access_key_created",
    "aws.iam.admin_policy_attached_to_user",
)


def _fixture_records() -> list[dict[str, Any]]:
    return json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))["Records"]


def _document_with(*event_names: str) -> str:
    records = [
        record for record in _fixture_records() if record["eventName"] in event_names
    ]
    assert records, "fixture must contain the requested records"
    return json.dumps({"Records": records})


def _shifted_document(minutes: int, event_name: str) -> str:
    records = [
        record for record in _fixture_records() if record["eventName"] == event_name
    ]
    assert records, "fixture must contain the requested record"
    for record in records:
        timestamp = datetime.fromisoformat(record["eventTime"])
        record["eventTime"] = (timestamp + timedelta(minutes=minutes)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    return json.dumps({"Records": records})


def _actor_swapped_document() -> str:
    records = _fixture_records()
    for record in records:
        if record["eventName"] == "ConsoleLogin":
            identity = record["userIdentity"]
            identity["principalId"] = "AIDAEXAMPLEOPERATOR"
            identity["arn"] = "arn:aws:iam::111122223333:user/operator"
            identity["userName"] = "operator"
    return json.dumps({"Records": records})


def _no_id_document() -> str:
    records = _fixture_records()
    for record in records:
        del record["eventID"]
    return json.dumps({"Records": records})


def _sqlite_runner(database: Path) -> tuple[
    SQLiteIncidentRepository, InvestigationRunner
]:
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    return repository, runner


class _FailOnceAtomicSaveRepository(InMemoryIncidentRepository):
    """Fails the second atomic save to exercise partial multi-incident failure."""

    def __init__(self) -> None:
        super().__init__()
        self.atomic_attempts = 0

    def save_incident_if_correlation_new(
        self, incident: Incident, correlation_key: str
    ) -> SaveIncidentOutcome:
        self.atomic_attempts += 1
        if self.atomic_attempts == 2:
            raise RuntimeError("second atomic save unavailable")
        return super().save_incident_if_correlation_new(incident, correlation_key)


class _FailingHistory(InMemorySignalHistory):
    def __init__(self, *, fail_on: str) -> None:
        super().__init__()
        self._fail_on = fail_on

    def store_signals(self, signals):  # type: ignore[no-untyped-def]
        if self._fail_on == "store":
            raise SignalHistoryError("signal history unavailable")
        return super().store_signals(signals)

    def candidate_signals(self, **kwargs):  # type: ignore[no-untyped-def]
        if self._fail_on == "read":
            raise SignalHistoryError("signal history read unavailable")
        return super().candidate_signals(**kwargs)


def test_three_separate_runs_form_one_incident(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "split.sqlite3")

    login = runner.run_cloudtrail_json(_document_with("ConsoleLogin"))
    assert login.signal_count == 1
    assert login.incident_count == 0

    key = runner.run_cloudtrail_json(_document_with("CreateAccessKey"))
    assert key.signal_count == 1
    assert key.incident_count == 0

    admin = runner.run_cloudtrail_json(_document_with("AttachUserPolicy"))
    assert admin.signal_count == 1
    assert admin.incident_count == 1
    assert [entry.rule_id for entry in admin.incidents[0].timeline] == list(
        EXPECTED_TIMELINE_RULES
    )


def test_two_runs_form_one_incident(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "two.sqlite3")

    first = runner.run_cloudtrail_json(_document_with("ConsoleLogin"))
    assert first.incident_count == 0

    second = runner.run_cloudtrail_json(
        _document_with("CreateAccessKey", "AttachUserPolicy")
    )
    assert second.signal_count == 2
    assert second.incident_count == 1
    assert len(repository.list_incidents()) == 1


def test_single_run_correlation_still_works(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "single.sqlite3")

    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert result.signal_count == 3
    assert result.incident_count == 1
    assert [entry.rule_id for entry in result.incidents[0].timeline] == list(
        EXPECTED_TIMELINE_RULES
    )


def test_out_of_order_arrival_correlates_when_temporal_order_permits(
    tmp_path: Path,
) -> None:
    _, runner = _sqlite_runner(tmp_path / "ooo.sqlite3")

    late_arriving_early_evidence = runner.run_cloudtrail_json(
        _document_with("CreateAccessKey", "AttachUserPolicy")
    )
    assert late_arriving_early_evidence.incident_count == 0

    login = runner.run_cloudtrail_json(_document_with("ConsoleLogin"))
    assert login.incident_count == 1
    assert [entry.rule_id for entry in login.incidents[0].timeline] == list(
        EXPECTED_TIMELINE_RULES
    )


def test_wrong_temporal_order_does_not_correlate(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "order.sqlite3")

    key = runner.run_cloudtrail_json(_document_with("CreateAccessKey"))
    admin_early = runner.run_cloudtrail_json(_shifted_document(-7, "AttachUserPolicy"))
    login = runner.run_cloudtrail_json(_document_with("ConsoleLogin"))

    assert key.incident_count == 0
    assert admin_early.incident_count == 0
    assert login.signal_count == 1
    assert login.incident_count == 0


def test_exact_window_boundary_preserved() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)

    runner.run_cloudtrail_json(_document_with("ConsoleLogin", "CreateAccessKey"))
    boundary = runner.run_cloudtrail_json(_shifted_document(5, "AttachUserPolicy"))
    assert boundary.incident_count == 1

    repository_late = InMemoryIncidentRepository()
    runner_late = create_default_investigation_runner(repository_late)
    runner_late.run_cloudtrail_json(_document_with("ConsoleLogin", "CreateAccessKey"))
    just_outside = runner_late.run_cloudtrail_json(
        _shifted_document(5, "AttachUserPolicy").replace("10:15:00Z", "10:15:01Z")
    )
    assert just_outside.incident_count == 0


def test_outside_window_rejected(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "window.sqlite3")

    runner.run_cloudtrail_json(_document_with("ConsoleLogin", "CreateAccessKey"))
    late = runner.run_cloudtrail_json(_shifted_document(20, "AttachUserPolicy"))

    assert late.signal_count == 1
    assert late.incident_count == 0


def test_actor_mismatch_prevents_cross_run_match(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "actor2.sqlite3")

    login_records = [
        record
        for record in json.loads(_actor_swapped_document())["Records"]
        if record["eventName"] == "ConsoleLogin"
    ]
    foreign_login = runner.run_cloudtrail_json(json.dumps({"Records": login_records}))
    assert foreign_login.signal_count == 1
    assert foreign_login.incident_count == 0

    home_sequence = runner.run_cloudtrail_json(
        _document_with("CreateAccessKey", "AttachUserPolicy")
    )
    # The foreign login must not join the home key/admin evidence.
    assert home_sequence.signal_count == 2
    assert home_sequence.incident_count == 0


def test_rediscovered_evidence_creates_no_second_incident(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "rediscover.sqlite3")

    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert first.incident_count == 1

    second = runner.run_cloudtrail_json(
        _document_with("CreateAccessKey", "AttachUserPolicy")
    )
    assert second.signal_count == 0
    assert second.correlation_count == 0
    assert second.incident_count == 0
    assert len(repository.list_incidents()) == 1


def test_novel_counts_exclude_rediscoveries(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "counts.sqlite3")

    runner.run_cloudtrail_file(ATTACK_FIXTURE)
    second = runner.run_cloudtrail_json(
        _document_with("ConsoleLogin", "CreateAccessKey", "AttachUserPolicy")
    )

    assert second.analysis_run.records_seen == 3
    assert second.analysis_run.records_accepted == 3
    assert second.analyzed_event_count == 0
    assert second.analysis_run.signals_created == 0
    assert second.analysis_run.correlations_created == 0
    assert second.analysis_run.incidents_created == 0


def _two_sequence_document() -> str:
    first = _fixture_records()
    second = json.loads(json.dumps(first))
    for position, record in enumerate(second):
        record["eventID"] = f"ffffffff-{position:04d}-4111-8111-ffffffffffff"
        timestamp = datetime.fromisoformat(record["eventTime"])
        record["eventTime"] = (timestamp + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    return json.dumps({"Records": first + second})


class _FailOnceAtomicSaveRepository(InMemoryIncidentRepository):
    """Fails the second atomic save once, then heals, tracking outcomes."""

    def __init__(self) -> None:
        super().__init__()
        self.atomic_attempts = 0
        self.outcomes: list[SaveIncidentOutcome] = []
        self._healed = False

    def heal(self) -> None:
        self._healed = True

    def save_incident_if_correlation_new(
        self, incident: Incident, correlation_key: str
    ) -> SaveIncidentOutcome:
        self.atomic_attempts += 1
        if self.atomic_attempts == 2 and not self._healed:
            raise RuntimeError("second atomic save unavailable")
        outcome = super().save_incident_if_correlation_new(incident, correlation_key)
        self.outcomes.append(outcome)
        return outcome


def test_partial_multi_incident_failure_recovers_without_duplicates(
    tmp_path: Path,
) -> None:
    database = tmp_path / "partial.sqlite3"
    repository = SQLiteIncidentRepository(database)
    failing = _FailOnceAtomicSaveRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=failing,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    document = _two_sequence_document()

    with pytest.raises(RuntimeError, match="second atomic save unavailable"):
        runner.run_cloudtrail_json(document, source_label="partial.json")
    assert len(failing.list_incidents()) == 1

    healed = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=failing,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    failing.heal()
    retry = healed.run_cloudtrail_json(document, source_label="partial-retry.json")

    assert retry.incident_count == 1
    assert len(failing.list_incidents()) == 2
    assert failing.outcomes.count(SaveIncidentOutcome.ALREADY_EMITTED) == 1
    assert failing.outcomes.count(SaveIncidentOutcome.CREATED) == 2


def test_none_id_evidence_still_correlates_within_one_run(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "noid.sqlite3")

    result = runner.run_cloudtrail_json(_no_id_document())

    assert result.signal_count == 3
    assert result.incident_count == 1


def test_none_id_replay_may_duplicate_but_never_suppresses(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "noid2.sqlite3")
    document = _no_id_document()

    first = runner.run_cloudtrail_json(document)
    second = runner.run_cloudtrail_json(document)

    assert first.incident_count == 1
    assert second.incident_count == 1
    assert len(repository.list_incidents()) == 2


def test_none_id_login_fuses_with_identified_history_but_replay_duplicates(
    tmp_path: Path,
) -> None:
    # None-ID evidence participates normally in current-run correlation, but
    # its incident key falls back to random UUIDs: replay duplicates instead
    # of suppressing. Duplicates possible; suppression impossible.
    _, runner = _sqlite_runner(tmp_path / "noidmix.sqlite3")

    runner.run_cloudtrail_json(_document_with("CreateAccessKey", "AttachUserPolicy"))
    login_only = json.loads(_no_id_document())
    login_records = [
        record
        for record in login_only["Records"]
        if record["eventName"] == "ConsoleLogin"
    ]
    fused = runner.run_cloudtrail_json(json.dumps({"Records": login_records}))
    assert fused.signal_count == 1
    assert fused.incident_count == 1

    replayed = runner.run_cloudtrail_json(json.dumps({"Records": login_records}))
    assert replayed.signal_count == 1
    assert replayed.incident_count == 1


def test_complete_run_failure_converges_without_duplicate_incidents(
    tmp_path: Path,
) -> None:
    from trailweaver.analysis_ledger import (
        AnalysisRunRepositoryError,
        InMemoryAnalysisRunRepository,
    )

    database = tmp_path / "complete-fail.sqlite3"
    repository = SQLiteIncidentRepository(database)
    incidents = InMemoryIncidentRepository()

    class FailingLedger(InMemoryAnalysisRunRepository):
        def complete_run(self, run):  # type: ignore[no-untyped-def]
            del run
            raise AnalysisRunRepositoryError("completion unavailable")

    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents,
        analysis_run_repository=FailingLedger(),
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    with pytest.raises(AnalysisRunRepositoryError, match="completion unavailable"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert len(incidents.list_incidents()) == 1

    healed = create_default_investigation_runner(
        incidents,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    retry = healed.run_cloudtrail_file(ATTACK_FIXTURE)
    assert retry.signal_count == 3
    assert retry.incident_count == 0
    assert len(incidents.list_incidents()) == 1


def test_signal_store_failure_leaves_no_failed_row_and_converges(
    tmp_path: Path,
) -> None:
    database = tmp_path / "store-fail.sqlite3"
    repository = SQLiteIncidentRepository(database)
    incidents = InMemoryIncidentRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=_FailingHistory(fail_on="store"),
    )

    with pytest.raises(SignalHistoryError):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert len(incidents.list_incidents()) == 1
    assert [record.status.value for record in repository.list_runs()] == ["running"]

    healed = create_default_investigation_runner(
        incidents,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    retry = healed.run_cloudtrail_file(ATTACK_FIXTURE)
    assert retry.incident_count == 0
    assert len(incidents.list_incidents()) == 1


def test_history_read_failure_stops_before_correlation(tmp_path: Path) -> None:
    database = tmp_path / "history-read-fail.sqlite3"
    repository = SQLiteIncidentRepository(database)
    incidents = InMemoryIncidentRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=IncidentFactory(),
        incident_repository=incidents,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=_FailingHistory(fail_on="read"),
    )

    with pytest.raises(SignalHistoryError):
        runner.run_cloudtrail_json(
            _document_with("ConsoleLogin", "CreateAccessKey", "AttachUserPolicy")
        )
    assert [record.status.value for record in repository.list_runs()] == ["running"]
    assert incidents.list_incidents() == ()


def test_lifecycle_logs_report_cross_run_counts(tmp_path: Path) -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)

    _, runner = _sqlite_runner(tmp_path / "logs.sqlite3")
    runner.run_cloudtrail_json(_document_with("ConsoleLogin"))
    runner.run_cloudtrail_json(_document_with("CreateAccessKey", "AttachUserPolicy"))

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    analyzed = [record for record in records if record["event"] == "investigation_analyzed"]
    assert [record["current_signals"] for record in analyzed] == [1, 2]
    assert [record["historical_candidates"] for record in analyzed] == [0, 1]
    assert [record["cross_run_correlations"] for record in analyzed] == [0, 1]


def test_cross_run_incident_supports_full_downstream_analysis(
    tmp_path: Path,
) -> None:
    from trailweaver.attack_graph import AttackGraphBuilder
    from trailweaver.investigation import InvestigationAdvisor
    from trailweaver.mitre import MitreMapper
    from trailweaver.risk import RiskScorer

    _, runner = _sqlite_runner(tmp_path / "downstream.sqlite3")
    runner.run_cloudtrail_json(_document_with("ConsoleLogin"))
    result = runner.run_cloudtrail_json(
        _document_with("CreateAccessKey", "AttachUserPolicy")
    )
    incident = result.incidents[0]

    assert RiskScorer().score(incident).score == 80
    assert [technique.technique_id for technique in MitreMapper().map(incident).techniques] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]
    graph = AttackGraphBuilder().build(incident)
    assert len(graph.nodes) > 0
    assert len(graph.edges) == 3
    guidance = InvestigationAdvisor().advise(incident)
    assert len(guidance.recommendations) > 0


def test_workspace_clear_preserves_history_and_tombstones(tmp_path: Path) -> None:
    import sqlite3 as sqlite3_module

    database = tmp_path / "clear.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert len(repository.list_incidents()) == 1

    repository.clear_incidents()

    connection = sqlite3_module.connect(database)
    try:
        history_rows = connection.execute(
            "SELECT COUNT(*) FROM signal_history"
        ).fetchone()[0]
        tombstone_rows = connection.execute(
            "SELECT COUNT(*) FROM emitted_correlations"
        ).fetchone()[0]
        event_rows = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        connection.close()
    assert history_rows == 3
    assert tombstone_rows == 1
    assert event_rows == 3
    assert repository.list_incidents() == ()

    replay = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert replay.signal_count == 0
    assert replay.incident_count == 0
    assert repository.list_incidents() == ()


def test_demo_reset_clears_history_and_tombstones_for_replay() -> None:
    import asyncio

    import httpx

    from trailweaver.api.demo import create_demo_app

    async def _post(app, path: str, payload: bytes | None = None):  # type: ignore[no-untyped-def]
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            if payload is None:
                return await client.post(path)
            return await client.post(
                path,
                content=payload,
                headers={"Content-Type": "application/json"},
            )

    async def _get(app, path: str):  # type: ignore[no-untyped-def]
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get(path)

    async def _flow() -> None:
        app = create_demo_app()
        fixture = ATTACK_FIXTURE.read_bytes()
        first = await _post(app, "/api/v1/analyses/file", fixture)
        assert first.status_code == 200
        assert first.json()["incidents_created"] == 1
        assert len((await _get(app, "/api/v1/incidents")).json()) == 1
        reset = await _post(app, "/api/v1/demo/reset")
        assert reset.status_code == 200
        assert (await _get(app, "/api/v1/incidents")).json() == []
        second = await _post(app, "/api/v1/analyses/file", fixture)
        assert second.status_code == 200
        assert second.json()["incidents_created"] == 1
        assert len((await _get(app, "/api/v1/incidents")).json()) == 1

    asyncio.run(_flow())
