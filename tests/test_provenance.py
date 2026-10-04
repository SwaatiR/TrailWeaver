"""Focused tests for read-only incident evidence provenance (M34)."""

import json
import sqlite3
from asyncio import run
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from trailweaver.analysis_ledger import InMemoryAnalysisRunRepository
from trailweaver.analysis_runs import (
    AnalysisFailurePhase,
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.app import create_app
from trailweaver.api.demo import create_demo_app
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
from trailweaver.event_ledger import InMemoryEventLedger
from trailweaver.incidents import IncidentFactory
from trailweaver.provenance import (
    InMemoryProvenanceReader,
    ObservationState,
    ProvenanceObservation,
    build_incident_provenance,
)
from trailweaver.rules import AWS_RULES

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail"


class _ApiClient:
    def __init__(self, application: FastAPI) -> None:
        self._application = application

    def get(self, path: str) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.get(path)

        return run(request())

    def post(
        self,
        path: str,
        *,
        content: bytes | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.post(
                    path, content=content, json=json_body, headers=headers
                )

        return run(request())


def _fixture(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def _split_fixture() -> tuple[bytes, bytes]:
    """Return the compromise fixture as login-only and key-plus-admin documents."""
    records = json.loads(_fixture("account-compromise-sequence.json").decode("utf-8"))[
        "Records"
    ]
    by_name = {record["eventName"]: record for record in records}
    login = json.dumps({"Records": [by_name["ConsoleLogin"]]}).encode("utf-8")
    rest = json.dumps(
        {
            "Records": [
                record
                for record in records
                if record["eventName"] != "ConsoleLogin"
            ]
        }
    ).encode("utf-8")
    return login, rest


def _strip_event_ids(payload: bytes) -> bytes:
    document = json.loads(payload.decode("utf-8"))
    for record in document["Records"]:
        del record["eventID"]
    return json.dumps(document).encode("utf-8")


def _sqlite_runner(database: Path):  # type: ignore[no-untyped-def]
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    return repository, runner


def _provenance_body(client: _ApiClient, incident_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/incidents/{incident_id}/provenance")
    assert response.status_code == 200
    return response.json()


def test_single_run_provenance_maps_every_event_to_its_run(
    tmp_path: Path,
) -> None:
    repository, runner = _sqlite_runner(tmp_path / "single.sqlite3")
    result = runner.run_cloudtrail_file(
        SAMPLES / "account-compromise-sequence.json",
        source_label="analyst-upload.json",
    )
    incident_id = result.incidents[0].incident_id
    run_id = result.analysis_run.analysis_run_id

    provenance = repository.get_incident_provenance(incident_id)
    assert provenance is not None
    assert provenance.incident_id == incident_id
    assert provenance.summary.evidence_signal_count == 3
    assert provenance.summary.identified_event_count == 3
    assert provenance.summary.identified_events_with_recorded_observations == 3
    assert provenance.summary.unidentified_signal_count == 0
    assert provenance.summary.observing_run_count == 1
    assert provenance.summary.source_types == ("local_file",)
    assert provenance.summary.event_time_start == datetime(
        2026, 9, 23, 10, 0, tzinfo=UTC
    )
    assert provenance.summary.event_time_end == datetime(
        2026, 9, 23, 10, 10, tzinfo=UTC
    )
    assert [run.analysis_run_id for run in provenance.observing_runs] == [run_id]
    observing = provenance.observing_runs[0]
    assert observing.source_type is AnalysisSourceType.LOCAL_FILE
    assert observing.source_label == "analyst-upload.json"
    assert observing.status.value == "completed"
    assert observing.finished_at is not None
    assert [item.signal_id for item in provenance.evidence] == [
        entry.signal_id for entry in result.incidents[0].timeline
    ]
    for item in provenance.evidence:
        assert item.observation_state is ObservationState.RECORDED
        assert item.event_id is not None
        assert item.first_recorded_at is not None
        assert item.observed_run_ids == (run_id,)


def test_cross_run_provenance_spans_three_runs(tmp_path: Path) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "cross.sqlite3")
    login, rest = _split_fixture()
    key_admin_records = json.loads(rest.decode("utf-8"))["Records"]
    by_event = {record["eventName"]: record for record in key_admin_records}
    key_doc = json.dumps({"Records": [by_event["CreateAccessKey"]]}).encode("utf-8")
    admin_doc = json.dumps({"Records": [by_event["AttachUserPolicy"]]}).encode(
        "utf-8"
    )

    def _runner() -> InvestigationRunner:
        return InvestigationRunner(
            detection_engine=DetectionEngine(AWS_RULES),
            correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
            incident_factory=IncidentFactory(),
            incident_repository=repository,
            analysis_run_repository=repository,
            event_ledger_repository=repository,
            signal_history_repository=repository,
        )

    first = _runner().run_cloudtrail_json(login, source_label="login.json")
    assert first.incident_count == 0
    second = _runner().run_cloudtrail_json(key_doc, source_label="key.json")
    assert second.incident_count == 0
    third = _runner().run_cloudtrail_json(admin_doc, source_label="admin.json")
    assert third.incident_count == 1

    provenance = repository.get_incident_provenance(third.incidents[0].incident_id)
    assert provenance is not None
    assert provenance.summary.observing_run_count == 3
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        first.analysis_run.analysis_run_id,
        second.analysis_run.analysis_run_id,
        third.analysis_run.analysis_run_id,
    ]
    assert provenance.summary.source_types == ("direct_input",)
    by_rule = {item.rule_id: item for item in provenance.evidence}
    assert by_rule["aws.auth.console_login_without_mfa"].observed_run_ids == (
        first.analysis_run.analysis_run_id,
    )
    assert by_rule["aws.iam.access_key_created"].observed_run_ids == (
        second.analysis_run.analysis_run_id,
    )
    assert by_rule["aws.iam.admin_policy_attached_to_user"].observed_run_ids == (
        third.analysis_run.analysis_run_id,
    )


def test_repeated_observation_lists_every_recorded_run(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "repeat.sqlite3")
    payload = _fixture("account-compromise-sequence.json")

    first = runner.run_cloudtrail_json(payload, source_label="first.json")
    second = runner.run_cloudtrail_json(payload, source_label="second.json")
    assert second.incident_count == 0

    provenance = repository.get_incident_provenance(first.incidents[0].incident_id)
    assert provenance is not None
    assert provenance.summary.observing_run_count == 2
    for item in provenance.evidence:
        assert item.observation_state is ObservationState.RECORDED
        assert item.observed_run_ids == (
            first.analysis_run.analysis_run_id,
            second.analysis_run.analysis_run_id,
        )


def test_source_label_passthrough_and_nullability(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "labels.sqlite3")
    labelled = runner.run_cloudtrail_json(
        _fixture("account-compromise-sequence.json"),
        source_label="/abs/path/export.json",
    )
    unlabelled = runner.run_cloudtrail_json(_fixture("empty-records.json"))

    labelled_provenance = repository.get_incident_provenance(
        labelled.incidents[0].incident_id
    )
    assert labelled_provenance is not None
    assert labelled_provenance.observing_runs[0].source_label == "export.json"
    assert unlabelled.analysis_run.source_label is None


def test_event_time_is_distinct_from_analysis_timestamps(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "times.sqlite3")
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)
    assert provenance is not None
    assert provenance.summary.event_time_start is not None
    assert provenance.summary.event_time_start.year == 2026
    assert provenance.summary.event_time_start < result.analysis_run.started_at
    for item in provenance.evidence:
        assert item.event_time < result.analysis_run.started_at
        assert item.first_recorded_at is not None
        assert item.first_recorded_at >= result.analysis_run.started_at


def test_none_id_evidence_reports_identity_unavailable(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "noid.sqlite3")
    result = runner.run_cloudtrail_json(
        _strip_event_ids(_fixture("account-compromise-sequence.json"))
    )
    assert result.incident_count == 1

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)
    assert provenance is not None
    assert provenance.summary.evidence_signal_count == 3
    assert provenance.summary.identified_event_count == 0
    assert provenance.summary.unidentified_signal_count == 3
    assert provenance.summary.observing_run_count == 0
    for item in provenance.evidence:
        assert item.observation_state is ObservationState.IDENTITY_UNAVAILABLE
        assert item.event_id is None
        assert item.first_recorded_at is None
        assert item.observed_run_ids == ()


def test_identified_evidence_without_association_reports_history_unavailable() -> None:
    incidents = InMemoryIncidentRepository()
    runs_repo = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    runner = create_default_investigation_runner(incidents)
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")

    reader = InMemoryProvenanceReader(incidents, runs_repo, ledger)
    provenance = reader.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    assert provenance.summary.identified_event_count == 3
    assert provenance.summary.identified_events_with_recorded_observations == 0
    assert provenance.summary.observing_run_count == 0
    for item in provenance.evidence:
        # Case B: no events row exists, so neither a first-recorded fact
        # nor run associations can be reported.
        assert item.observation_state is ObservationState.HISTORY_UNAVAILABLE
        assert item.event_id is not None
        assert item.first_recorded_at is None
        assert item.observed_run_ids == ()


def test_observation_cases_distinguish_missing_history_from_missing_identity() -> None:
    incidents = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(incidents)
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    incident = result.incidents[0]
    signals = incident.correlation_match.signals
    assert all(signal.source_event.event_id is not None for signal in signals)
    first_key = (
        signals[0].source_event.provider,
        signals[0].source_event.event_id,
    )
    assert first_key[1] is not None
    first_seen = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)

    rebuilt = build_incident_provenance(
        incident,
        run_records={},
        observations={
            # Case C: events row exists, but no run association survives.
            first_key: ProvenanceObservation(
                first_recorded_at=first_seen, run_ids=()
            ),
        },
    )

    assert rebuilt is not None
    assert rebuilt.evidence[0].observation_state is (
        ObservationState.HISTORY_UNAVAILABLE
    )
    assert rebuilt.evidence[0].first_recorded_at == first_seen
    assert rebuilt.evidence[0].observed_run_ids == ()
    for item in rebuilt.evidence[1:]:
        # Case B: no events row at all.
        assert item.observation_state is ObservationState.HISTORY_UNAVAILABLE
        assert item.first_recorded_at is None
        assert item.observed_run_ids == ()
    assert rebuilt.summary.identified_events_with_recorded_observations == 0
    assert rebuilt.summary.observing_run_count == 0


def test_partial_history_reports_recorded_subset(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "partial.sqlite3")
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    incident_id = result.incidents[0].incident_id
    database = tmp_path / "partial.sqlite3"
    connection = sqlite3_connect(database)
    try:
        connection.execute(
            "DELETE FROM analysis_run_events WHERE event_identity LIKE 'aaaa%'"
        )
        connection.commit()
    finally:
        connection.close()

    provenance = repository.get_incident_provenance(incident_id)
    assert provenance is not None
    assert provenance.summary.identified_event_count == 3
    assert provenance.summary.identified_events_with_recorded_observations == 2
    by_rule = {item.rule_id: item for item in provenance.evidence}
    orphaned = by_rule["aws.iam.admin_policy_attached_to_user"]
    assert orphaned.observation_state is ObservationState.HISTORY_UNAVAILABLE
    # Case C: the events row survives, so the first-recorded fact remains
    # reportable even though no run association survives.
    assert orphaned.first_recorded_at is not None
    assert orphaned.observed_run_ids == ()
    for rule_id, item in by_rule.items():
        if rule_id != "aws.iam.admin_policy_attached_to_user":
            assert item.observation_state is ObservationState.RECORDED
            assert item.first_recorded_at is not None


def test_events_row_without_any_association_keeps_first_recorded(
    tmp_path: Path,
) -> None:
    repository, runner = _sqlite_runner(tmp_path / "orphaned.sqlite3")
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    incident_id = result.incidents[0].incident_id
    database = tmp_path / "orphaned.sqlite3"
    connection = sqlite3_connect(database)
    try:
        connection.execute("DELETE FROM analysis_run_events")
        connection.commit()
    finally:
        connection.close()

    provenance = repository.get_incident_provenance(incident_id)

    assert provenance is not None
    assert provenance.summary.identified_event_count == 3
    assert provenance.summary.identified_events_with_recorded_observations == 0
    assert provenance.summary.observing_run_count == 0
    for item in provenance.evidence:
        assert item.observation_state is ObservationState.HISTORY_UNAVAILABLE
        assert item.event_id is not None
        assert item.first_recorded_at is not None
        assert item.observed_run_ids == ()


def sqlite3_connect(database: Path):  # type: ignore[no-untyped-def]
    import sqlite3

    return sqlite3.connect(database)


def test_unexpected_running_and_failed_runs_reconstruct_safely(
    tmp_path: Path,
) -> None:
    incidents = InMemoryIncidentRepository()
    runs = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    runner = create_default_investigation_runner(incidents)
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    incident = result.incidents[0]
    started = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
    for index, run_id in enumerate(("running-run", "failed-run")):
        runs.start_run(
            AnalysisRunRecord(
                analysis_run_id=run_id,
                source_type=AnalysisSourceType.DIRECT_INPUT,
                source_label=None,
                status=AnalysisRunStatus.RUNNING,
                started_at=started + timedelta(seconds=index),
                finished_at=None,
                records_seen=3,
                records_accepted=3,
                signals_created=None,
                correlations_created=None,
                incidents_created=None,
                failure_phase=None,
            )
        )
    runs.fail_run(
        "failed-run",
        failed_at=started + timedelta(seconds=10),
        failure_phase=AnalysisFailurePhase.DETECTION,
    )
    ledger.acknowledge_run_events(
        analysis_run_id="running-run",
        finished_at=started + timedelta(seconds=5),
        observed=[],
    )

    reader = InMemoryProvenanceReader(incidents, runs, ledger)
    provenance = reader.get_incident_provenance(incident.incident_id)

    assert provenance is not None
    assert provenance.summary.observing_run_count == 0
    for item in provenance.evidence:
        assert item.observation_state is ObservationState.HISTORY_UNAVAILABLE


def test_no_creation_run_is_ever_inferred(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "nocreation.sqlite3")
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)
    assert provenance is not None
    body = {
        "incident_id": provenance.incident_id,
        "summary": provenance.summary,
        "observing_runs": provenance.observing_runs,
        "evidence": provenance.evidence,
    }
    assert set(body) == {"incident_id", "summary", "observing_runs", "evidence"}


def test_unknown_incident_returns_none(tmp_path: Path) -> None:
    repository, _ = _sqlite_runner(tmp_path / "missing.sqlite3")

    assert repository.get_incident_provenance("missing-incident") is None


def test_malformed_stored_provenance_raises_storage_error(tmp_path: Path) -> None:
    database = tmp_path / "malformed.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    connection = sqlite3.connect(database)
    try:
        # Corrupt a run timestamp the provenance read must validate: the
        # column CHECK only requires non-empty text, so this writes
        # successfully but cannot reconstruct a valid run record.
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'not-a-timestamp',"
            " finished_at = 'not-a-timestamp'"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IncidentRepositoryError):
        repository.get_incident_provenance(result.incidents[0].incident_id)


def test_evidence_ordering_and_run_ordering_are_deterministic(
    tmp_path: Path,
) -> None:
    first_repository, _ = _sqlite_runner(tmp_path / "order.sqlite3")
    login, rest = _split_fixture()
    key_admin = json.loads(rest.decode("utf-8"))["Records"]
    key_doc = json.dumps({"Records": [key_admin[0]]}).encode("utf-8")
    admin_doc = json.dumps({"Records": [key_admin[1]]}).encode("utf-8")

    def _runner() -> InvestigationRunner:
        return InvestigationRunner(
            detection_engine=DetectionEngine(AWS_RULES),
            correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
            incident_factory=IncidentFactory(),
            incident_repository=first_repository,
            analysis_run_repository=first_repository,
            event_ledger_repository=first_repository,
            signal_history_repository=first_repository,
        )

    _runner().run_cloudtrail_json(login, source_label="b-login.json")
    _runner().run_cloudtrail_json(key_doc, source_label="a-key.json")
    third = _runner().run_cloudtrail_json(admin_doc, source_label="c-admin.json")

    provenance = first_repository.get_incident_provenance(
        third.incidents[0].incident_id
    )
    assert provenance is not None
    assert [item.rule_id for item in provenance.evidence] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]
    started = [run.started_at for run in provenance.observing_runs]
    assert started == sorted(started)
    assert [run.source_label for run in provenance.observing_runs] == [
        "b-login.json",
        "a-key.json",
        "c-admin.json",
    ]


def test_repeated_associations_do_not_duplicate_runs(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "repeat.sqlite3")
    payload = _fixture("account-compromise-sequence.json")

    first = runner.run_cloudtrail_json(payload, source_label="first.json")
    second = runner.run_cloudtrail_json(payload, source_label="second.json")
    assert second.incident_count == 0

    provenance = repository.get_incident_provenance(first.incidents[0].incident_id)
    assert provenance is not None
    assert provenance.summary.observing_run_count == 2
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        first.analysis_run.analysis_run_id,
        second.analysis_run.analysis_run_id,
    ]
    for item in provenance.evidence:
        assert item.observed_run_ids == (
            first.analysis_run.analysis_run_id,
            second.analysis_run.analysis_run_id,
        )


def test_provenance_api_single_run(tmp_path: Path) -> None:
    database = tmp_path / "api-single.sqlite3"
    client = _ApiClient(
        create_app(
            repository=SQLiteIncidentRepository(database)
        )
    )
    body = _fixture("account-compromise-sequence.json")
    created = client.post(
        "/api/v1/analyses/file",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_ids"][0]

    response = client.get(f"/api/v1/incidents/{incident_id}/provenance")

    assert response.status_code == 200
    payload = response.json()
    assert payload["incident_id"] == incident_id
    assert payload["summary"]["evidence_signal_count"] == 3
    assert payload["summary"]["identified_events_with_recorded_observations"] == 3
    assert payload["summary"]["observing_run_count"] == 1
    assert payload["summary"]["source_types"] == ["web_upload"]
    assert len(payload["observing_runs"]) == 1
    run = payload["observing_runs"][0]
    assert run["source_type"] == "web_upload"
    assert run["status"] == "completed"
    assert run["finished_at"] is not None
    assert len(payload["evidence"]) == 3
    assert all(
        item["observation_state"] == "recorded" for item in payload["evidence"]
    )


def test_provenance_api_multirun_partial_and_none_id() -> None:
    login, rest = _split_fixture()
    client = _ApiClient(
        create_app()
    )
    headers = {"Content-Type": "application/json"}
    first = client.post("/api/v1/analyses/file", content=login, headers=headers)
    assert first.status_code == 200
    second = client.post("/api/v1/analyses/file", content=rest, headers=headers)
    assert second.status_code == 200
    incident_id = second.json()["incident_ids"][0]

    multi = client.get(f"/api/v1/incidents/{incident_id}/provenance").json()

    assert multi["summary"]["observing_run_count"] == 2
    assert multi["summary"]["identified_events_with_recorded_observations"] == 3
    assert [item["observation_state"] for item in multi["evidence"]] == [
        "recorded",
        "recorded",
        "recorded",
    ]

    stripped = client.post(
        "/api/v1/analyses/file",
        content=_strip_event_ids(_fixture("account-compromise-sequence.json")),
        headers=headers,
    )
    assert stripped.status_code == 200
    none_id = client.get(
        f"/api/v1/incidents/{stripped.json()['incident_ids'][0]}/provenance"
    ).json()
    assert none_id["summary"]["unidentified_signal_count"] == 3
    assert none_id["summary"]["observing_run_count"] == 0
    assert {item["observation_state"] for item in none_id["evidence"]} == {
        "identity_unavailable"
    }

    key_admin = json.loads(rest.decode("utf-8"))["Records"]
    partial_client = _ApiClient(
        create_app()
    )
    partial_client.post("/api/v1/analyses/file", content=login, headers=headers)
    key_only = json.dumps({"Records": [key_admin[0]]}).encode("utf-8")
    partial_client.post("/api/v1/analyses/file", content=key_only, headers=headers)
    admin_only = json.dumps({"Records": [key_admin[1]]}).encode("utf-8")
    formed = partial_client.post(
        "/api/v1/analyses/file", content=admin_only, headers=headers
    )
    formed_id = formed.json()["incident_ids"][0]
    partial = partial_client.get(f"/api/v1/incidents/{formed_id}/provenance").json()
    assert partial["summary"]["identified_events_with_recorded_observations"] == 3
    assert partial["summary"]["observing_run_count"] == 3


def test_provenance_api_missing_incident_returns_404() -> None:
    client = _ApiClient(
        create_app()
    )

    response = client.get("/api/v1/incidents/missing/provenance")

    assert response.status_code == 404


def test_provenance_api_storage_failure_returns_503(tmp_path: Path) -> None:
    database = tmp_path / "broken.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE analysis_runs SET started_at = 'not-a-timestamp',"
            " finished_at = 'not-a-timestamp'"
        )
        connection.commit()
    finally:
        connection.close()

    client = _ApiClient(create_app(repository=repository))
    response = client.get(
        f"/api/v1/incidents/{result.incidents[0].incident_id}/provenance"
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Incident storage is unavailable"}
    with pytest.raises(IncidentRepositoryError):
        repository.get_incident_provenance(result.incidents[0].incident_id)


def test_provenance_api_preserves_null_source_label(tmp_path: Path) -> None:
    database = tmp_path / "nulllabel.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    # No source label: the run persists source_label NULL.
    result = runner.run_cloudtrail_json(
        _fixture("account-compromise-sequence.json")
    )
    assert result.analysis_run.source_label is None

    client = _ApiClient(create_app(repository=repository))
    response = client.get(
        f"/api/v1/incidents/{result.incidents[0].incident_id}/provenance"
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["observing_runs"]) == 1
    assert "source_label" in payload["observing_runs"][0]
    assert payload["observing_runs"][0]["source_label"] is None


def test_provenance_api_exact_response_keys() -> None:
    client = _ApiClient(
        create_app()
    )
    created = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    payload = client.get(
        f"/api/v1/incidents/{created.json()['incident_ids'][0]}/provenance"
    ).json()

    assert set(payload) == {"incident_id", "summary", "observing_runs", "evidence"}
    assert set(payload["summary"]) == {
        "evidence_signal_count",
        "identified_event_count",
        "identified_events_with_recorded_observations",
        "unidentified_signal_count",
        "observing_run_count",
        "source_types",
        "event_time_start",
        "event_time_end",
    }
    assert set(payload["observing_runs"][0]) == {
        "analysis_run_id",
        "source_type",
        "source_label",
        "status",
        "started_at",
        "finished_at",
    }
    assert set(payload["evidence"][0]) == {
        "signal_id",
        "rule_id",
        "title",
        "provider",
        "event_id",
        "event_time",
        "observation_state",
        "first_recorded_at",
        "observed_run_ids",
    }
    assert payload["observing_runs"][0]["source_label"] == "browser-upload"


def test_provenance_api_rejects_raw_evidence_markers() -> None:
    client = _ApiClient(
        create_app()
    )
    created = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    text = client.get(
        f"/api/v1/incidents/{created.json()['incident_ids'][0]}/provenance"
    ).text

    for marker in (
        "raw_event",
        "requestParameters",
        "userIdentity",
        "responseElements",
        "AKIA",
        "signed",
        "traceback",
        "ETag",
        "VersionId",
    ):
        assert marker not in text


def test_existing_incident_detail_schema_unchanged() -> None:
    client = _ApiClient(
        create_app()
    )
    created = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    body = client.get(
        f"/api/v1/incidents/{created.json()['incident_ids'][0]}"
    ).json()

    assert set(body) == {
        "incident_id",
        "title",
        "description",
        "severity",
        "summary",
        "created_at",
        "started_at",
        "ended_at",
        "primary_actor",
        "timeline",
    }


def test_m31_reobservation_lists_every_recorded_run(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "m31.sqlite3")
    payload = _fixture("account-compromise-sequence.json")

    first = runner.run_cloudtrail_json(payload, source_label="first.json")
    second = runner.run_cloudtrail_json(payload, source_label="second.json")
    assert second.incident_count == 0

    provenance = repository.get_incident_provenance(first.incidents[0].incident_id)
    assert provenance is not None
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        first.analysis_run.analysis_run_id,
        second.analysis_run.analysis_run_id,
    ]


def test_m32_split_runs_map_each_evidence_to_its_run(tmp_path: Path) -> None:
    login, rest = _split_fixture()
    key_admin = json.loads(rest.decode("utf-8"))["Records"]
    key_doc = json.dumps({"Records": [key_admin[0]]}).encode("utf-8")
    admin_doc = json.dumps({"Records": [key_admin[1]]}).encode("utf-8")
    repository, runner = _sqlite_runner(tmp_path / "m32.sqlite3")

    runner.run_cloudtrail_json(login, source_label="login.json")
    runner.run_cloudtrail_json(key_doc, source_label="key.json")
    third = runner.run_cloudtrail_json(admin_doc, source_label="admin.json")
    assert third.incident_count == 1

    provenance = repository.get_incident_provenance(third.incidents[0].incident_id)
    assert provenance is not None
    assert [run.source_label for run in provenance.observing_runs] == [
        "login.json",
        "key.json",
        "admin.json",
    ]


def test_prefix_replay_keeps_run_provenance_without_batch_concepts(
    tmp_path: Path,
) -> None:
    from trailweaver.aws_s3 import S3CloudTrailAdapter

    repository, runner = _sqlite_runner(tmp_path / "prefix.sqlite3")

    class _ObjectStore:
        def __init__(self, payloads: dict[str, bytes]) -> None:
            self._payloads = payloads

        def get_object(self, **kwargs: object) -> dict[str, Any]:
            from io import BytesIO

            key = kwargs["Key"]
            assert isinstance(key, str)
            content = self._payloads[key]
            return {"Body": BytesIO(content), "ContentLength": len(content)}

        def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
            prefix = kwargs["Prefix"]
            assert isinstance(prefix, str)
            keys = sorted(
                key for key in self._payloads if isinstance(key, str) and key.startswith(prefix)
            )
            return {
                "Contents": [
                    {"Key": key, "Size": len(self._payloads[key])} for key in keys
                ],
                "IsTruncated": False,
            }

    login, rest = _split_fixture()
    key_admin = json.loads(rest.decode("utf-8"))["Records"]
    payloads = {
        "logs/a-login.json": login,
        "logs/b-key.json": json.dumps({"Records": [key_admin[0]]}).encode("utf-8"),
        "logs/c-admin.json": json.dumps({"Records": [key_admin[1]]}).encode("utf-8"),
    }
    adapter = S3CloudTrailAdapter(_ObjectStore(payloads))  # type: ignore[arg-type]
    outcome = adapter.analyze_prefix(
        runner, bucket="example-bucket", prefix="logs/", max_objects=10
    )

    assert outcome.incidents_created == 1
    assert outcome.objects_succeeded == 3
    provenance = repository.get_incident_provenance(outcome.incident_ids[0])
    assert provenance is not None
    assert [run.source_type for run in provenance.observing_runs] == [
        AnalysisSourceType.S3_OBJECT,
        AnalysisSourceType.S3_OBJECT,
        AnalysisSourceType.S3_OBJECT,
    ]
    assert [run.source_label for run in provenance.observing_runs] == [
        "s3://example-bucket/logs/a-login.json",
        "s3://example-bucket/logs/b-key.json",
        "s3://example-bucket/logs/c-admin.json",
    ]

    replayed = adapter.analyze_prefix(
        runner, bucket="example-bucket", prefix="logs/", max_objects=10
    )
    assert replayed.incidents_created == 0
    rerun = repository.get_incident_provenance(outcome.incident_ids[0])
    assert rerun is not None
    assert rerun.summary.observing_run_count == 6


def test_workspace_clear_makes_provenance_404_but_keeps_ledger() -> None:
    client = _ApiClient(
        create_app()
    )
    created = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    incident_id = created.json()["incident_ids"][0]
    assert (
        client.get(f"/api/v1/incidents/{incident_id}/provenance").status_code == 200
    )

    cleared = client.post("/api/v1/workspace/clear", json_body={})
    assert cleared.status_code == 200

    assert client.get(f"/api/v1/incidents/{incident_id}/provenance").status_code == 404
    assert client.get("/api/v1/incidents").json() == []


def test_demo_reset_replay_shows_only_surviving_associations() -> None:
    client = _ApiClient(create_demo_app())
    payload = _fixture("account-compromise-sequence.json")
    headers = {"Content-Type": "application/json"}

    first = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    first_id = first.json()["incident_ids"][0]
    first_run = first.json()["analysis_run_id"]
    before = client.get(f"/api/v1/incidents/{first_id}/provenance").json()
    assert [run["analysis_run_id"] for run in before["observing_runs"]] == [first_run]

    assert client.post("/api/v1/demo/reset", json_body={}).status_code == 200
    assert client.get(f"/api/v1/incidents/{first_id}/provenance").status_code == 404

    second = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    second_id = second.json()["incident_ids"][0]
    second_run = second.json()["analysis_run_id"]
    assert second_id != first_id
    after = client.get(f"/api/v1/incidents/{second_id}/provenance").json()
    assert [run["analysis_run_id"] for run in after["observing_runs"]] == [second_run]


def test_only_relevant_runs_are_returned(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "scoped.sqlite3")
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    unrelated = runner.run_cloudtrail_json(_fixture("empty-records.json"))
    assert unrelated.analysis_run.analysis_run_id != result.analysis_run.analysis_run_id

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    assert provenance.summary.observing_run_count == 1
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        result.analysis_run.analysis_run_id
    ]


def test_provenance_does_not_require_signal_history(tmp_path: Path) -> None:
    database = tmp_path / "nohistory.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TABLE signal_history")
        connection.commit()
    finally:
        connection.close()

    provenance = repository.get_incident_provenance(result.incidents[0].incident_id)

    assert provenance is not None
    assert provenance.summary.identified_events_with_recorded_observations == 3
    assert provenance.summary.observing_run_count == 1


def test_build_provenance_orders_runs_by_start_then_insertion_sequence() -> None:
    incidents = InMemoryIncidentRepository()
    runs_repo = InMemoryAnalysisRunRepository()
    ledger = InMemoryEventLedger()
    runner = create_default_investigation_runner(
        incidents,
        analysis_run_repository=runs_repo,
        event_ledger_repository=ledger,
    )
    result = runner.run_cloudtrail_file(SAMPLES / "account-compromise-sequence.json")
    incident = result.incidents[0]

    reader = InMemoryProvenanceReader(incidents, runs_repo, ledger)
    provenance = reader.get_incident_provenance(incident.incident_id)

    assert provenance is not None
    assert [run.analysis_run_id for run in provenance.observing_runs] == [
        result.analysis_run.analysis_run_id
    ]
    # Lexical run-ID order must never drive semantics: rebuilding with an
    # explicit sequence keeps the same deterministic result.
    rebuilt = build_incident_provenance(
        incident,
        run_records={
            record.analysis_run_id: record for record in runs_repo.list_runs()
        },
        observations={
            key: ProvenanceObservation(
                first_recorded_at=first_seen, run_ids=run_ids
            )
            for key, (first_seen, run_ids) in ledger.recorded_observations().items()
        },
        run_sequence={
            record.analysis_run_id: index
            for index, record in enumerate(runs_repo.list_runs())
        },
    )
    assert [run.analysis_run_id for run in rebuilt.observing_runs] == [
        run.analysis_run_id for run in provenance.observing_runs
    ]
