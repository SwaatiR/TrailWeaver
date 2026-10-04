import asyncio
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi import FastAPI

from trailweaver.analysis_runs import AnalysisRun, AnalysisSourceType
from trailweaver.api.app import create_app
from trailweaver.api.execution import (
    InvestigationExecutionResult,
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.service import (
    IncidentAlreadyExistsError,
    InMemoryIncidentRepository,
)
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository
from trailweaver.cloudtrail_ingestion import (
    CloudTrailInvalidJsonError,
    ingest_cloudtrail_document,
)
from trailweaver.correlation import CorrelationEngine, CorrelationMatch
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.models import JsonObject
from trailweaver.rules import AWS_RULES

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"


def _attack_document() -> JsonObject:
    return cast(JsonObject, json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8")))


def _api_get(application: FastAPI, path: str) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get(path)

    return asyncio.run(request())


def test_default_runner_executes_real_attack_sequence_in_memory() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)

    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert isinstance(result, InvestigationExecutionResult)
    assert isinstance(result.analysis_run, AnalysisRun)
    assert result.analysis_run.source_type is AnalysisSourceType.LOCAL_FILE
    assert result.analysis_run.started_at.tzinfo is not None
    assert result.analysis_run.completed_at >= result.analysis_run.started_at
    assert result.ingestion_result.total_records == 3
    assert result.ingestion_result.accepted_records == 3
    assert result.ingestion_result.failed_records == 0
    assert result.ingestion_result.duplicate_records == 0
    assert result.analyzed_event_count == 3
    assert result.signal_count == 3
    assert result.correlation_count == 1
    assert result.incident_count == 1
    assert result.persisted_incident_count == 1
    assert tuple(signal.rule_id for signal in result.signals) == (
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    )
    assert result.correlations[0].rule_id == (
        "aws.identity.possible_account_compromise_sequence"
    )
    assert result.incidents[0].title == "Possible AWS account compromise"
    assert result.persisted_incidents == result.incidents
    assert repository.list_incidents() == result.incidents
    assert result.analysis_run.records_seen == 3
    assert result.analysis_run.records_accepted == 3
    assert result.analysis_run.signals_created == result.signal_count == 3
    assert result.analysis_run.correlations_created == result.correlation_count == 1
    assert result.analysis_run.incidents_created == result.incident_count == 1


def test_existing_ingestion_result_is_preserved_and_analyzed() -> None:
    ingestion_result = ingest_cloudtrail_document(
        _attack_document(), source_label="pre-ingested-upload"
    )

    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_ingestion_result(ingestion_result)

    assert result.ingestion_result is ingestion_result
    assert result.ingestion_result.source_label == "pre-ingested-upload"
    assert result.analysis_run.source_type is AnalysisSourceType.DIRECT_INPUT


def test_non_chronological_source_is_ordered_only_for_analysis() -> None:
    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(ATTACK_FIXTURE)

    assert [event.action for event in result.ingestion_result.events] == [
        "AttachUserPolicy",
        "ConsoleLogin",
        "CreateAccessKey",
    ]
    assert [event.action for event in result.analyzed_events] == [
        "ConsoleLogin",
        "CreateAccessKey",
        "AttachUserPolicy",
    ]
    assert result.correlation_count == 1


def test_same_timestamp_events_retain_source_tie_order_and_remain_distinct() -> None:
    document = _attack_document()
    records = cast(list[JsonObject], document["Records"])
    by_action = {cast(str, record["eventName"]): record for record in records}
    document["Records"] = [
        by_action["ConsoleLogin"],
        by_action["CreateAccessKey"],
        by_action["AttachUserPolicy"],
    ]
    for record in cast(list[JsonObject], document["Records"]):
        record["eventTime"] = "2026-09-23T10:00:00Z"

    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_json(json.dumps(document))

    assert [event.action for event in result.analyzed_events] == [
        "ConsoleLogin",
        "CreateAccessKey",
        "AttachUserPolicy",
    ]
    assert len({event.event_id for event in result.analyzed_events}) == 3
    assert result.correlation_count == 1


def test_benign_valid_document_is_a_successful_zero_incident_execution() -> None:
    source = json.dumps(
        {
            "Records": [
                {
                    "eventTime": "2026-09-23T10:00:00Z",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "ListBuckets",
                    "eventID": "dddddddd-4444-4444-8444-dddddddddddd",
                }
            ]
        }
    )
    repository = InMemoryIncidentRepository()

    result = create_default_investigation_runner(repository).run_cloudtrail_json(source)

    assert result.analyzed_event_count == 1
    assert result.signal_count == 0
    assert result.correlation_count == 0
    assert result.incident_count == 0
    assert result.persisted_incident_count == 0
    assert repository.list_incidents() == ()
    assert result.analysis_run.signals_created == 0
    assert result.analysis_run.incidents_created == 0


def test_standalone_detection_is_reported_without_manufacturing_incident() -> None:
    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(SAMPLES / "valid-multi-record.json")

    assert result.ingestion_result.accepted_records == 3
    assert result.signal_count == 1
    assert result.signals[0].rule_id == "aws.iam.access_key_created"
    assert result.correlation_count == 0
    assert result.incident_count == 0


def test_partial_ingestion_still_creates_and_persists_incident() -> None:
    document = _attack_document()
    cast(list[object], document["Records"]).insert(1, "malformed-record")
    repository = InMemoryIncidentRepository()

    result = create_default_investigation_runner(repository).run_cloudtrail_json(
        json.dumps(document)
    )

    assert result.ingestion_result.total_records == 4
    assert result.ingestion_result.accepted_records == 3
    assert result.ingestion_result.failed_records == 1
    assert result.ingestion_result.issues[0].record_index == 1
    assert result.signal_count == 3
    assert result.incident_count == 1
    assert repository.list_incidents() == result.incidents
    assert result.analysis_run.records_seen == 4
    assert result.analysis_run.records_accepted == 3


def test_m20_duplicate_handling_is_inherited_before_analysis() -> None:
    document = _attack_document()
    records = cast(list[JsonObject], document["Records"])
    records.append(deepcopy(records[0]))

    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_json(json.dumps(document))

    assert result.ingestion_result.total_records == 4
    assert result.ingestion_result.accepted_records == 3
    assert result.ingestion_result.duplicate_records == 1
    assert result.analyzed_event_count == 3
    assert result.incident_count == 1


def test_document_failure_prevents_analysis_and_persistence() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)

    with pytest.raises(CloudTrailInvalidJsonError):
        runner.run_cloudtrail_json('{"Records": [}')

    assert repository.list_incidents() == ()


@pytest.mark.parametrize("failure_stage", ("detection", "correlation", "factory"))
def test_analysis_stage_failures_propagate_without_completed_run(
    failure_stage: str,
) -> None:
    runner = InvestigationRunner(
        detection_engine=(
            _FailingDetectionEngine()
            if failure_stage == "detection"
            else DetectionEngine(AWS_RULES)
        ),  # type: ignore[arg-type]
        correlation_engine=(
            _FailingCorrelationEngine()
            if failure_stage == "correlation"
            else CorrelationEngine(AWS_CORRELATION_RULES)
        ),  # type: ignore[arg-type]
        incident_factory=(
            _FailingIncidentFactory()
            if failure_stage == "factory"
            else IncidentFactory()
        ),
        incident_repository=InMemoryIncidentRepository(),
    )

    with pytest.raises(RuntimeError, match=f"{failure_stage} failed"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)


def test_reprocessing_same_source_is_not_idempotent_with_random_domain_ids() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)

    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    second = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert len(repository.list_incidents()) == 2
    assert first.analysis_run.analysis_run_id != second.analysis_run.analysis_run_id
    assert first.incidents[0].incident_id != second.incidents[0].incident_id
    assert first.correlations[0].correlation_id != second.correlations[0].correlation_id
    assert {signal.signal_id for signal in first.signals}.isdisjoint(
        signal.signal_id for signal in second.signals
    )
    assert [event.event_id for event in first.analyzed_events] == [
        event.event_id for event in second.analyzed_events
    ]
    assert all(event.event_id is not None for event in first.analyzed_events)


def test_duplicate_incident_error_is_not_misclassified_as_idempotent_success() -> None:
    repository = InMemoryIncidentRepository()
    runner = InvestigationRunner(
        detection_engine=DetectionEngine(AWS_RULES),
        correlation_engine=CorrelationEngine(AWS_CORRELATION_RULES),
        incident_factory=_FixedIdentityIncidentFactory(),
        incident_repository=repository,
    )
    runner.run_cloudtrail_file(ATTACK_FIXTURE)

    with pytest.raises(IncidentAlreadyExistsError, match="already exists"):
        runner.run_cloudtrail_file(ATTACK_FIXTURE)

    assert len(repository.list_incidents()) == 1


def test_same_runner_has_in_memory_and_sqlite_repository_parity(tmp_path: Path) -> None:
    memory_result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(ATTACK_FIXTURE)
    sqlite_repository = SQLiteIncidentRepository(tmp_path / "parity.sqlite3")
    sqlite_result = create_default_investigation_runner(
        sqlite_repository
    ).run_cloudtrail_file(ATTACK_FIXTURE)

    assert memory_result.signal_count == sqlite_result.signal_count == 3
    assert memory_result.correlation_count == sqlite_result.correlation_count == 1
    assert memory_result.incident_count == sqlite_result.incident_count == 1
    assert memory_result.analysis_run.records_seen == (
        sqlite_result.analysis_run.records_seen
    )
    assert memory_result.analysis_run.records_accepted == (
        sqlite_result.analysis_run.records_accepted
    )
    assert memory_result.analysis_run.signals_created == (
        sqlite_result.analysis_run.signals_created
    )
    assert memory_result.analysis_run.correlations_created == (
        sqlite_result.analysis_run.correlations_created
    )
    assert memory_result.analysis_run.incidents_created == (
        sqlite_result.analysis_run.incidents_created
    )
    assert tuple(signal.rule_id for signal in memory_result.signals) == tuple(
        signal.rule_id for signal in sqlite_result.signals
    )
    assert len(sqlite_repository.list_incidents()) == 1


def test_sqlite_reopen_and_existing_api_derive_complete_investigation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "investigations.sqlite3"
    first_repository = SQLiteIncidentRepository(database)
    result = create_default_investigation_runner(
        first_repository
    ).run_cloudtrail_file(ATTACK_FIXTURE)
    incident = result.incidents[0]
    expected_signal_ids = tuple(entry.signal_id for entry in incident.timeline)

    reopened_repository = SQLiteIncidentRepository(database)
    reopened = reopened_repository.get_incident(incident.incident_id)
    assert reopened is not None
    assert reopened.incident_id == incident.incident_id
    assert result.analysis_run.analysis_run_id.encode() not in database.read_bytes()
    assert tuple(entry.signal_id for entry in reopened.timeline) == expected_signal_ids
    assert all(
        signal.source_event.raw_event == {}
        for signal in reopened.correlation_match.signals
    )

    application = create_app(repository=reopened_repository, cors_origins=())
    collection = _api_get(application, "/api/v1/incidents")
    detail = _api_get(application, f"/api/v1/incidents/{incident.incident_id}")
    risk = _api_get(application, f"/api/v1/incidents/{incident.incident_id}/risk")
    mitre = _api_get(application, f"/api/v1/incidents/{incident.incident_id}/mitre")
    graph = _api_get(application, f"/api/v1/incidents/{incident.incident_id}/graph")
    blast = _api_get(
        application, f"/api/v1/incidents/{incident.incident_id}/blast-radius"
    )

    assert collection.status_code == detail.status_code == 200
    assert risk.status_code == mitre.status_code == graph.status_code == 200
    assert collection.json()[0]["incident_id"] == incident.incident_id
    assert risk.json()["score"] == 80
    assert risk.json()["level"] == "critical"
    assert [item["technique_id"] for item in mitre.json()["techniques"]] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]
    timeline_ids = {entry["signal_id"] for entry in detail.json()["timeline"]}
    graph_ids = {edge["signal_id"] for edge in graph.json()["edges"]}
    assert graph_ids
    assert graph_ids <= timeline_ids
    assert blast.json()["available"] is False
    for response in (collection, detail, risk, mitre, graph, blast):
        assert "raw_event" not in response.text

    assert not hasattr(reopened, "analysis_run_id")
    assert not hasattr(reopened.correlation_match, "analysis_run_id")
    assert all(
        not hasattr(signal, "analysis_run_id")
        and not hasattr(signal.source_event, "analysis_run_id")
        for signal in reopened.correlation_match.signals
    )


def test_file_execution_does_not_modify_source() -> None:
    before = ATTACK_FIXTURE.read_bytes()
    before_mtime = ATTACK_FIXTURE.stat().st_mtime_ns

    create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(ATTACK_FIXTURE)

    assert ATTACK_FIXTURE.read_bytes() == before
    assert ATTACK_FIXTURE.stat().st_mtime_ns == before_mtime


def test_second_repository_failure_leaves_first_incident_saved_and_stops() -> None:
    document = _two_actor_attack_document()
    repository = _FailOnSecondSaveRepository()
    runner = create_default_investigation_runner(repository)

    with pytest.raises(RuntimeError, match="repository unavailable"):
        runner.run_cloudtrail_json(json.dumps(document))

    assert repository.save_attempts == 2
    assert len(repository.list_incidents()) == 1


def test_execution_result_is_immutable() -> None:
    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(SAMPLES / "empty-records.json")

    with pytest.raises(FrozenInstanceError):
        result.signals = ()  # type: ignore[misc]


def test_empty_input_produces_completed_zero_count_local_file_run() -> None:
    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(SAMPLES / "empty-records.json")

    assert result.analysis_run.source_type is AnalysisSourceType.LOCAL_FILE
    assert result.analysis_run.records_seen == 0
    assert result.analysis_run.records_accepted == 0
    assert result.analysis_run.signals_created == 0
    assert result.analysis_run.correlations_created == 0
    assert result.analysis_run.incidents_created == 0


def test_direct_json_execution_uses_direct_input_source_type() -> None:
    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_json('{"Records": []}')

    assert result.analysis_run.source_type is AnalysisSourceType.DIRECT_INPUT


def _two_actor_attack_document() -> JsonObject:
    document = _attack_document()
    original_records = cast(list[JsonObject], document["Records"])
    second_records = deepcopy(original_records)
    for record in second_records:
        identity = cast(JsonObject, record["userIdentity"])
        identity["principalId"] = "AIDAEXAMPLEOPERATOR"
        identity["arn"] = "arn:aws:iam::111122223333:user/operator"
        identity["userName"] = "operator"
        event_id = cast(str, record["eventID"])
        record["eventID"] = event_id.replace(event_id[0], "f")
        event_time = cast(str, record["eventTime"])
        record["eventTime"] = event_time.replace("10:", "11:", 1)
        parameters = record.get("requestParameters")
        if isinstance(parameters, dict) and "userName" in parameters:
            parameters["userName"] = "operator"
    document["Records"] = original_records + second_records
    return document


class _FailOnSecondSaveRepository:
    def __init__(self) -> None:
        self._incidents: list[Incident] = []
        self.save_attempts = 0

    def list_incidents(self) -> tuple[Incident, ...]:
        return tuple(self._incidents)

    def get_incident(self, incident_id: str) -> Incident | None:
        return next(
            (
                incident
                for incident in self._incidents
                if incident.incident_id == incident_id
            ),
            None,
        )

    def save_incident(self, incident: Incident) -> None:
        self.save_attempts += 1
        if self.save_attempts == 2:
            raise RuntimeError("repository unavailable")
        self._incidents.append(incident)


class _FixedIdentityIncidentFactory(IncidentFactory):
    def create(
        self,
        correlation_match: CorrelationMatch,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
    ) -> Incident:
        del incident_id
        return super().create(
            correlation_match,
            incident_id="fixed-incident-id",
            created_at=created_at,
        )


class _FailingDetectionEngine:
    def evaluate(self, _event: object) -> tuple[()]:
        raise RuntimeError("detection failed")


class _FailingCorrelationEngine:
    def evaluate(self, _signals: object) -> tuple[()]:
        raise RuntimeError("correlation failed")


class _FailingIncidentFactory(IncidentFactory):
    def create(
        self,
        correlation_match: CorrelationMatch,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
    ) -> Incident:
        del correlation_match, incident_id, created_at
        raise RuntimeError("factory failed")
