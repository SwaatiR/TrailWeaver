import json
import sqlite3
from dataclasses import replace
from datetime import timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI

from trailweaver.api.app import create_app, create_persistent_app
from trailweaver.api.demo import create_demo_cloud_context, create_demo_incident
from trailweaver.api.service import IncidentAlreadyExistsError, InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import (
    InvalidStoredIncidentError,
    SQLiteIncidentRepository,
    UnsupportedSchemaVersionError,
)
from trailweaver.attack_graph import AttackGraphBuilder
from trailweaver.blast_radius import BlastRadiusAnalyzer
from trailweaver.investigation import InvestigationAdvisor
from trailweaver.mitre import MitreMapper
from trailweaver.models import EventOutcome
from trailweaver.risk import RiskScorer
from trailweaver.signals import SignalSeverity


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

        import asyncio

        return asyncio.run(request())


def _without_raw_event(incident):
    signals = tuple(
        replace(signal, source_event=replace(signal.source_event, raw_event={}))
        for signal in incident.correlation_match.signals
    )
    match = replace(incident.correlation_match, signals=signals)
    return replace(incident, correlation_match=match)


def _analysis(incident, cloud_context):
    risk = RiskScorer().score(incident)
    blast_radius = BlastRadiusAnalyzer().analyze(incident, cloud_context)
    return (
        incident.timeline,
        risk,
        MitreMapper().map(incident),
        AttackGraphBuilder().build(incident),
        InvestigationAdvisor().advise(incident, risk_assessment=risk, blast_radius=blast_radius),
        blast_radius,
    )


def test_new_database_initializes_versioned_schema_and_lists_empty(tmp_path) -> None:
    database = tmp_path / "nested" / "incidents.sqlite3"
    repository = SQLiteIncidentRepository(database)

    assert repository.list_incidents() == ()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert tables == {
            "incidents",
            "correlation_matches",
            "signals",
            "analysis_runs",
            "sqlite_sequence",
        }


def test_repository_health_check_is_lightweight_and_successful(tmp_path) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "ready.sqlite3")

    assert repository.check_health() is None


def test_reopen_round_trip_preserves_domain_and_derived_analysis(tmp_path) -> None:
    database = tmp_path / "incidents.sqlite3"
    incident = create_demo_incident()
    cloud_context = create_demo_cloud_context()
    expected_incident = _without_raw_event(incident)
    expected_analysis = _analysis(expected_incident, cloud_context)

    SQLiteIncidentRepository(database).save_incident(incident)
    reloaded = SQLiteIncidentRepository(database).get_incident(incident.incident_id)

    assert reloaded == expected_incident
    assert reloaded is not None
    assert _analysis(reloaded, cloud_context) == expected_analysis
    assert [entry.signal_id for entry in reloaded.timeline] == [
        signal.signal_id for signal in reloaded.correlation_match.signals
    ]
    graph = AttackGraphBuilder().build(reloaded)
    timeline_ids = {entry.signal_id for entry in reloaded.timeline}
    assert all(edge.signal_id in timeline_ids for edge in graph.edges)
    assert all(signal.source_event.raw_event == {} for signal in reloaded.correlation_match.signals)
    assert b"m16-1-raw-evidence" not in database.read_bytes()


def test_round_trip_preserves_timezone_aware_timestamps_semantically(tmp_path) -> None:
    incident = create_demo_incident()
    offset = timezone(timedelta(hours=5, minutes=30))
    shifted_signals = tuple(
        replace(
            signal,
            source_event=replace(
                signal.source_event,
                timestamp=signal.source_event.timestamp.astimezone(offset),
            ),
        )
        for signal in incident.correlation_match.signals
    )
    shifted_match = replace(incident.correlation_match, signals=shifted_signals)
    shifted_incident = replace(
        incident,
        correlation_match=shifted_match,
        created_at=incident.created_at.astimezone(offset),
    )

    database = tmp_path / "offset.sqlite3"
    SQLiteIncidentRepository(database).save_incident(shifted_incident)
    loaded = SQLiteIncidentRepository(database).get_incident(incident.incident_id)

    assert loaded is not None
    assert loaded.created_at == shifted_incident.created_at
    assert loaded.created_at.utcoffset() == timedelta(0)
    for actual, expected in zip(
        loaded.correlation_match.signals,
        shifted_incident.correlation_match.signals,
        strict=True,
    ):
        assert actual.source_event.timestamp == expected.source_event.timestamp
        assert actual.source_event.timestamp.tzinfo is not None


def test_repository_orders_by_insertion_and_supports_multiple_incidents(tmp_path) -> None:
    first = replace(create_demo_incident(), incident_id="z-first")
    second = replace(create_demo_incident(), incident_id="a-second")
    repository = SQLiteIncidentRepository(tmp_path / "order.sqlite3")

    repository.save_incident(first)
    repository.save_incident(second)

    assert tuple(item.incident_id for item in repository.list_incidents()) == (
        "z-first",
        "a-second",
    )
    assert repository.get_incident("missing") is None


def test_duplicate_incident_id_is_insert_only_and_does_not_replace(tmp_path) -> None:
    incident = create_demo_incident()
    repository = SQLiteIncidentRepository(tmp_path / "duplicate.sqlite3")
    repository.save_incident(incident)

    with pytest.raises(IncidentAlreadyExistsError, match="already exists"):
        repository.save_incident(replace(incident, title="replacement"))

    assert repository.get_incident(incident.incident_id).title == incident.title


def test_in_memory_repository_uses_same_insert_only_contract() -> None:
    incident = create_demo_incident()
    repository = InMemoryIncidentRepository((incident,))

    with pytest.raises(IncidentAlreadyExistsError):
        repository.save_incident(incident)

    added = replace(incident, incident_id="second-incident")
    repository.save_incident(added)
    assert repository.list_incidents() == (incident, added)


def test_hostile_looking_id_is_a_parameterized_lookup(tmp_path) -> None:
    incident = create_demo_incident()
    database = tmp_path / "hostile.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.save_incident(incident)

    assert repository.get_incident("' OR 1=1 --") is None
    assert len(repository.list_incidents()) == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)


def test_unsupported_schema_version_fails_without_modifying_database(tmp_path) -> None:
    database = tmp_path / "future.sqlite3"
    SQLiteIncidentRepository(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(UnsupportedSchemaVersionError, match="version 99"):
        SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (99,)


def test_corrupt_persisted_enum_fails_instead_of_returning_partial_incident(tmp_path) -> None:
    incident = create_demo_incident()
    database = tmp_path / "corrupt.sqlite3"
    SQLiteIncidentRepository(database).save_incident(incident)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE incidents SET severity = ? WHERE incident_id = ?",
            ("not-a-severity", incident.incident_id),
        )

    with pytest.raises(InvalidStoredIncidentError, match="is invalid"):
        SQLiteIncidentRepository(database).get_incident(incident.incident_id)


def test_persistent_application_reads_and_derives_analysis_after_reopen(tmp_path) -> None:
    incident = create_demo_incident()
    database = tmp_path / "api.sqlite3"
    SQLiteIncidentRepository(database).save_incident(incident)
    application = create_persistent_app(
        database,
        cloud_context=create_demo_cloud_context(),
        cors_origins=(),
    )
    client = _ApiClient(application)

    detail = client.get(f"/api/v1/incidents/{incident.incident_id}")
    risk = client.get(f"/api/v1/incidents/{incident.incident_id}/risk")
    mitre = client.get(f"/api/v1/incidents/{incident.incident_id}/mitre")
    graph = client.get(f"/api/v1/incidents/{incident.incident_id}/graph")
    guidance = client.get(f"/api/v1/incidents/{incident.incident_id}/guidance")
    blast = client.get(f"/api/v1/incidents/{incident.incident_id}/blast-radius")

    assert detail.status_code == risk.status_code == mitre.status_code == 200
    assert graph.status_code == guidance.status_code == blast.status_code == 200
    signal_ids = {item["signal_id"] for item in detail.json()["timeline"]}
    assert all(edge["signal_id"] in signal_ids for edge in graph.json()["edges"])
    assert risk.json()["score"] == 80
    assert [item["technique_id"] for item in mitre.json()["techniques"]] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]
    assert blast.json()["total_reachable_assets"] == 5
    assert guidance.json()["recommendations"]
    assert "raw_event" not in json.dumps(detail.json())


def test_blast_radius_still_requires_external_cloud_context(tmp_path) -> None:
    incident = create_demo_incident()
    database = tmp_path / "without-context.sqlite3"
    SQLiteIncidentRepository(database).save_incident(incident)
    application = create_app(repository=SQLiteIncidentRepository(database))

    response = _ApiClient(application).get(f"/api/v1/incidents/{incident.incident_id}/blast-radius")

    assert response.status_code == 200
    assert response.json()["available"] is False


def test_persisted_signal_enums_and_event_identity_are_domain_values(tmp_path) -> None:
    incident = create_demo_incident()
    repository = SQLiteIncidentRepository(tmp_path / "types.sqlite3")
    repository.save_incident(incident)

    loaded = repository.get_incident(incident.incident_id)

    assert loaded is not None
    assert loaded.severity is SignalSeverity.HIGH
    for actual, expected in zip(
        loaded.correlation_match.signals,
        incident.correlation_match.signals,
        strict=True,
    ):
        assert actual.severity is expected.severity
        assert actual.source_event.outcome is EventOutcome.SUCCESS
        assert actual.signal_id == expected.signal_id
        assert actual.source_event.event_id == expected.source_event.event_id
