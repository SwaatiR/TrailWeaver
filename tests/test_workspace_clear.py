"""Focused tests for clearing the TrailWeaver investigation workspace.

Clearing removes persisted incidents and their related correlation and
signal rows from the repository already configured for the running
process. It never touches source files, AWS resources, or the database
file itself.
"""

import sqlite3
from asyncio import run
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from trailweaver.analysis_ledger import InMemoryAnalysisRunRepository
from trailweaver.analysis_runs import AnalysisRunStatus
from trailweaver.api.app import create_app
from trailweaver.api.demo import create_demo_app, create_demo_incident
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository

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
        json_body: Any | None = None,
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


def _child_row_counts(database: Path) -> tuple[int, int]:
    connection = sqlite3.connect(database)
    try:
        matches = connection.execute("SELECT COUNT(*) FROM correlation_matches").fetchone()[0]
        signals = connection.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
        return (matches, signals)
    finally:
        connection.close()


def _fixture(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def test_sqlite_clear_removes_incidents_and_related_rows_without_touching_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "workspace.sqlite3"
    repository = SQLiteIncidentRepository(database)
    repository.save_incident(create_demo_incident())

    assert len(repository.list_incidents()) == 1
    assert _child_row_counts(database) == (1, 3)

    repository.clear_incidents()

    assert repository.list_incidents() == ()
    assert _child_row_counts(database) == (0, 0)
    connection = sqlite3.connect(database)
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        connection.close()
    assert version == 2
    assert {"incidents", "correlation_matches", "signals"} <= tables

    repository.save_incident(create_demo_incident())
    assert len(repository.list_incidents()) == 1


def test_sqlite_clear_of_empty_workspace_is_safe_and_idempotent(
    tmp_path: Path,
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "empty.sqlite3")

    repository.clear_incidents()

    assert repository.list_incidents() == ()
    repository.check_health()


def test_in_memory_clear_restores_empty_reusable_workspace() -> None:
    repository = InMemoryIncidentRepository((create_demo_incident(),))

    repository.clear_incidents()

    assert repository.list_incidents() == ()
    repository.save_incident(create_demo_incident())
    assert len(repository.list_incidents()) == 1


def test_production_clear_endpoint_empties_workspace_and_stays_usable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "incidents.sqlite3"
    client = _ApiClient(create_app(repository=SQLiteIncidentRepository(database)))
    payload = _fixture("account-compromise-sequence.json")
    headers = {"Content-Type": "application/json"}
    incident_id = (
        client.post("/api/v1/analyses/file", content=payload, headers=headers)
        .json()["incident_ids"][0]
    )
    assert len(client.get("/api/v1/incidents").json()) == 1

    response = client.post("/api/v1/workspace/clear")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "incidents": 0}
    assert client.get("/api/v1/incidents").json() == []
    assert client.get(f"/api/v1/incidents/{incident_id}").status_code == 404
    assert _child_row_counts(database) == (0, 0)

    repeated = client.post(
        "/api/v1/analyses/file", content=payload, headers=headers
    )
    assert repeated.status_code == 200
    assert repeated.json()["incidents_created"] == 1
    assert len(client.get("/api/v1/incidents").json()) == 1


def test_production_clear_of_empty_workspace_succeeds(tmp_path: Path) -> None:
    client = _ApiClient(
        create_app(repository=SQLiteIncidentRepository(tmp_path / "fresh.sqlite3"))
    )

    response = client.post("/api/v1/workspace/clear")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "incidents": 0}


def test_workspace_clear_is_not_available_over_get(tmp_path: Path) -> None:
    client = _ApiClient(
        create_app(repository=SQLiteIncidentRepository(tmp_path / "get.sqlite3"))
    )

    assert client.get("/api/v1/workspace/clear").status_code == 405


def test_workspace_clear_ignores_irrelevant_request_input(tmp_path: Path) -> None:
    client = _ApiClient(
        create_app(repository=SQLiteIncidentRepository(tmp_path / "input.sqlite3"))
    )
    client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )

    response = client.post(
        "/api/v1/workspace/clear",
        json_body={"incident_id": "does-not-control-scope", "database_path": "/tmp/nope"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "incidents": 0}
    assert client.get("/api/v1/incidents").json() == []


def test_workspace_clear_failure_preserves_existing_incidents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "locked.sqlite3"
    client = _ApiClient(create_app(repository=SQLiteIncidentRepository(database)))
    client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    assert len(client.get("/api/v1/incidents").json()) == 1

    def _unavailable(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        raise sqlite3.OperationalError("storage unavailable for this test")

    monkeypatch.setattr(sqlite3, "connect", _unavailable)
    response = client.post("/api/v1/workspace/clear")

    assert response.status_code == 503
    monkeypatch.undo()
    assert len(client.get("/api/v1/incidents").json()) == 1
    assert _child_row_counts(database) == (1, 3)


def test_demo_workspace_clear_covers_the_same_in_memory_operation() -> None:
    client = _ApiClient(create_demo_app())
    client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    assert len(client.get("/api/v1/incidents").json()) == 1

    response = client.post("/api/v1/workspace/clear")

    assert response.status_code == 200


def test_workspace_clear_preserves_sqlite_analysis_run_history(tmp_path: Path) -> None:
    database = tmp_path / "history.sqlite3"
    repository = SQLiteIncidentRepository(database)
    client = _ApiClient(create_app(repository=repository))
    response = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    run_id = response.json()["analysis_run_id"]

    assert client.post("/api/v1/workspace/clear").status_code == 200
    assert repository.list_incidents() == ()
    assert repository.get_run(run_id).status is AnalysisRunStatus.COMPLETED


def test_demo_reset_preserves_separate_in_memory_run_history() -> None:
    incident_repository = InMemoryIncidentRepository()
    ledger = InMemoryAnalysisRunRepository()
    client = _ApiClient(
        create_app(
            repository=incident_repository,
            analysis_run_repository=ledger,
            demo_mode=True,
            enable_s3_analysis=False,
            enable_demo_reset=True,
        )
    )
    client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )

    assert client.post("/api/v1/demo/reset").status_code == 200
    assert incident_repository.list_incidents() == ()
    assert len(ledger.list_runs()) == 1
    assert ledger.list_runs()[0].status is AnalysisRunStatus.COMPLETED
