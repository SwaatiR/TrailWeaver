"""Focused tests for the thin web-analysis adapter endpoints."""

import gzip
from asyncio import run
from io import BytesIO
from pathlib import Path
from typing import Any

import httpx
from botocore.exceptions import ClientError
from fastapi import FastAPI

from trailweaver.api.app import create_app
from trailweaver.api.demo import app as demo_application
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository
from trailweaver.aws_s3 import S3CloudTrailAdapter

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail"


class _ApiClient:
    def __init__(self, application: FastAPI) -> None:
        self._application = application

    def get(self, path: str) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
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
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.post(
                    path, content=content, json=json_body, headers=headers
                )

        return run(request())


class _FakeS3Client:
    def __init__(self, content: bytes) -> None:
        self._content = content
        self.get_error: ClientError | None = None

    def get_object(self, **kwargs: object) -> dict[str, Any]:
        if self.get_error is not None:
            raise self.get_error
        return {"Body": BytesIO(self._content), "ContentLength": len(self._content)}

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
        raise AssertionError("listing must not be used by web S3 analysis")


def _client(application: FastAPI | None = None) -> _ApiClient:
    return _ApiClient(application if application is not None else create_app())


def _sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def _client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "sensitive AWS response details"}},
        "GetObject",
    )


def test_capabilities_enabled_by_default() -> None:
    body = _client().get("/api/v1/capabilities").json()
    assert body == {"file_analysis": True, "s3_analysis": True, "demo_mode": False}


def test_capabilities_for_demo_enable_file_but_not_s3() -> None:
    response = _ApiClient(demo_application).get("/api/v1/capabilities")
    assert response.status_code == 200
    assert response.json() == {
        "file_analysis": True,
        "s3_analysis": False,
        "demo_mode": True,
    }


def test_file_analysis_produces_incident() -> None:
    client = _client()
    response = client.post(
        "/api/v1/analyses/file",
        content=_sample("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_records"] == 3
    assert body["accepted_records"] == 3
    assert body["failed_records"] == 0
    assert body["signals"] == 3
    assert body["incidents_created"] == 1
    assert body["persisted_incidents"] == 1
    assert len(body["incident_ids"]) == 1

    incident_id = body["incident_ids"][0]
    listed = client.get("/api/v1/incidents").json()
    assert [item["incident_id"] for item in listed] == [incident_id]
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["title"] == "Possible AWS account compromise"


def test_file_analysis_does_not_expose_raw_evidence() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=_sample("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    text = response.text
    for forbidden in ("raw_event", "requestParameters", "userIdentity", "eventName"):
        assert forbidden not in text


def test_file_analysis_accepts_gzip_bytes() -> None:
    payload = gzip.compress(_sample("account-compromise-sequence.json"))
    response = _client().post(
        "/api/v1/analyses/file",
        content=payload,
        headers={"Content-Type": "application/gzip"},
    )
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 1


def test_benign_file_reports_zero_incidents() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=_sample("empty-records.json"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_records"] == 0
    assert body["incidents_created"] == 0
    assert body["persisted_incidents"] == 0
    assert body["incident_ids"] == []


def test_partial_file_preserves_m20_diagnostics() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=_sample("mixed-records.json"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted_records"] > 0
    assert body["failed_records"] > 0
    assert body["issues"], "partial failures must surface safe diagnostics"
    for issue in body["issues"]:
        assert set(issue) == {"record_index", "code", "event_id"}


def test_reprocessing_same_source_creates_distinct_incident() -> None:
    client = _client()
    payload = _sample("account-compromise-sequence.json")
    headers = {"Content-Type": "application/json"}
    first = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    second = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["incident_ids"] != second.json()["incident_ids"]
    assert len(client.get("/api/v1/incidents").json()) == 2


def test_malformed_envelope_is_rejected_safely() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=b'{"unexpected": "shape"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "CloudTrail document is missing 'Records'"}


def test_invalid_json_is_rejected_safely() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=b"not json at all",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "CloudTrail source is not a valid JSON document"}


def test_invalid_gzip_is_rejected_safely() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=b"\x1f\x8bnot actually gzip content",
        headers={"Content-Type": "application/gzip"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Uploaded CloudTrail content is not valid gzip"}


def test_unsupported_content_type_is_rejected() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=b"<Records></Records>",
        headers={"Content-Type": "text/xml"},
    )
    assert response.status_code == 415


def test_declared_oversize_is_rejected_without_processing() -> None:
    response = _client().post(
        "/api/v1/analyses/file",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "99999999"},
    )
    assert response.status_code == 413


def test_gzip_bomb_is_rejected() -> None:
    payload = gzip.compress(b'{"Records": []}' + b" " * (11 * 1024 * 1024))
    response = _client().post(
        "/api/v1/analyses/file",
        content=payload,
        headers={"Content-Type": "application/gzip"},
    )
    assert response.status_code in {413, 422}


def test_demo_app_rejects_s3_analysis_but_accepts_file_uploads() -> None:
    client = _ApiClient(demo_application)
    denied = client.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "trail/export.json"},
    )
    assert denied.status_code == 503

    allowed = client.post(
        "/api/v1/analyses/file",
        content=_sample("empty-records.json"),
        headers={"Content-Type": "application/json"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["incidents_created"] == 0


def test_s3_analysis_uses_injected_adapter_without_live_aws() -> None:
    application = create_app()
    fake = _FakeS3Client(_sample("account-compromise-sequence.json"))
    application.state.s3_adapter_factory = lambda region: S3CloudTrailAdapter(fake)
    client = _ApiClient(application)

    response = client.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "trail/export.json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_label"] == "s3://example-bucket/trail/export.json"
    assert body["incidents_created"] == 1
    assert len(client.get("/api/v1/incidents").json()) == 1


def test_s3_analysis_maps_source_errors_safely() -> None:
    application = create_app()
    fake = _FakeS3Client(b"{}")
    application.state.s3_adapter_factory = lambda region: S3CloudTrailAdapter(fake)
    client = _ApiClient(application)

    fake.get_error = _client_error("NoSuchKey")
    missing = client.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "missing.json"},
    )
    assert missing.status_code == 404
    assert missing.json() == {"detail": "The configured S3 CloudTrail object was not found"}

    fake.get_error = _client_error("AccessDenied")
    denied = client.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "trail.json"},
    )
    assert denied.status_code == 403
    assert "sensitive AWS response details" not in denied.text


def test_s3_analysis_rejects_blank_location_and_credentials() -> None:
    client = _client()
    blank = client.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "   "},
    )
    assert blank.status_code == 422

    with_credentials = client.post(
        "/api/v1/analyses/s3",
        json_body={
            "bucket": "example-bucket",
            "key": "trail.json",
            "aws_access_key_id": "AKIAEXAMPLE",
        },
    )
    assert with_credentials.status_code == 422


def test_file_analysis_persists_to_configured_sqlite(tmp_path: Path) -> None:
    database = tmp_path / "incidents.sqlite3"
    application = create_app(repository=SQLiteIncidentRepository(database))
    client = _ApiClient(application)
    response = client.post(
        "/api/v1/analyses/file",
        content=_sample("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json()["persisted_incidents"] == 1

    reopened = _ApiClient(create_app(repository=SQLiteIncidentRepository(database)))
    listed = reopened.get("/api/v1/incidents").json()
    assert [item["incident_id"] for item in listed] == response.json()["incident_ids"]


def test_unavailable_service_repository_reports_503() -> None:
    from trailweaver.api.sqlite_repository import IncidentRepositoryError

    class UnavailableRepository(InMemoryIncidentRepository):
        def list_incidents(self):  # type: ignore[no-untyped-def]
            raise IncidentRepositoryError("storage unavailable")

    response = _client(create_app(repository=UnavailableRepository())).get(
        "/api/v1/incidents"
    )
    assert response.status_code == 503
