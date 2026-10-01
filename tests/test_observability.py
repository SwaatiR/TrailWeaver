import json
from asyncio import run
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest
from botocore.exceptions import ClientError

from trailweaver.api.app import create_app
from trailweaver.api.execution import create_default_investigation_runner
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.aws_s3 import S3CloudTrailAdapter, S3CloudTrailSourceError
from trailweaver.incidents import Incident
from trailweaver.observability import configure_logging, safe_source_label

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"


class _DeniedS3Client:
    def get_object(self, **kwargs: object) -> dict[str, Any]:
        del kwargs
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "raw-aws-secret-marker"}},
            "GetObject",
        )

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
        del kwargs
        return {"IsTruncated": False}


def _records(stream: StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_investigation_logs_safe_stage_counts_without_raw_evidence() -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)

    result = create_default_investigation_runner(
        InMemoryIncidentRepository()
    ).run_cloudtrail_file(
        ATTACK_FIXTURE,
        source_label="/private/operator/account-compromise.json",
    )

    records = _records(stream)
    assert [record["event"] for record in records] == [
        "investigation_started",
        "investigation_analyzed",
        "investigation_completed",
    ]
    assert records[0]["source"] == "account-compromise.json"
    assert records[0]["accepted"] == 3
    assert records[1]["signals"] == result.signal_count == 3
    assert records[1]["correlations"] == result.correlation_count == 1
    assert records[2]["persisted"] == 1
    assert "requestParameters" not in stream.getvalue()
    assert "raw_event" not in stream.getvalue()


def test_aws_failure_log_uses_error_type_not_aws_error_details() -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)

    with pytest.raises(S3CloudTrailSourceError):
        S3CloudTrailAdapter(_DeniedS3Client()).ingest_object(
            bucket="fictional-cloudtrail",
            key="AWSLogs/export.json.gz",
        )

    records = _records(stream)
    assert records[-1]["event"] == "aws_ingestion_failed"
    assert records[-1]["error_type"] == "S3CloudTrailAccessDeniedError"
    assert "raw-aws-secret-marker" not in stream.getvalue()


def test_persistence_failure_is_logged_then_propagated_without_error_message() -> None:
    class FailingRepository(InMemoryIncidentRepository):
        def save_incident(self, incident: Incident) -> None:
            del incident
            raise RuntimeError("raw-database-secret-marker")

    stream = StringIO()
    configure_logging("info", stream=stream)

    with pytest.raises(RuntimeError, match="raw-database-secret-marker"):
        create_default_investigation_runner(
            FailingRepository()
        ).run_cloudtrail_file(ATTACK_FIXTURE)

    records = _records(stream)
    assert records[-1]["event"] == "incident_persistence_failed"
    assert records[-1]["error_type"] == "RuntimeError"
    assert "raw-database-secret-marker" not in stream.getvalue()


def test_request_log_uses_route_template_and_never_query_string() -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)
    application = create_app(repository=InMemoryIncidentRepository())

    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get(
                "/api/v1/incidents/missing?token=raw-query-secret-marker"
            )

    response = run(request())

    assert response.status_code == 404
    records = _records(stream)
    request_record = records[-1]
    assert request_record["event"] == "http_request_completed"
    assert request_record["route"] == "/api/v1/incidents/{incident_id}"
    assert request_record["method"] == "GET"
    assert request_record["status"] == 404
    assert "raw-query-secret-marker" not in stream.getvalue()


def test_routine_health_probes_are_not_request_logged() -> None:
    stream = StringIO()
    configure_logging("info", stream=stream)
    application = create_app(repository=InMemoryIncidentRepository())

    async def request() -> tuple[httpx.Response, httpx.Response]:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get("/health"), await client.get("/ready")

    health, ready = run(request())

    assert health.status_code == ready.status_code == 200
    assert stream.getvalue() == ""


def test_safe_source_label_strips_absolute_posix_and_windows_paths() -> None:
    assert safe_source_label("/home/operator/export.json") == "export.json"
    assert safe_source_label(r"C:\Users\operator\export.json") == "export.json"
    assert safe_source_label("upload-42") == "upload-42"
