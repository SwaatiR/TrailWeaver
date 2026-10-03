"""Tests for the local deterministic demo workflow.

The demo application starts from an empty workspace, runs the production
file-analysis pipeline, keeps S3 disabled, and exposes a demo-only reset.
Separately, the deterministic incident builders keep their exact content
coverage through an explicitly constructed showcase application.
"""

import json
from asyncio import run
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from trailweaver.api.app import app as default_app
from trailweaver.api.app import create_app
from trailweaver.api.demo import (
    DEMO_INCIDENT_ID,
    create_demo_app,
    create_demo_cloud_context,
    create_demo_incident,
)
from trailweaver.api.service import InMemoryIncidentRepository

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail"


class _ApiClient:
    """Small synchronous facade for focused demo API tests."""

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


def _demo_client() -> _ApiClient:
    return _ApiClient(create_demo_app())


def _showcase_client() -> _ApiClient:
    """Build the pre-populated deterministic incident without the demo app."""

    return _ApiClient(
        create_app(
            repository=InMemoryIncidentRepository((create_demo_incident(),)),
            cloud_context=create_demo_cloud_context(),
        )
    )


def _fixture(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def test_default_application_remains_empty() -> None:
    response = _ApiClient(default_app).get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == []


def test_demo_application_starts_with_zero_incidents() -> None:
    response = _demo_client().get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == []


def test_demo_capabilities_enable_file_but_not_s3() -> None:
    response = _demo_client().get("/api/v1/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "file_analysis": True,
        "s3_analysis": False,
        "demo_mode": True,
    }


def test_demo_fixture_analysis_produces_expected_pipeline_result() -> None:
    client = _demo_client()
    response = client.post(
        "/api/v1/analyses/file",
        content=_fixture("account-compromise-sequence.json"),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_records"] == 3
    assert body["accepted_records"] == 3
    assert body["failed_records"] == 0
    assert body["signals"] == 3
    assert body["correlations"] == 1
    assert body["incidents_created"] == 1
    assert body["persisted_incidents"] == 1
    assert len(body["incident_ids"]) == 1

    incident_id = body["incident_ids"][0]
    listed = client.get("/api/v1/incidents").json()
    assert [item["incident_id"] for item in listed] == [incident_id]
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["title"] == "Possible AWS account compromise"
    assert [entry["rule_id"] for entry in detail["timeline"]] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]


def test_demo_reset_returns_to_zero_and_stays_repeatable() -> None:
    client = _demo_client()
    payload = _fixture("account-compromise-sequence.json")
    headers = {"Content-Type": "application/json"}

    first = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    assert first.status_code == 200
    assert len(client.get("/api/v1/incidents").json()) == 1

    reset = client.post("/api/v1/demo/reset")
    assert reset.status_code == 200
    assert reset.json() == {"status": "ok", "incidents": 0}
    assert client.get("/api/v1/incidents").json() == []

    second = client.post("/api/v1/analyses/file", content=payload, headers=headers)
    assert second.status_code == 200
    assert second.json()["incidents_created"] == 1
    assert second.json()["incident_ids"] != first.json()["incident_ids"]
    assert len(client.get("/api/v1/incidents").json()) == 1


def test_demo_s3_analysis_stays_disabled() -> None:
    response = _demo_client().post(
        "/api/v1/analyses/s3",
        json_body={"bucket": "example-bucket", "key": "trail/export.json"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "S3 analysis is unavailable on this API instance"
    }


def test_reset_capability_is_not_exposed_by_production() -> None:
    response = _ApiClient(create_app()).post("/api/v1/demo/reset")

    assert response.status_code == 404


def test_showcase_application_exposes_exactly_one_deterministic_incident() -> None:
    response = _showcase_client().get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == [
        {
            "incident_id": DEMO_INCIDENT_ID,
            "title": "Possible AWS account compromise",
            "severity": "high",
            "created_at": "2026-09-23T10:09:00Z",
            "started_at": "2026-09-23T10:01:00Z",
            "ended_at": "2026-09-23T10:08:00Z",
        }
    ]


def test_showcase_incident_contains_three_real_detection_signals() -> None:
    body = _showcase_client().get(f"/api/v1/incidents/{DEMO_INCIDENT_ID}").json()

    assert [entry["rule_id"] for entry in body["timeline"]] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]
    assert body["primary_actor"]["name"] == "developer"
    assert body["severity"] == "high"


def test_showcase_timeline_and_graph_share_stable_signal_identity() -> None:
    client = _showcase_client()
    timeline = client.get(f"/api/v1/incidents/{DEMO_INCIDENT_ID}").json()[
        "timeline"
    ]
    edges = client.get(f"/api/v1/incidents/{DEMO_INCIDENT_ID}/graph").json()[
        "edges"
    ]

    assert [entry["signal_id"] for entry in timeline] == [
        "demo-signal-1",
        "demo-signal-2",
        "demo-signal-3",
    ]
    timeline_ids = {entry["signal_id"] for entry in timeline}
    assert [edge["signal_id"] for edge in edges] == [
        "demo-signal-1",
        "demo-signal-2",
        "demo-signal-3",
    ]
    assert all(edge["signal_id"] in timeline_ids for edge in edges)
    assert [edge["relationship"] for edge in edges] == [
        "logged_in_from",
        "affected",
        "granted",
    ]


def test_showcase_risk_comes_from_the_real_risk_service() -> None:
    body = _showcase_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/risk"
    ).json()

    assert body["score"] == 80
    assert body["level"] == "critical"
    assert [factor["points"] for factor in body["factors"]] == [20, 20, 40]
    assert body["explanation"].startswith("Score 80 of 100")


def test_showcase_mitre_mapping_comes_from_the_real_mapper() -> None:
    body = _showcase_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/mitre"
    ).json()

    assert [technique["technique_id"] for technique in body["techniques"]] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]


def test_showcase_blast_radius_comes_from_the_real_analysis_service() -> None:
    body = _showcase_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/blast-radius"
    ).json()

    assert body["available"] is True
    assert body["total_reachable_assets"] == 5
    assert Counter(asset["asset_type"] for asset in body["reachable_assets"]) == {
        "storage": 2,
        "compute": 1,
        "database": 1,
        "secret": 1,
    }
    assert "potentially reachable" in body["summary"]


def test_showcase_guidance_comes_from_the_real_advisor() -> None:
    body = _showcase_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/guidance"
    ).json()

    recommendation_ids = {
        recommendation["recommendation_id"]
        for recommendation in body["recommendations"]
    }
    assert recommendation_ids == {
        "review-administrator-access-assignment",
        "verify-console-login-without-mfa",
        "review-access-key-creation",
        "review-potentially-reachable-assets",
    }
    reachability = next(
        recommendation
        for recommendation in body["recommendations"]
        if recommendation["recommendation_id"]
        == "review-potentially-reachable-assets"
    )
    assert "does not establish" in reachability["rationale"]
    assert "accessed" in reachability["rationale"]


def test_showcase_raw_event_is_not_exposed_by_any_api_response() -> None:
    client = _showcase_client()
    paths = (
        "/api/v1/incidents",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/risk",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/mitre",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/graph",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/blast-radius",
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/guidance",
    )

    for path in paths:
        serialized = json.dumps(client.get(path).json())
        assert "raw_event" not in serialized
        assert "m16-1-raw-evidence" not in serialized
