import json
from asyncio import run
from collections import Counter

import httpx
from fastapi import FastAPI

from trailweaver.api.app import app as default_app
from trailweaver.api.demo import DEMO_INCIDENT_ID, create_demo_app


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


def _demo_client() -> _ApiClient:
    return _ApiClient(create_demo_app())


def test_default_application_remains_empty() -> None:
    response = _ApiClient(default_app).get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == []


def test_demo_application_exposes_exactly_one_deterministic_incident() -> None:
    response = _demo_client().get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == [
        {
            "incident_id": DEMO_INCIDENT_ID,
            "title": "Possible AWS account compromise",
            "severity": "high",
            "started_at": "2026-09-23T10:01:00Z",
            "ended_at": "2026-09-23T10:08:00Z",
        }
    ]


def test_demo_incident_contains_three_real_detection_signals() -> None:
    body = _demo_client().get(f"/api/v1/incidents/{DEMO_INCIDENT_ID}").json()

    assert [entry["rule_id"] for entry in body["timeline"]] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]
    assert body["primary_actor"]["name"] == "developer"
    assert body["severity"] == "high"


def test_demo_risk_comes_from_the_real_risk_service() -> None:
    body = _demo_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/risk"
    ).json()

    assert body["score"] == 80
    assert body["level"] == "critical"
    assert [factor["points"] for factor in body["factors"]] == [20, 20, 40]
    assert body["explanation"].startswith("Score 80 of 100")


def test_demo_mitre_mapping_comes_from_the_real_mapper() -> None:
    body = _demo_client().get(
        f"/api/v1/incidents/{DEMO_INCIDENT_ID}/mitre"
    ).json()

    assert [technique["technique_id"] for technique in body["techniques"]] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]


def test_demo_blast_radius_comes_from_the_real_analysis_service() -> None:
    body = _demo_client().get(
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


def test_demo_guidance_comes_from_the_real_advisor() -> None:
    body = _demo_client().get(
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


def test_demo_raw_event_is_not_exposed_by_any_api_response() -> None:
    client = _demo_client()
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
