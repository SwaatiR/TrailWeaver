import json
from asyncio import run
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI

from trailweaver.api.app import create_app
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.cloud_context import (
    CloudAsset,
    CloudAssetType,
    CloudContext,
    PermissionEffect,
    PermissionGrant,
)
from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.models import Actor, JsonObject, NormalizedEvent, SecurityAttributes
from trailweaver.risk import RiskAssessment, RiskFactor, RiskScorer
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
ACTOR_ARN = "arn:aws:iam::123456789012:user/alice"
ACTOR = Actor(
    actor_type="IAMUser",
    identifier="AIDAALICE",
    name="alice",
    arn=ACTOR_ARN,
    account_id="123456789012",
)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
ADMIN = "aws.iam.admin_policy_attached_to_user"


def _signal(
    rule_id: str,
    *,
    minutes: int,
    actor: Actor | None = ACTOR,
    source_ip: str | None = None,
    attributes: SecurityAttributes | None = None,
    raw_event: JsonObject | None = None,
) -> Signal:
    return Signal(
        signal_id=f"signal-{minutes}",
        rule_id=rule_id,
        title=f"Signal for {rule_id}",
        description="Normalized signal used by API tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider="aws",
            service="test",
            action="TestAction",
            source_ip=source_ip,
            actor=actor,
            attributes={} if attributes is None else attributes,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=f"Normalized reason for {rule_id}.",
    )


def _incident(
    *,
    incident_id: str = "incident-1",
    actor: Actor | None = ACTOR,
    raw_event: JsonObject | None = None,
) -> Incident:
    signals = (
        _signal(
            LOGIN,
            minutes=0,
            actor=actor,
            source_ip="192.0.2.10",
            raw_event=raw_event,
        ),
        _signal(
            ACCESS_KEY,
            minutes=5,
            actor=actor,
            attributes={"target_user": "alice"},
            raw_event=raw_event,
        ),
        _signal(
            ADMIN,
            minutes=10,
            actor=actor,
            attributes={"target_user": "alice"},
            raw_event=raw_event,
        ),
    )
    match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="aws.identity.possible_account_compromise_sequence",
        title="Possible AWS account compromise sequence",
        description="Related AWS identity-security activity was observed.",
        reason="The normalized signals matched a suspicious sequence.",
        signals=signals,
    )
    return Incident(
        incident_id=incident_id,
        title="Possible AWS account compromise",
        description="Related identity-security events require investigation.",
        severity=SignalSeverity.HIGH,
        correlation_match=match,
        summary="Possible account compromise activity was observed.",
        created_at=BASE_TIME + timedelta(minutes=20),
    )


class _ApiClient:
    """Small synchronous facade over HTTPX's in-process ASGI test transport."""

    def __init__(self, application: FastAPI) -> None:
        self._application = application

    def get(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.get(path, headers=headers)

        return run(request())

    def options(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self._application)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.options(path, headers=headers)

        return run(request())


def _client(
    *incidents: Incident,
    cloud_context: CloudContext | None = None,
) -> _ApiClient:
    repository = InMemoryIncidentRepository(incidents)
    return _ApiClient(create_app(repository=repository, cloud_context=cloud_context))


def _reachable_context(*, include_grant: bool = True) -> CloudContext:
    asset = CloudAsset(
        asset_type=CloudAssetType.SECRET,
        provider="aws",
        account_id="123456789012",
        name="production-api-key",
        arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:production-api-key",
        metadata={"environment": "production", "labels": ["sensitive"]},
    )
    grants = (
        PermissionGrant(
            subject=ACTOR_ARN,
            actions=("secretsmanager:GetSecretValue",),
            resources=(asset.asset_id,),
            effect=PermissionEffect.ALLOW,
            source="attached_managed_policy:ReadProductionSecret",
        ),
    )
    return CloudContext(
        assets=(asset,),
        permission_grants=grants if include_grant else (),
    )


def _assert_iso8601(value: str) -> None:
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None


def test_health_returns_ok() -> None:
    response = _client().get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_default_cors_allows_local_vite_origin() -> None:
    response = _client().get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_does_not_allow_unconfigured_origin() -> None:
    response = _client().get(
        "/health",
        headers={"Origin": "https://untrusted.example"},
    )

    assert "access-control-allow-origin" not in response.headers


def test_cors_origins_can_be_injected_explicitly() -> None:
    client = _ApiClient(create_app(cors_origins=("https://dashboard.example",)))

    response = client.get(
        "/health",
        headers={"Origin": "https://dashboard.example"},
    )

    assert response.headers["access-control-allow-origin"] == "https://dashboard.example"


def test_cors_origins_can_be_configured_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TRAILWEAVER_CORS_ORIGINS",
        "https://one.example, https://two.example,https://one.example",
    )
    client = _ApiClient(create_app())

    first_response = client.get("/health", headers={"Origin": "https://one.example"})
    second_response = client.get("/health", headers={"Origin": "https://two.example"})

    assert first_response.headers["access-control-allow-origin"] == "https://one.example"
    assert second_response.headers["access-control-allow-origin"] == "https://two.example"


def test_cors_preflight_allows_configured_frontend_get_request() -> None:
    response = _client().options(
        "/api/v1/incidents",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Accept",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "Accept" in response.headers["access-control-allow-headers"]


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValueError, match="explicit origins"):
        create_app(cors_origins=("*",))


def test_wildcard_cors_origin_from_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRAILWEAVER_CORS_ORIGINS", "*")

    with pytest.raises(ValueError, match="explicit origins"):
        create_app()


def test_empty_repository_returns_empty_incident_list() -> None:
    response = _client().get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == []


def test_incident_list_returns_only_compact_summary_data() -> None:
    response = _client(_incident()).get("/api/v1/incidents")

    assert response.status_code == 200
    assert response.json() == [
        {
            "incident_id": "incident-1",
            "title": "Possible AWS account compromise",
            "severity": "high",
            "started_at": "2026-09-23T10:30:00Z",
            "ended_at": "2026-09-23T10:40:00Z",
        }
    ]


def test_incident_detail_returns_expected_fields_and_chronological_timeline() -> None:
    response = _client(_incident()).get("/api/v1/incidents/incident-1")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "incident-1"
    assert body["title"] == "Possible AWS account compromise"
    assert body["description"] == "Related identity-security events require investigation."
    assert body["severity"] == "high"
    assert body["summary"] == "Possible account compromise activity was observed."
    assert [entry["rule_id"] for entry in body["timeline"]] == [LOGIN, ACCESS_KEY, ADMIN]
    timestamps = [
        datetime.fromisoformat(entry["timestamp"])
        for entry in body["timeline"]
    ]
    assert timestamps == sorted(timestamps)


def test_primary_actor_is_serialized_when_available() -> None:
    body = _client(_incident()).get("/api/v1/incidents/incident-1").json()

    assert body["primary_actor"] == {
        "actor_type": "IAMUser",
        "identifier": "AIDAALICE",
        "name": "alice",
        "arn": ACTOR_ARN,
        "account_id": "123456789012",
    }


def test_missing_primary_actor_is_null() -> None:
    body = _client(_incident(actor=None)).get("/api/v1/incidents/incident-1").json()

    assert body["primary_actor"] is None


@pytest.mark.parametrize(
    "suffix",
    ["", "/risk", "/mitre", "/graph", "/blast-radius", "/guidance"],
)
def test_unknown_incident_returns_consistent_404(suffix: str) -> None:
    response = _client().get(f"/api/v1/incidents/missing{suffix}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Incident 'missing' not found"}


def test_risk_endpoint_returns_existing_explainable_assessment() -> None:
    body = _client(_incident()).get("/api/v1/incidents/incident-1/risk").json()

    assert body["score"] == 80
    assert body["level"] == "critical"
    assert [factor["points"] for factor in body["factors"]] == [20, 20, 40]
    assert body["explanation"].startswith("Score 80 of 100")


def test_mitre_endpoint_returns_techniques_and_tactics() -> None:
    body = _client(_incident()).get("/api/v1/incidents/incident-1/mitre").json()

    assert [technique["technique_id"] for technique in body["techniques"]] == [
        "T1078.004",
        "T1098.001",
        "T1098.003",
    ]
    assert all(
        set(technique) == {"technique_id", "name", "tactics", "description"}
        for technique in body["techniques"]
    )
    assert "Persistence" in body["tactics"]


def test_graph_endpoint_returns_json_safe_nodes_and_edges() -> None:
    body = _client(_incident()).get("/api/v1/incidents/incident-1/graph").json()

    assert body["nodes"]
    assert body["edges"]
    assert body["nodes"][0]["node_type"] == "identity"
    assert body["edges"][0]["relationship"] == "logged_in_from"
    _assert_iso8601(body["edges"][0]["timestamp"])


def test_blast_radius_works_with_cloud_context() -> None:
    body = (
        _client(_incident(), cloud_context=_reachable_context())
        .get("/api/v1/incidents/incident-1/blast-radius")
        .json()
    )

    assert body["available"] is True
    assert body["subject"] == ACTOR_ARN
    assert body["total_reachable_assets"] == 1
    assert body["reachable_assets"][0]["asset_type"] == "secret"
    assert body["reachable_assets"][0]["metadata"] == {
        "environment": "production",
        "labels": ["sensitive"],
    }
    assert body["matched_grants"][0]["effect"] == "allow"


def test_missing_context_is_distinct_from_empty_reachable_result() -> None:
    incident = _incident()
    unavailable = _client(incident).get(
        "/api/v1/incidents/incident-1/blast-radius"
    )
    empty = _client(
        incident,
        cloud_context=_reachable_context(include_grant=False),
    ).get("/api/v1/incidents/incident-1/blast-radius")

    assert unavailable.json() == {
        "available": False,
        "reason": "Blast-radius analysis is unavailable because no cloud context is loaded.",
    }
    assert empty.json()["available"] is True
    assert empty.json()["total_reachable_assets"] == 0
    assert empty.json()["reachable_assets"] == []


def test_guidance_returns_recommendations() -> None:
    body = _client(_incident()).get("/api/v1/incidents/incident-1/guidance").json()

    assert body["recommendations"]
    assert body["summary"]
    assert body["recommendations"][0]["priority"] == "high"


def test_guidance_incorporates_available_blast_radius() -> None:
    body = (
        _client(_incident(), cloud_context=_reachable_context())
        .get("/api/v1/incidents/incident-1/guidance")
        .json()
    )

    assert any(
        recommendation["recommendation_id"] == "review-potentially-reachable-assets"
        for recommendation in body["recommendations"]
    )


def test_all_timestamps_use_iso8601_serialization() -> None:
    client = _client(_incident())
    summary = client.get("/api/v1/incidents").json()[0]
    detail = client.get("/api/v1/incidents/incident-1").json()

    for value in (
        summary["started_at"],
        summary["ended_at"],
        detail["created_at"],
        detail["started_at"],
        detail["ended_at"],
        *(entry["timestamp"] for entry in detail["timeline"]),
    ):
        _assert_iso8601(value)


def test_enum_values_serialize_as_clear_strings() -> None:
    client = _client(_incident(), cloud_context=_reachable_context())

    assert client.get("/api/v1/incidents").json()[0]["severity"] == "high"
    assert client.get("/api/v1/incidents/incident-1/risk").json()["level"] == "critical"
    assert client.get("/api/v1/incidents/incident-1/graph").json()["nodes"][0][
        "node_type"
    ] == "identity"
    assert client.get("/api/v1/incidents/incident-1/guidance").json()[
        "recommendations"
    ][0]["priority"] == "high"


def test_raw_event_never_appears_in_incident_responses() -> None:
    secret = "raw-cloudtrail-secret-value"
    client = _client(_incident(raw_event={"raw_event": {"secret": secret}}))

    for path in ("/api/v1/incidents", "/api/v1/incidents/incident-1"):
        serialized = json.dumps(client.get(path).json())
        assert "raw_event" not in serialized
        assert secret not in serialized


def test_raw_event_never_appears_in_analysis_responses() -> None:
    secret = "raw-cloudtrail-secret-value"
    client = _client(
        _incident(raw_event={"raw_event": {"secret": secret}}),
        cloud_context=_reachable_context(),
    )

    for suffix in ("risk", "mitre", "graph", "blast-radius", "guidance"):
        serialized = json.dumps(
            client.get(f"/api/v1/incidents/incident-1/{suffix}").json()
        )
        assert "raw_event" not in serialized
        assert secret not in serialized


def test_risk_endpoint_delegates_to_existing_domain_scorer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_with: list[Incident] = []

    def score(self: RiskScorer, incident: Incident) -> RiskAssessment:
        del self
        called_with.append(incident)
        return RiskAssessment(
            factors=(
                RiskFactor(
                    identifier="test.delegated",
                    description="Returned by the injected domain scorer test.",
                    points=7,
                ),
            ),
            explanation="Delegated to RiskScorer.score.",
        )

    monkeypatch.setattr(RiskScorer, "score", score)
    incident = _incident()

    body = _client(incident).get("/api/v1/incidents/incident-1/risk").json()

    assert called_with == [incident]
    assert body["score"] == 7
    assert body["factors"][0]["identifier"] == "test.delegated"


def test_application_factory_uses_injected_repository_and_context() -> None:
    incident = _incident(incident_id="injected-incident")
    repository = InMemoryIncidentRepository((incident,))
    context = _reachable_context()

    client = _ApiClient(create_app(repository=repository, cloud_context=context))

    assert client.get("/api/v1/incidents").json()[0]["incident_id"] == "injected-incident"
    assert client.get(
        "/api/v1/incidents/injected-incident/blast-radius"
    ).json()["available"] is True


def test_default_factory_does_not_create_production_incidents() -> None:
    client = _ApiClient(create_app())

    assert client.get("/api/v1/incidents").json() == []
