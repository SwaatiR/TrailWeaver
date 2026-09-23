import socket
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from trailweaver.blast_radius import BlastRadiusResult
from trailweaver.cloud_context import CloudAsset, CloudAssetType
from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.investigation import (
    InvestigationAdvisor,
    InvestigationGuidance,
    InvestigationRecommendation,
    RecommendationPriority,
)
from trailweaver.models import JsonObject, NormalizedEvent, SecurityAttributes
from trailweaver.risk import RiskAssessment
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
USER_ADMIN = "aws.iam.admin_policy_attached_to_user"
ROLE_ADMIN = "aws.iam.admin_policy_attached_to_role"
LOGGING_STOPPED = "aws.cloudtrail.logging_stopped"


def _signal(
    rule_id: str,
    *,
    minutes: int = 0,
    source_ip: str | None = None,
    attributes: SecurityAttributes | None = None,
    raw_event: JsonObject | None = None,
) -> Signal:
    return Signal(
        signal_id=f"signal-{minutes}-{rule_id}",
        rule_id=rule_id,
        title=f"Signal for {rule_id}",
        description="A source signal for investigation-guidance tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider="aws",
            service="test",
            action="TestAction",
            source_ip=source_ip,
            attributes={} if attributes is None else attributes,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=f"Normalized signal reason for {rule_id}.",
    )


def _incident(*signals: Signal) -> Incident:
    match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="test.correlation",
        title="Test correlation",
        description="Related security activity was observed.",
        reason="The test evidence was correlated.",
        signals=signals,
    )
    return Incident(
        incident_id="incident-1",
        title="Potential security incident",
        description="Related activity requires investigation.",
        severity=SignalSeverity.HIGH,
        correlation_match=match,
        summary="Potential security-sensitive activity was observed.",
        created_at=BASE_TIME + timedelta(minutes=20),
    )


def _recommendation(
    guidance: InvestigationGuidance, recommendation_id: str
) -> InvestigationRecommendation:
    return next(
        recommendation
        for recommendation in guidance.recommendations
        if recommendation.recommendation_id == recommendation_id
    )


def _blast_radius(*asset_types: CloudAssetType) -> BlastRadiusResult:
    assets = tuple(
        CloudAsset(
            asset_type=asset_type,
            provider="aws",
            name=f"asset-{index}",
        )
        for index, asset_type in enumerate(asset_types)
    )
    return BlastRadiusResult(
        subject="arn:aws:iam::123456789012:user/alice",
        reachable_assets=assets,
        matched_grants=(),
        summary="Known assets may be potentially reachable.",
    )


def test_login_without_mfa_generates_verification_guidance() -> None:
    guidance = InvestigationAdvisor().advise(_incident(_signal(LOGIN)))

    recommendation = _recommendation(
        guidance, "verify-console-login-without-mfa"
    )
    assert "expected" in recommendation.description
    assert "recognized" in recommendation.description


def test_known_source_ip_appears_in_login_rationale() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal(LOGIN, source_ip="192.0.2.10"))
    )

    recommendation = _recommendation(
        guidance, "verify-console-login-without-mfa"
    )
    assert "192.0.2.10" in recommendation.rationale


def test_missing_source_ip_still_produces_useful_login_guidance() -> None:
    guidance = InvestigationAdvisor().advise(_incident(_signal(LOGIN)))

    recommendation = _recommendation(
        guidance, "verify-console-login-without-mfa"
    )
    assert "no source IP was available" in recommendation.rationale
    assert recommendation.description


def test_access_key_creation_generates_credential_review_guidance() -> None:
    guidance = InvestigationAdvisor().advise(_incident(_signal(ACCESS_KEY)))

    recommendation = _recommendation(guidance, "review-access-key-creation")
    assert "authorized" in recommendation.description
    assert "activity performed after" in recommendation.description


def test_access_key_target_user_appears_when_available() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal(ACCESS_KEY, attributes={"target_user": "alice"}))
    )

    recommendation = _recommendation(guidance, "review-access-key-creation")
    assert "alice" in recommendation.rationale


def test_admin_user_assignment_generates_privilege_review_guidance() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal(USER_ADMIN, attributes={"target_user": "alice"}))
    )

    recommendation = _recommendation(
        guidance, "review-administrator-access-assignment"
    )
    assert "who authorized" in recommendation.description
    assert "IAM user alice" in recommendation.rationale


def test_admin_role_assignment_generates_privilege_review_guidance() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(ROLE_ADMIN, attributes={"target_role": "DeploymentRole"})
        )
    )

    recommendation = _recommendation(
        guidance, "review-administrator-access-assignment"
    )
    assert "still requires" in recommendation.description
    assert "IAM role DeploymentRole" in recommendation.rationale


def test_similar_admin_recommendations_are_deduplicated() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(USER_ADMIN, attributes={"target_user": "alice"}),
            _signal(
                ROLE_ADMIN,
                minutes=1,
                attributes={"target_role": "DeploymentRole"},
            ),
        )
    )

    admin_recommendations = tuple(
        recommendation
        for recommendation in guidance.recommendations
        if recommendation.recommendation_id
        == "review-administrator-access-assignment"
    )
    assert len(admin_recommendations) == 1
    assert "IAM user alice" in admin_recommendations[0].rationale
    assert "IAM role DeploymentRole" in admin_recommendations[0].rationale


def test_logging_stopped_generates_audit_guidance() -> None:
    guidance = InvestigationAdvisor().advise(_incident(_signal(LOGGING_STOPPED)))

    recommendation = _recommendation(
        guidance, "review-cloudtrail-logging-stop"
    )
    assert "intentionally stopped" in recommendation.description
    assert "audit gaps" in recommendation.description
    assert "if the action was unauthorized" in recommendation.description


def test_trail_name_appears_when_available() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(
                LOGGING_STOPPED,
                attributes={"trail_name": "security-audit"},
            )
        )
    )

    recommendation = _recommendation(
        guidance, "review-cloudtrail-logging-stop"
    )
    assert "security-audit" in recommendation.rationale


def test_reachable_assets_generate_blast_radius_guidance() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal("example.unknown")),
        blast_radius=_blast_radius(
            CloudAssetType.SECRET,
            CloudAssetType.DATABASE,
            CloudAssetType.STORAGE,
        ),
    )

    recommendation = _recommendation(
        guidance, "review-potentially-reachable-assets"
    )
    assert "3 known assets" in recommendation.description
    assert "secrets, databases" in recommendation.description
    assert "were accessed" in recommendation.rationale


def test_empty_blast_radius_does_not_generate_reachability_guidance() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal("example.unknown")),
        blast_radius=_blast_radius(),
    )

    assert all(
        recommendation.recommendation_id
        != "review-potentially-reachable-assets"
        for recommendation in guidance.recommendations
    )


def test_recommendation_priorities_follow_fixed_rules() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(LOGIN),
            _signal(ACCESS_KEY, minutes=1),
            _signal(USER_ADMIN, minutes=2),
            _signal(LOGGING_STOPPED, minutes=3),
        ),
        blast_radius=_blast_radius(CloudAssetType.SECRET),
    )

    priorities = {
        recommendation.recommendation_id: recommendation.priority
        for recommendation in guidance.recommendations
    }
    assert priorities == {
        "verify-console-login-without-mfa": RecommendationPriority.MEDIUM,
        "review-access-key-creation": RecommendationPriority.MEDIUM,
        "review-administrator-access-assignment": RecommendationPriority.HIGH,
        "review-cloudtrail-logging-stop": RecommendationPriority.HIGH,
        "review-potentially-reachable-assets": RecommendationPriority.MEDIUM,
    }


def test_recommendations_are_priority_then_chronology_ordered() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(LOGIN),
            _signal(LOGGING_STOPPED, minutes=1),
            _signal(ACCESS_KEY, minutes=2),
            _signal(USER_ADMIN, minutes=3),
        ),
        blast_radius=_blast_radius(CloudAssetType.SECRET),
    )

    assert tuple(
        recommendation.recommendation_id
        for recommendation in guidance.recommendations
    ) == (
        "review-cloudtrail-logging-stop",
        "review-administrator-access-assignment",
        "verify-console-login-without-mfa",
        "review-access-key-creation",
        "review-potentially-reachable-assets",
    )


def test_repeated_advisor_runs_return_equivalent_guidance() -> None:
    incident = _incident(
        _signal(LOGIN, source_ip="192.0.2.10"),
        _signal(ACCESS_KEY, minutes=1, attributes={"target_user": "alice"}),
        _signal(USER_ADMIN, minutes=2, attributes={"target_user": "alice"}),
    )
    advisor = InvestigationAdvisor()

    assert advisor.advise(incident) == advisor.advise(incident)


def test_advisor_does_not_mutate_inputs() -> None:
    attributes: SecurityAttributes = {"target_user": "alice"}
    incident = _incident(_signal(ACCESS_KEY, attributes=attributes))
    risk = RiskAssessment(factors=(), explanation="No defined risk factors.")
    blast_radius = _blast_radius(CloudAssetType.SECRET)
    original_signals = incident.correlation_match.signals
    original_assets = blast_radius.reachable_assets

    InvestigationAdvisor().advise(
        incident,
        risk_assessment=risk,
        blast_radius=blast_radius,
    )

    assert incident.correlation_match.signals is original_signals
    assert attributes == {"target_user": "alice"}
    assert blast_radius.reachable_assets is original_assets
    assert risk.factors == ()


def test_advisor_does_not_inspect_raw_event() -> None:
    raw_event: JsonObject = {
        "sourceIPAddress": "198.51.100.20",
        "requestParameters": {"userName": "raw-user"},
        "confirmedCompromise": True,
    }
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(
                LOGIN,
                source_ip="192.0.2.10",
                raw_event=raw_event,
            )
        )
    )

    recommendation = _recommendation(
        guidance, "verify-console-login-without-mfa"
    )
    assert "192.0.2.10" in recommendation.rationale
    assert "198.51.100.20" not in recommendation.rationale
    assert "raw-user" not in recommendation.rationale


def test_guidance_wording_does_not_claim_confirmed_compromise() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(
            _signal(LOGIN, source_ip="192.0.2.10"),
            _signal(ACCESS_KEY, minutes=1),
            _signal(USER_ADMIN, minutes=2),
            _signal(LOGGING_STOPPED, minutes=3),
        ),
        blast_radius=_blast_radius(CloudAssetType.SECRET),
    )
    wording = " ".join(
        (
            guidance.summary,
            *(
                f"{recommendation.title} {recommendation.description} "
                f"{recommendation.rationale}"
                for recommendation in guidance.recommendations
            ),
        )
    ).lower()

    assert "account is compromised" not in wording
    assert "malicious ip" not in wording
    assert "data was stolen" not in wording
    assert "attacker" not in wording


def test_advisor_makes_no_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("Investigation guidance attempted a network call")

    monkeypatch.setattr(socket, "create_connection", fail_if_called)

    guidance = InvestigationAdvisor().advise(_incident(_signal(LOGIN)))

    assert guidance.recommendations


def test_limited_evidence_returns_valid_guidance() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal("example.unknown"))
    )

    assert isinstance(guidance, InvestigationGuidance)
    assert guidance.recommendations == ()
    assert "no current investigation recommendation" in guidance.summary


def test_guidance_models_are_immutable() -> None:
    recommendation = InvestigationRecommendation(
        recommendation_id="test-recommendation",
        title="Test recommendation",
        description="Review the test evidence.",
        priority=RecommendationPriority.LOW,
        rationale="Normalized test evidence exists.",
    )
    guidance = InvestigationGuidance(
        recommendations=[recommendation],  # type: ignore[arg-type]
        summary="Test guidance.",
    )

    assert guidance.recommendations == (recommendation,)
    with pytest.raises(FrozenInstanceError):
        recommendation.title = "Changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        guidance.summary = "Changed"  # type: ignore[misc]


def test_summary_reflects_only_supported_recommendation_categories() -> None:
    guidance = InvestigationAdvisor().advise(
        _incident(_signal(LOGIN), _signal(ACCESS_KEY, minutes=1))
    )

    assert guidance.summary == (
        "TrailWeaver recommends reviewing identity activity and credential creation "
        "associated with this incident."
    )
