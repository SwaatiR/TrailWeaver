from datetime import UTC, datetime, timedelta

import pytest

from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.models import JsonObject, NormalizedEvent
from trailweaver.risk import (
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    RiskScorer,
    risk_level_for_score,
)
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
USER_ADMIN = "aws.iam.admin_policy_attached_to_user"
ROLE_ADMIN = "aws.iam.admin_policy_attached_to_role"


def _signal(
    rule_id: str,
    *,
    minutes: int,
    raw_event: JsonObject | None = None,
) -> Signal:
    return Signal(
        signal_id=f"signal-{minutes}-{rule_id}",
        rule_id=rule_id,
        title=f"Signal for {rule_id}",
        description="A source signal for risk tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider="aws",
            service="test",
            action="TestAction",
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=f"Normalized signal reason for {rule_id}.",
    )


def _incident(
    rule_ids: tuple[str, ...],
    *,
    raw_events: tuple[JsonObject, ...] | None = None,
) -> Incident:
    evidence = raw_events or tuple({} for _ in rule_ids)
    signals = tuple(
        _signal(rule_id, minutes=index, raw_event=evidence[index])
        for index, rule_id in enumerate(rule_ids)
    )
    correlation_match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="aws.identity.possible_account_compromise_sequence",
        title="Possible AWS account compromise sequence",
        description="Related AWS identity-security activity was observed.",
        reason="The signals matched a suspicious sequence.",
        signals=signals,
    )
    return Incident(
        incident_id="incident-1",
        title="Possible AWS account compromise",
        description="Related identity-security events require investigation.",
        severity=SignalSeverity.HIGH,
        created_at=BASE_TIME + timedelta(minutes=20),
        correlation_match=correlation_match,
        summary="Possible account compromise activity was observed.",
    )


def _factor_for(assessment: RiskAssessment, identifier: str) -> RiskFactor:
    return next(factor for factor in assessment.factors if factor.identifier == identifier)


def test_existing_three_stage_sequence_scores_eighty() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, USER_ADMIN))

    assessment = RiskScorer().score(incident)

    assert assessment.score == 80
    assert tuple(factor.points for factor in assessment.factors) == (20, 20, 40)


def test_score_eighty_maps_to_critical() -> None:
    assessment = RiskScorer().score(_incident((LOGIN, ACCESS_KEY, USER_ADMIN)))

    assert assessment.level is RiskLevel.CRITICAL


def test_login_without_mfa_contributes_twenty_points() -> None:
    assessment = RiskScorer().score(_incident((LOGIN,)))

    assert _factor_for(assessment, LOGIN).points == 20
    assert assessment.score == 20


def test_access_key_creation_contributes_twenty_points() -> None:
    assessment = RiskScorer().score(_incident((ACCESS_KEY,)))

    assert _factor_for(assessment, ACCESS_KEY).points == 20
    assert assessment.score == 20


def test_admin_user_attachment_contributes_forty_points() -> None:
    assessment = RiskScorer().score(_incident((USER_ADMIN,)))

    assert _factor_for(assessment, USER_ADMIN).points == 40
    assert assessment.score == 40


def test_admin_role_attachment_contributes_forty_points() -> None:
    assessment = RiskScorer().score(_incident((ROLE_ADMIN,)))

    assert _factor_for(assessment, ROLE_ADMIN).points == 40
    assert assessment.score == 40


def test_duplicate_signal_types_contribute_at_most_once() -> None:
    assessment = RiskScorer().score(
        _incident((LOGIN, LOGIN, ACCESS_KEY, ACCESS_KEY, USER_ADMIN, USER_ADMIN))
    )

    assert assessment.score == 80
    assert tuple(factor.identifier for factor in assessment.factors) == (
        LOGIN,
        ACCESS_KEY,
        USER_ADMIN,
    )


def test_user_and_role_admin_attachments_share_one_contribution() -> None:
    assessment = RiskScorer().score(
        _incident((LOGIN, ACCESS_KEY, USER_ADMIN, ROLE_ADMIN))
    )

    assert assessment.score == 80
    assert sum(
        factor.points
        for factor in assessment.factors
        if factor.identifier in {USER_ADMIN, ROLE_ADMIN}
    ) == 40


def test_unknown_signal_rule_ids_contribute_zero() -> None:
    assessment = RiskScorer().score(
        _incident((LOGIN, "example.unknown", ACCESS_KEY))
    )

    assert assessment.score == 40
    assert tuple(factor.identifier for factor in assessment.factors) == (
        LOGIN,
        ACCESS_KEY,
    )


def test_risk_assessment_caps_factor_total_at_one_hundred() -> None:
    assessment = RiskAssessment(
        factors=(
            RiskFactor(identifier="test.first", description="First factor.", points=60),
            RiskFactor(identifier="test.second", description="Second factor.", points=60),
        ),
        explanation="Two constructed factors verify score capping.",
    )

    assert assessment.score == 100
    assert assessment.level is RiskLevel.CRITICAL


def test_each_risk_factor_has_readable_deterministic_reasoning() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, USER_ADMIN))

    first = RiskScorer().score(incident)
    second = RiskScorer().score(incident)

    assert first.factors == second.factors
    assert all(factor.identifier for factor in first.factors)
    assert all(factor.description.endswith(".") for factor in first.factors)
    assert tuple(factor.description for factor in first.factors) == (
        "Successful AWS console login occurred without MFA.",
        "A new IAM access key was created.",
        "AWS AdministratorAccess policy was attached to an IAM user.",
    )


def test_same_incident_produces_same_assessment_repeatedly() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, ROLE_ADMIN))
    scorer = RiskScorer()

    assert scorer.score(incident) == scorer.score(incident)


def test_risk_scoring_does_not_mutate_incident() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, USER_ADMIN))
    original_match = incident.correlation_match
    original_signals = incident.correlation_match.signals

    RiskScorer().score(incident)

    assert incident.correlation_match is original_match
    assert incident.correlation_match.signals is original_signals
    assert tuple(signal.rule_id for signal in original_signals) == (
        LOGIN,
        ACCESS_KEY,
        USER_ADMIN,
    )


def test_risk_scoring_does_not_inspect_raw_event() -> None:
    raw_events: tuple[JsonObject, ...] = (
        {"rule_id": "example.unknown"},
        {"eventName": "DeleteAccessKey", "errorCode": "AccessDenied"},
        {"rule_id": ROLE_ADMIN, "confirmedCompromise": True},
    )
    incident = _incident(
        (LOGIN, ACCESS_KEY, USER_ADMIN),
        raw_events=raw_events,
    )

    assessment = RiskScorer().score(incident)

    assert assessment.score == 80
    assert tuple(factor.identifier for factor in assessment.factors) == (
        LOGIN,
        ACCESS_KEY,
        USER_ADMIN,
    )


def test_no_known_factor_evidence_produces_zero_and_low() -> None:
    assessment = RiskScorer().score(_incident(("example.unknown",)))

    assert assessment.score == 0
    assert assessment.level is RiskLevel.LOW
    assert assessment.factors == ()


def test_risk_wording_does_not_claim_confirmed_compromise() -> None:
    assessment = RiskScorer().score(_incident((LOGIN, ACCESS_KEY, USER_ADMIN)))

    assert "requires investigation" in assessment.explanation
    assert "does not confirm compromise" in assessment.explanation
    assert "hacked" not in assessment.explanation
    assert "attacker" not in assessment.explanation


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, RiskLevel.LOW),
        (24, RiskLevel.LOW),
        (25, RiskLevel.MEDIUM),
        (49, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (79, RiskLevel.HIGH),
        (80, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_threshold_boundaries(
    score: int, expected_level: RiskLevel
) -> None:
    assert risk_level_for_score(score) is expected_level
