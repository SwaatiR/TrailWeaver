from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import (
    IncidentFactory,
    UnsupportedCorrelationRuleError,
)
from trailweaver.models import Actor, JsonObject, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
CORRELATION_RULE_ID = "aws.identity.possible_account_compromise_sequence"
ACTOR = Actor(
    actor_type="IAMUser",
    identifier="AIDAALICE",
    name="alice",
    arn="arn:aws:iam::123456789012:user/alice",
    account_id="123456789012",
)


def _signal(
    rule_id: str,
    *,
    minutes: int,
    title: str,
    reason: str,
    actor: Actor | None = ACTOR,
    raw_event: JsonObject | None = None,
) -> Signal:
    return Signal(
        signal_id=f"signal-{minutes}",
        rule_id=rule_id,
        title=title,
        description="A source detection signal.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider="aws",
            service="test",
            action="TestAction",
            actor=actor,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=reason,
    )


def _correlation_match(
    *,
    rule_id: str = CORRELATION_RULE_ID,
    actor: Actor | None = ACTOR,
    raw_events: tuple[JsonObject, JsonObject, JsonObject] | None = None,
) -> CorrelationMatch:
    evidence = raw_events or ({}, {}, {})
    signals = (
        _signal(
            "aws.auth.console_login_without_mfa",
            minutes=0,
            title="AWS console login without MFA",
            reason="Successful AWS console login occurred without MFA.",
            actor=actor,
            raw_event=evidence[0],
        ),
        _signal(
            "aws.iam.access_key_created",
            minutes=5,
            title="IAM access key created",
            reason="A new access key was created for IAM user alice.",
            actor=actor,
            raw_event=evidence[1],
        ),
        _signal(
            "aws.iam.admin_policy_attached_to_user",
            minutes=10,
            title="AdministratorAccess attached to IAM user",
            reason="AdministratorAccess was attached to IAM user alice.",
            actor=actor,
            raw_event=evidence[2],
        ),
    )
    return CorrelationMatch(
        correlation_id="correlation-1",
        rule_id=rule_id,
        title="Possible AWS account compromise sequence",
        description="Related AWS identity-security activity was observed.",
        reason="The expected three-stage sequence occurred within 15 minutes.",
        signals=signals,
    )


def test_valid_correlation_match_creates_one_incident() -> None:
    incident = IncidentFactory().create(_correlation_match())

    assert incident.title == "Possible AWS account compromise"
    assert "related AWS identity-security events" in incident.description


def test_incident_has_generated_uuid4_by_default() -> None:
    incident = IncidentFactory().create(_correlation_match())

    assert UUID(incident.incident_id).version == 4


def test_explicit_incident_id_is_preserved() -> None:
    incident = IncidentFactory().create(
        _correlation_match(), incident_id="incident-imported-123"
    )

    assert incident.incident_id == "incident-imported-123"


def test_current_sequence_incident_severity_is_high() -> None:
    incident = IncidentFactory().create(_correlation_match())

    assert incident.severity is SignalSeverity.HIGH


def test_incident_started_at_derives_from_correlation() -> None:
    correlation_match = _correlation_match()

    incident = IncidentFactory().create(correlation_match)

    assert incident.started_at == correlation_match.started_at


def test_incident_ended_at_derives_from_correlation() -> None:
    correlation_match = _correlation_match()

    incident = IncidentFactory().create(correlation_match)

    assert incident.ended_at == correlation_match.ended_at


def test_created_at_can_be_explicitly_injected() -> None:
    created_at = datetime(2026, 9, 23, 11, 0, tzinfo=UTC)

    incident = IncidentFactory().create(
        _correlation_match(), created_at=created_at
    )

    assert incident.created_at is created_at


def test_incident_references_exact_correlation_match() -> None:
    correlation_match = _correlation_match()

    incident = IncidentFactory().create(correlation_match)

    assert incident.correlation_match is correlation_match


def test_timeline_entries_are_chronological() -> None:
    incident = IncidentFactory().create(_correlation_match())

    timestamps = tuple(entry.timestamp for entry in incident.timeline)

    assert timestamps == tuple(sorted(timestamps))
    assert timestamps == (
        BASE_TIME,
        BASE_TIME + timedelta(minutes=5),
        BASE_TIME + timedelta(minutes=10),
    )


def test_timeline_preserves_signal_metadata() -> None:
    correlation_match = _correlation_match()
    incident = IncidentFactory().create(correlation_match)

    assert tuple(entry.rule_id for entry in incident.timeline) == tuple(
        signal.rule_id for signal in correlation_match.signals
    )
    assert tuple(entry.title for entry in incident.timeline) == tuple(
        signal.title for signal in correlation_match.signals
    )
    assert tuple(entry.reason for entry in incident.timeline) == tuple(
        signal.reason for signal in correlation_match.signals
    )


def test_primary_actor_returns_normalized_actor() -> None:
    incident = IncidentFactory().create(_correlation_match())

    assert incident.primary_actor is ACTOR


def test_primary_actor_is_none_when_correlation_has_no_actor() -> None:
    incident = IncidentFactory().create(_correlation_match(actor=None))

    assert incident.primary_actor is None


def test_incident_wording_does_not_claim_confirmed_compromise() -> None:
    incident = IncidentFactory().create(_correlation_match())
    wording = f"{incident.title} {incident.description} {incident.summary}".lower()

    assert "possible" in wording
    assert "confirmed" not in wording


def test_incident_creation_does_not_inspect_raw_event() -> None:
    raw_events: tuple[JsonObject, JsonObject, JsonObject] = (
        {"userIdentity": {"arn": "arn:aws:iam::1:user/one"}},
        {"eventName": "DeleteAccessKey", "errorCode": "AccessDenied"},
        {"eventSource": "different.amazonaws.com"},
    )
    correlation_match = _correlation_match(raw_events=raw_events)

    incident = IncidentFactory().create(correlation_match)

    assert incident.correlation_match is correlation_match
    assert incident.primary_actor is ACTOR
    assert len(incident.timeline) == 3


def test_unsupported_correlation_rule_fails_clearly() -> None:
    correlation_match = _correlation_match(rule_id="example.unsupported_correlation")

    with pytest.raises(
        UnsupportedCorrelationRuleError,
        match="example.unsupported_correlation",
    ):
        IncidentFactory().create(correlation_match)
