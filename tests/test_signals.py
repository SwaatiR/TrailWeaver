from datetime import UTC, datetime
from uuid import UUID

import pytest

from trailweaver.models import NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity


def _source_event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 23, 10, 30, tzinfo=UTC),
        provider="aws",
        service="cloudtrail",
        action="StopLogging",
        attributes={"trail_name": "production-audit"},
        raw_event={"eventID": "event-123"},
    )


def test_create_low_severity_signal_with_explicit_id() -> None:
    event = _source_event()
    reason = "Successful StopLogging action was observed for trail production-audit."

    signal = Signal(
        signal_id="signal-123",
        rule_id="aws.cloudtrail.logging_stopped",
        title="CloudTrail logging stopped",
        description="CloudTrail logging was stopped for an audit trail.",
        severity=SignalSeverity.LOW,
        source_event=event,
        reason=reason,
    )

    assert signal.signal_id == "signal-123"
    assert signal.rule_id == "aws.cloudtrail.logging_stopped"
    assert signal.title == "CloudTrail logging stopped"
    assert signal.description == "CloudTrail logging was stopped for an audit trail."
    assert signal.severity is SignalSeverity.LOW
    assert signal.source_event is event
    assert signal.timestamp == event.timestamp
    assert signal.reason == reason


def test_create_critical_severity_signal() -> None:
    signal = Signal(
        rule_id="example.critical_activity",
        title="Critical activity",
        description="A critical security-relevant action was observed.",
        severity=SignalSeverity.CRITICAL,
        source_event=_source_event(),
        reason="The event matched a critical rule condition.",
    )

    assert signal.severity is SignalSeverity.CRITICAL


def test_automatically_generated_signal_ids_are_valid_and_distinct() -> None:
    event = _source_event()
    first = Signal(
        rule_id="example.first",
        title="First signal",
        description="The first signal.",
        severity=SignalSeverity.MEDIUM,
        source_event=event,
        reason="First deterministic reason.",
    )
    second = Signal(
        rule_id="example.second",
        title="Second signal",
        description="The second signal.",
        severity=SignalSeverity.HIGH,
        source_event=event,
        reason="Second deterministic reason.",
    )

    assert UUID(first.signal_id).version == 4
    assert UUID(second.signal_id).version == 4
    assert first.signal_id != second.signal_id


def test_signal_severity_is_limited_to_supported_values() -> None:
    assert {severity.value for severity in SignalSeverity} == {
        "low",
        "medium",
        "high",
        "critical",
    }

    with pytest.raises(ValueError):
        SignalSeverity("informational")
