from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

from trailweaver.detection import DetectionEngine
from trailweaver.models import EventOutcome, JsonObject, NormalizedEvent, SecurityAttributes
from trailweaver.rules import SuccessfulCloudTrailStopLoggingRule
from trailweaver.signals import SignalSeverity


def _event(
    *,
    provider: str = "aws",
    service: str = "cloudtrail",
    action: str = "StopLogging",
    outcome: EventOutcome = EventOutcome.SUCCESS,
    attributes: SecurityAttributes | None = None,
    raw_event: JsonObject | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 23, 10, 30, tzinfo=UTC),
        provider=provider,
        service=service,
        action=action,
        outcome=outcome,
        attributes={} if attributes is None else attributes,
        raw_event={} if raw_event is None else raw_event,
    )


def test_rule_metadata_is_stable() -> None:
    rule = SuccessfulCloudTrailStopLoggingRule()

    assert rule.rule_id == "aws.cloudtrail.logging_stopped"
    assert rule.title == "CloudTrail logging stopped"
    assert rule.description == "CloudTrail logging was stopped for an audit trail."
    assert rule.severity is SignalSeverity.HIGH


def test_matching_event_produces_one_signal_with_rule_metadata() -> None:
    event = _event(attributes={"trail_name": "production-audit"})
    rule = SuccessfulCloudTrailStopLoggingRule()

    signals = DetectionEngine([rule]).evaluate(event)

    assert len(signals) == 1
    signal = signals[0]
    assert signal.source_event is event
    assert signal.rule_id == rule.rule_id
    assert signal.title == rule.title
    assert signal.description == rule.description
    assert signal.severity is rule.severity


def test_non_matching_action_produces_no_signal() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(_event(action="StartLogging"))

    assert signal is None


def test_failed_stop_logging_produces_no_signal() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(
        _event(outcome=EventOutcome.FAILURE)
    )

    assert signal is None


def test_wrong_provider_produces_no_signal() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(_event(provider="other-cloud"))

    assert signal is None


def test_wrong_service_produces_no_signal() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(_event(service="config"))

    assert signal is None


def test_reason_includes_trail_name_when_available() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(
        _event(attributes={"trail_name": "production-audit"})
    )

    assert signal is not None
    assert signal.reason == (
        "Successful StopLogging action was observed for trail production-audit."
    )


def test_reason_remains_useful_without_trail_name() -> None:
    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(_event())

    assert signal is not None
    assert signal.reason == "Successful StopLogging action was observed."


def test_engine_runs_multiple_rules_and_returns_only_matches() -> None:
    engine = DetectionEngine(
        [
            _NeverMatchRule(),
            SuccessfulCloudTrailStopLoggingRule(),
        ]
    )

    signals = engine.evaluate(_event())

    assert len(signals) == 1
    assert signals[0].rule_id == "aws.cloudtrail.logging_stopped"


def test_engine_returns_empty_tuple_when_no_rules_match() -> None:
    engine = DetectionEngine([SuccessfulCloudTrailStopLoggingRule()])

    assert engine.evaluate(_event(action="StartLogging")) == ()


def test_rule_uses_normalized_fields_instead_of_raw_event() -> None:
    event = _event(
        attributes={"trail_name": "normalized-trail"},
        raw_event={
            "eventSource": "different.amazonaws.com",
            "eventName": "DeleteTrail",
            "errorCode": "AccessDenied",
        },
    )

    signal = SuccessfulCloudTrailStopLoggingRule().evaluate(event)

    assert signal is not None
    assert "normalized-trail" in signal.reason


@dataclass(frozen=True, slots=True)
class _NeverMatchRule:
    rule_id: ClassVar[str] = "test.never_matches"
    title: ClassVar[str] = "Never matches"
    description: ClassVar[str] = "Test rule that does not produce signals."
    severity: ClassVar[SignalSeverity] = SignalSeverity.LOW

    def evaluate(self, event: NormalizedEvent) -> None:
        del event
