from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from trailweaver.correlation import (
    CorrelationEngine,
    CorrelationMatch,
    actor_correlation_key,
)
from trailweaver.models import Actor, JsonObject, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)


def _signal(*, timestamp: datetime, signal_id: str = "signal-1") -> Signal:
    return Signal(
        signal_id=signal_id,
        rule_id="test.signal",
        title="Test signal",
        description="A test signal.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=timestamp,
            provider="aws",
            service="test",
            action="TestAction",
            actor=Actor(
                arn="arn:aws:iam::123456789012:user/alice",
                account_id="123456789012",
            ),
            raw_event={},
        ),
        reason="A test signal was observed.",
    )


def test_correlation_match_derives_time_range_from_chronological_signals() -> None:
    first = _signal(timestamp=BASE_TIME, signal_id="first")
    last = _signal(timestamp=BASE_TIME + timedelta(minutes=4), signal_id="last")

    match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="test.correlation",
        title="Test correlation",
        description="A test correlation.",
        reason="Two test signals were related.",
        signals=(first, last),
    )

    assert match.correlation_id == "correlation-1"
    assert match.signals == (first, last)
    assert match.started_at == BASE_TIME
    assert match.ended_at == BASE_TIME + timedelta(minutes=4)


def test_correlation_match_rejects_non_chronological_signals() -> None:
    first = _signal(timestamp=BASE_TIME, signal_id="first")
    last = _signal(timestamp=BASE_TIME + timedelta(minutes=4), signal_id="last")

    with pytest.raises(ValueError, match="chronological"):
        CorrelationMatch(
            rule_id="test.correlation",
            title="Test correlation",
            description="A test correlation.",
            reason="Two test signals were related.",
            signals=(last, first),
        )


def test_actor_correlation_key_prefers_arn_and_includes_context() -> None:
    event = NormalizedEvent(
        timestamp=BASE_TIME,
        provider="aws",
        service="iam",
        action="TestAction",
        actor=Actor(
            arn="arn:aws:iam::123456789012:user/alice",
            identifier="AIDAEXAMPLE",
            name="alice",
            account_id="123456789012",
        ),
        raw_event={},
    )

    assert actor_correlation_key(event) == (
        "aws",
        "123456789012",
        "arn",
        "arn:aws:iam::123456789012:user/alice",
    )


def test_actor_correlation_key_falls_back_and_ignores_raw_event() -> None:
    raw_event: JsonObject = {
        "userIdentity": {"arn": "arn:aws:iam::999999999999:user/mallory"}
    }
    event = NormalizedEvent(
        timestamp=BASE_TIME,
        provider="aws",
        service="iam",
        action="TestAction",
        actor=Actor(identifier="AIDAEXAMPLE", name="alice"),
        raw_event=raw_event,
    )

    assert actor_correlation_key(event) == (
        "aws",
        None,
        "identifier",
        "AIDAEXAMPLE",
    )


def test_actor_correlation_key_requires_usable_identity() -> None:
    event = NormalizedEvent(
        timestamp=BASE_TIME,
        provider="aws",
        service="iam",
        action="TestAction",
        actor=Actor(account_id="123456789012"),
        raw_event={},
    )

    assert actor_correlation_key(event) is None


def test_correlation_engine_returns_matches_from_each_configured_rule() -> None:
    signal = _signal(timestamp=BASE_TIME)
    engine = CorrelationEngine([_StaticRule("first"), _StaticRule("second")])

    matches = engine.evaluate([signal])

    assert tuple(match.rule_id for match in matches) == ("first", "second")


@dataclass(frozen=True, slots=True)
class _StaticRule:
    rule_id: str
    title: ClassVar[str] = "Static rule"
    description: ClassVar[str] = "Always returns one match for a non-empty batch."

    def evaluate(self, signals: tuple[Signal, ...]) -> tuple[CorrelationMatch, ...]:
        if not signals:
            return ()
        return (
            CorrelationMatch(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                reason="The static test rule matched.",
                signals=(signals[0],),
            ),
        )
