"""Detection rule contract and stateless rule execution."""

from collections.abc import Iterable
from typing import Protocol

from trailweaver.models import NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity


class DetectionRule(Protocol):
    """A rule that may produce one signal from one normalized event."""

    rule_id: str
    title: str
    description: str
    severity: SignalSeverity

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal when the event matches this rule."""


class DetectionEngine:
    """Evaluate a fixed collection of rules without retaining event state."""

    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self._rules = tuple(rules)

    def evaluate(self, event: NormalizedEvent) -> tuple[Signal, ...]:
        """Return every signal generated for one event, in rule order."""

        signals: list[Signal] = []
        for rule in self._rules:
            signal = rule.evaluate(event)
            if signal is not None:
                signals.append(signal)
        return tuple(signals)

