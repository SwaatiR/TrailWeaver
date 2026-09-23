"""Provider-neutral correlation models and stateless rule execution."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, TypeAlias
from uuid import uuid4

from trailweaver.models import NormalizedEvent
from trailweaver.signals import Signal

ActorCorrelationKey: TypeAlias = tuple[str, str | None, str, str]


def actor_correlation_key(event: NormalizedEvent) -> ActorCorrelationKey | None:
    """Return a namespaced key for the event actor's best stable identity.

    Actor ARN is preferred, followed by identifier and then name. Provider and
    account context are included so identities from separate namespaces do not
    collide. Raw event evidence is deliberately not consulted.
    """

    actor = event.actor
    if actor is None:
        return None

    identities = (
        ("arn", actor.arn),
        ("identifier", actor.identifier),
        ("name", actor.name),
    )
    for identity_type, identity_value in identities:
        if identity_value is not None and identity_value.strip():
            return (
                event.provider,
                actor.account_id,
                identity_type,
                identity_value,
            )
    return None


def _generate_correlation_id() -> str:
    return str(uuid4())


@dataclass(frozen=True, slots=True, kw_only=True)
class CorrelationMatch:
    """A chronological group of signals matched by one correlation rule."""

    rule_id: str
    title: str
    description: str
    reason: str
    signals: tuple[Signal, ...]
    correlation_id: str = field(default_factory=_generate_correlation_id)

    def __post_init__(self) -> None:
        if not self.signals:
            raise ValueError("A correlation match requires at least one signal")
        if any(
            earlier.timestamp > later.timestamp
            for earlier, later in zip(self.signals, self.signals[1:], strict=False)
        ):
            raise ValueError("Correlation match signals must be chronological")

    @property
    def started_at(self) -> datetime:
        """Return the timestamp of the first signal in the match."""

        return self.signals[0].timestamp

    @property
    def ended_at(self) -> datetime:
        """Return the timestamp of the last signal in the match."""

        return self.signals[-1].timestamp


class CorrelationRule(Protocol):
    """A rule that may relate multiple signals into correlation matches."""

    rule_id: str
    title: str
    description: str

    def evaluate(self, signals: Collection[Signal]) -> tuple[CorrelationMatch, ...]:
        """Return matches found in the supplied signal collection."""


class CorrelationEngine:
    """Evaluate a fixed collection of rules without retaining signal history."""

    def __init__(self, rules: Iterable[CorrelationRule]) -> None:
        self._rules = tuple(rules)

    def evaluate(self, signals: Iterable[Signal]) -> tuple[CorrelationMatch, ...]:
        """Return all matches generated for one signal batch, in rule order."""

        signal_batch = tuple(signals)
        matches: list[CorrelationMatch] = []
        for rule in self._rules:
            matches.extend(rule.evaluate(signal_batch))
        return tuple(matches)
