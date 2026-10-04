"""Durable history of successfully produced signals for cross-run correlation.

Signals produced by one analysis run can participate in correlations formed
by later runs. History rows are written only after the producing run's
incidents persist successfully; a run that fails earlier stores nothing, so
retries reprocess cleanly. Rows are keyed by stable signal identity and never
rewritten: the first historical representation wins, which keeps
deterministic correlation evidence stable across retries.
"""

from collections.abc import Collection
from datetime import datetime
from typing import Protocol

from trailweaver.correlation import ActorCorrelationKey, actor_correlation_key
from trailweaver.signals import Signal


class SignalHistoryError(RuntimeError):
    """Raised when durable signal history storage is unavailable."""


class InvalidStoredSignalError(SignalHistoryError):
    """Raised when stored signal history cannot be reconstructed."""


class SignalHistoryRepository(Protocol):
    """Durable successfully-produced signals for cross-run correlation."""

    def store_signals(self, signals: Collection[Signal]) -> None:
        """Idempotently store identified signals for future correlation."""

    def candidate_signals(
        self,
        *,
        actors: Collection[ActorCorrelationKey],
        start: datetime,
        end: datetime,
    ) -> tuple[Signal, ...]:
        """Return historical signals in range for the given actor keys."""


class InMemorySignalHistory:
    """Process-local signal history with the same semantics as durable storage."""

    def __init__(self) -> None:
        self._signals: dict[tuple[str, str, str], Signal] = {}

    def store_signals(self, signals: Collection[Signal]) -> None:
        """Keep the first stored representation of each logical signal."""

        for signal in signals:
            key = _signal_identity_key(signal)
            if key is not None and key not in self._signals:
                self._signals[key] = signal

    def candidate_signals(
        self,
        *,
        actors: Collection[ActorCorrelationKey],
        start: datetime,
        end: datetime,
    ) -> tuple[Signal, ...]:
        """Return stored signals matching an actor key inside the time range."""

        wanted = set(actors)
        ordered = sorted(
            (
                (signal.source_event.timestamp, signal.signal_id, signal)
                for signal in self._signals.values()
                if _actor_key_of(signal) in wanted
                and start <= signal.source_event.timestamp <= end
            ),
            key=lambda item: (item[0], item[1]),
        )
        return tuple(signal for _, _, signal in ordered)

    def clear(self) -> None:
        """Remove all stored signals.

        Demo replay support only: no production endpoint exposes this, and
        production workspace clearing deliberately preserves history.
        """

        self._signals.clear()


def _signal_identity_key(signal: Signal) -> tuple[str, str, str] | None:
    """Return the logical identity, or None when the signal has no event ID."""

    event = signal.source_event
    if (
        event.event_id is None
        or not event.event_id.strip()
        or not event.provider
        or not event.provider.strip()
    ):
        return None
    return (event.provider, event.event_id, signal.rule_id)


def _actor_key_of(signal: Signal) -> ActorCorrelationKey | None:
    """Return the correlation actor key of a stored signal, if any."""

    return actor_correlation_key(signal.source_event)
