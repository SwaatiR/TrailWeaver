"""Persistent identity ledger for normalized CloudTrail events.

M31 provides sequential/replay idempotency: an event identity that was
successfully processed by a completed analysis run is recognized - but never
reprocessed - by later runs. Identity is the provider event ID only; events
without a trustworthy ID are always processed and never recorded, because
repeated work is preferable to silently suppressing evidence.

This module deliberately does NOT implement concurrent exactly-once
processing. Two genuinely concurrent runs may both observe an unknown event
before either acknowledges it and therefore both process it. Duplicate work
is acceptable; silent evidence suppression is not.
"""

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from trailweaver.models import NormalizedEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class EventIdentity:
    """The conservative durable identity of one normalized event.

    Only the provider and its own event ID participate. Timestamps, actors,
    regions, actions, and all other normalized content are deliberately
    excluded: none of them identifies an event, and hashing them could
    falsely merge distinct evidence.
    """

    provider: str
    event_id: str

    def __post_init__(self) -> None:
        if not self.provider or not self.provider.strip():
            raise ValueError("provider must be non-empty")
        if not self.event_id or not self.event_id.strip():
            raise ValueError("event_id must be non-empty")

    @classmethod
    def from_event(cls, event: NormalizedEvent) -> "EventIdentity | None":
        """Return the durable identity, or None when the event has none.

        Events without a non-blank provider event ID are always processed
        and never recorded; callers must not invent a synthetic identity.
        """

        if (
            event.event_id is None
            or not event.event_id.strip()
            or not event.provider
            or not event.provider.strip()
        ):
            return None
        return cls(provider=event.provider, event_id=event.event_id)


class EventLedgerRepository(Protocol):
    """Durable membership and observation provenance for event identities."""

    def known_identities(
        self, identities: Collection[EventIdentity]
    ) -> frozenset[EventIdentity]:
        """Return the subset already acknowledged in persistent event history."""

    def acknowledge_run_events(
        self,
        *,
        analysis_run_id: str,
        finished_at: datetime,
        observed: Collection[EventIdentity],
    ) -> None:
        """Atomically record one completed run's observed event identities.

        Missing identities are inserted; existing identities are preserved;
        an observation association is created for every observed identity.
        """


class EventLedgerError(RuntimeError):
    """Raised when durable event-identity storage is unavailable."""


class InMemoryEventLedger:
    """Process-local event ledger with the same semantics as durable storage."""

    def __init__(self) -> None:
        self._first_seen: dict[tuple[str, str], datetime] = {}
        self._associations: set[tuple[str, str, str]] = set()

    def known_identities(
        self, identities: Collection[EventIdentity]
    ) -> frozenset[EventIdentity]:
        """Return the identities already recorded by earlier acknowledgements."""

        return frozenset(
            identity
            for identity in identities
            if (identity.provider, identity.event_id) in self._first_seen
        )

    def acknowledge_run_events(
        self,
        *,
        analysis_run_id: str,
        finished_at: datetime,
        observed: Collection[EventIdentity],
    ) -> None:
        """Record observed identities idempotently for one completed run."""

        if not analysis_run_id or not analysis_run_id.strip():
            raise ValueError("analysis_run_id must be non-empty")
        if finished_at.tzinfo is None or finished_at.utcoffset() is None:
            raise ValueError("finished_at must be timezone-aware")
        for identity in dict.fromkeys(observed):
            key = (identity.provider, identity.event_id)
            if key not in self._first_seen:
                self._first_seen[key] = finished_at
            self._associations.add((analysis_run_id, identity.provider, identity.event_id))

    def clear(self) -> None:
        """Remove all recorded identities and associations.

        Demo replay support only: no production endpoint exposes this, and
        production workspace clearing deliberately preserves dedup history.
        """

        self._first_seen.clear()
        self._associations.clear()
