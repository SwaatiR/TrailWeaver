"""Provider-neutral security signal models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from trailweaver.models import NormalizedEvent


class SignalSeverity(StrEnum):
    """The security importance assigned by a detection rule."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _generate_signal_id() -> str:
    return str(uuid4())


@dataclass(frozen=True, slots=True, kw_only=True)
class Signal:
    """A security-relevant finding produced from one normalized event."""

    rule_id: str
    title: str
    description: str
    severity: SignalSeverity
    source_event: NormalizedEvent
    reason: str
    signal_id: str = field(default_factory=_generate_signal_id)

    @property
    def timestamp(self) -> datetime:
        """Return the time of the activity that produced this signal."""

        return self.source_event.timestamp

