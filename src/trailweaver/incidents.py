"""Provider-neutral incident models and explicit incident creation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from trailweaver.correlation import CorrelationMatch
from trailweaver.models import Actor
from trailweaver.signals import SignalSeverity

_AWS_ACCOUNT_COMPROMISE_SEQUENCE = "aws.identity.possible_account_compromise_sequence"


def _generate_incident_id() -> str:
    return str(uuid4())


def _current_time() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, kw_only=True)
class TimelineEntry:
    """A concise view of one signal in an incident timeline."""

    signal_id: str
    timestamp: datetime
    rule_id: str
    title: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Incident:
    """An investigation object created from one correlation match."""

    title: str
    description: str
    severity: SignalSeverity
    correlation_match: CorrelationMatch
    summary: str
    created_at: datetime = field(default_factory=_current_time)
    incident_id: str = field(default_factory=_generate_incident_id)

    @property
    def started_at(self) -> datetime:
        """Return the start of the correlated activity."""

        return self.correlation_match.started_at

    @property
    def ended_at(self) -> datetime:
        """Return the end of the correlated activity."""

        return self.correlation_match.ended_at

    @property
    def timeline(self) -> tuple[TimelineEntry, ...]:
        """Return chronological signal metadata without copying raw evidence."""

        return tuple(
            TimelineEntry(
                signal_id=signal.signal_id,
                timestamp=signal.timestamp,
                rule_id=signal.rule_id,
                title=signal.title,
                reason=signal.reason,
            )
            for signal in self.correlation_match.signals
        )

    @property
    def primary_actor(self) -> Actor | None:
        """Return the first normalized actor represented in the correlation."""

        for signal in self.correlation_match.signals:
            if signal.source_event.actor is not None:
                return signal.source_event.actor
        return None


class UnsupportedCorrelationRuleError(ValueError):
    """Raised when no incident definition exists for a correlation rule."""


class IncidentFactory:
    """Create incidents from explicitly supported correlation rules."""

    def create(
        self,
        correlation_match: CorrelationMatch,
        *,
        incident_id: str | None = None,
        created_at: datetime | None = None,
    ) -> Incident:
        """Convert one supported correlation match into an incident."""

        if correlation_match.rule_id != _AWS_ACCOUNT_COMPROMISE_SEQUENCE:
            raise UnsupportedCorrelationRuleError(
                f"Unsupported correlation rule: {correlation_match.rule_id}"
            )

        return Incident(
            incident_id=(
                _generate_incident_id() if incident_id is None else incident_id
            ),
            title="Possible AWS account compromise",
            description=(
                "Multiple related AWS identity-security events were observed for the "
                "same actor within a short period."
            ),
            severity=SignalSeverity.HIGH,
            created_at=_current_time() if created_at is None else created_at,
            correlation_match=correlation_match,
            summary=(
                "Possible account compromise activity: a console login without MFA "
                "was followed by access-key creation and administrator privilege "
                "assignment for the same actor."
            ),
        )
