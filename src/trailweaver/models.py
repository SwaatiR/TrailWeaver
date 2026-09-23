"""Provider-neutral models shared by TrailWeaver components."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
SecurityAttributes: TypeAlias = dict[str, JsonValue]


class EventOutcome(StrEnum):
    """The broad result of an event."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class Actor:
    """The identity responsible for an event."""

    actor_type: str | None = None
    identifier: str | None = None
    name: str | None = None
    arn: str | None = None
    account_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Resource:
    """A resource affected by an event."""

    resource_type: str | None = None
    identifier: str | None = None
    arn: str | None = None
    account_id: str | None = None
    region: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class NormalizedEvent:
    """A provider-neutral security event with its original evidence."""

    timestamp: datetime
    provider: str
    service: str
    action: str
    event_id: str | None = None
    outcome: EventOutcome = EventOutcome.UNKNOWN
    error_code: str | None = None
    error_message: str | None = None
    region: str | None = None
    source_ip: str | None = None
    actor: Actor | None = None
    resources: tuple[Resource, ...] = ()
    attributes: SecurityAttributes = field(default_factory=dict)
    raw_event: JsonObject
