"""SQLite-backed incident persistence kept outside TrailWeaver's domain layer."""

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from trailweaver.api.service import IncidentAlreadyExistsError
from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.models import (
    Actor,
    EventOutcome,
    JsonObject,
    NormalizedEvent,
    Resource,
)
from trailweaver.signals import Signal, SignalSeverity

_SCHEMA_VERSION = 1


class IncidentRepositoryError(RuntimeError):
    """Raised when SQLite cannot store or read a valid incident repository."""


class InvalidStoredIncidentError(IncidentRepositoryError):
    """Raised when persisted evidence cannot be reconstructed as domain objects."""


class UnsupportedSchemaVersionError(IncidentRepositoryError):
    """Raised when a database uses an unsupported SQLite repository schema."""


class SQLiteIncidentRepository:
    """Persist incidents as explicit relational rows using one connection per call.

    Source-event ``raw_event`` payloads are intentionally not stored. The current
    incident analyses use normalized fields only, and M20 will define source-record
    ownership separately.
    """

    def __init__(self, database_path: str | Path) -> None:
        path = Path(database_path).expanduser()
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteIncidentRepository requires a persistent file path")
        self._database_path = path
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def list_incidents(self) -> tuple[Incident, ...]:
        """Return incidents in database insertion order."""

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN")
                rows = connection.execute(
                    "SELECT incident_id FROM incidents ORDER BY sequence"
                ).fetchall()
                incidents: list[Incident] = []
                for row in rows:
                    incident_id = row["incident_id"]
                    incident = self._load_incident(connection, incident_id)
                    if incident is None:
                        raise InvalidStoredIncidentError(
                            f"Persisted incident {incident_id!r} disappeared while listing"
                        )
                    incidents.append(incident)
                return tuple(incidents)
        except sqlite3.Error as error:
            raise IncidentRepositoryError("Unable to list persisted incidents") from error

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return an incident by exact ID, or ``None`` if it is absent."""

        try:
            with closing(self._connect()) as connection:
                return self._load_incident(connection, incident_id)
        except sqlite3.Error as error:
            raise IncidentRepositoryError("Unable to load persisted incident") from error

    def save_incident(self, incident: Incident) -> None:
        """Insert one incident; duplicate IDs are rejected rather than replaced."""

        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT 1 FROM incidents WHERE incident_id = ?",
                    (incident.incident_id,),
                ).fetchone()
                if existing is not None:
                    raise IncidentAlreadyExistsError(
                        f"Incident {incident.incident_id!r} already exists"
                    )
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, description, severity, summary, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        incident.title,
                        incident.description,
                        incident.severity.value,
                        incident.summary,
                        _datetime_to_storage(incident.created_at),
                    ),
                )
                match = incident.correlation_match
                connection.execute(
                    """
                    INSERT INTO correlation_matches (
                        incident_id, correlation_id, rule_id, title, description, reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        match.correlation_id,
                        match.rule_id,
                        match.title,
                        match.description,
                        match.reason,
                    ),
                )
                for position, signal in enumerate(match.signals):
                    event = signal.source_event
                    connection.execute(
                        """
                        INSERT INTO signals (
                            incident_id, position, signal_id, rule_id, title,
                            description, severity, reason, event_timestamp, provider,
                            service, action, event_id, outcome, error_code, error_message,
                            region, source_ip, actor_json, resources_json, attributes_json
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            incident.incident_id,
                            position,
                            signal.signal_id,
                            signal.rule_id,
                            signal.title,
                            signal.description,
                            signal.severity.value,
                            signal.reason,
                            _datetime_to_storage(event.timestamp),
                            event.provider,
                            event.service,
                            event.action,
                            event.event_id,
                            event.outcome.value,
                            event.error_code,
                            event.error_message,
                            event.region,
                            event.source_ip,
                            _actor_to_json(event.actor),
                            _resources_to_json(event.resources),
                            _json_to_storage(event.attributes),
                        ),
                    )
        except IncidentAlreadyExistsError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise IncidentRepositoryError("Unable to save incident") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize_schema(self) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version == _SCHEMA_VERSION:
                    connection.commit()
                    return
                if version != 0:
                    raise UnsupportedSchemaVersionError(
                        f"Unsupported SQLite incident schema version {version}; "
                        f"this application supports {_SCHEMA_VERSION}"
                    )

                existing_tables = connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
                if existing_tables:
                    raise UnsupportedSchemaVersionError(
                        "Database has unversioned tables; refusing to modify it"
                    )

                schema_statements = (
                    """CREATE TABLE incidents (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL UNIQUE,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )""",
                    """CREATE TABLE correlation_matches (
                        incident_id TEXT PRIMARY KEY
                            REFERENCES incidents(incident_id) ON DELETE CASCADE,
                        correlation_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        reason TEXT NOT NULL
                    )""",
                    """CREATE TABLE signals (
                        incident_id TEXT NOT NULL
                            REFERENCES correlation_matches(incident_id) ON DELETE CASCADE,
                        position INTEGER NOT NULL CHECK (position >= 0),
                        signal_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        event_timestamp TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        service TEXT NOT NULL,
                        action TEXT NOT NULL,
                        event_id TEXT,
                        outcome TEXT NOT NULL,
                        error_code TEXT,
                        error_message TEXT,
                        region TEXT,
                        source_ip TEXT,
                        actor_json TEXT,
                        resources_json TEXT NOT NULL,
                        attributes_json TEXT NOT NULL,
                        PRIMARY KEY (incident_id, position),
                        UNIQUE (incident_id, signal_id)
                    )""",
                )
                for statement in schema_statements:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                connection.commit()
        except UnsupportedSchemaVersionError:
            raise
        except sqlite3.Error as error:
            raise IncidentRepositoryError("Unable to initialize incident database") from error

    @staticmethod
    def _load_incident(connection: sqlite3.Connection, incident_id: str) -> Incident | None:
        incident_row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if incident_row is None:
            return None
        try:
            correlation_row = connection.execute(
                "SELECT * FROM correlation_matches WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if correlation_row is None:
                raise ValueError("correlation metadata is missing")
            signal_rows = connection.execute(
                "SELECT * FROM signals WHERE incident_id = ? ORDER BY position",
                (incident_id,),
            ).fetchall()
            if not signal_rows:
                raise ValueError("correlation evidence is missing")
            signals = tuple(_signal_from_row(row) for row in signal_rows)
            match = CorrelationMatch(
                correlation_id=_required_str(correlation_row["correlation_id"]),
                rule_id=_required_str(correlation_row["rule_id"]),
                title=_required_str(correlation_row["title"]),
                description=_required_str(correlation_row["description"]),
                reason=_required_str(correlation_row["reason"]),
                signals=signals,
            )
            return Incident(
                incident_id=_required_str(incident_row["incident_id"]),
                title=_required_str(incident_row["title"]),
                description=_required_str(incident_row["description"]),
                severity=SignalSeverity(_required_str(incident_row["severity"])),
                summary=_required_str(incident_row["summary"]),
                created_at=_datetime_from_storage(incident_row["created_at"]),
                correlation_match=match,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise InvalidStoredIncidentError(
                f"Persisted incident {incident_id!r} is invalid"
            ) from error


def _signal_from_row(row: sqlite3.Row) -> Signal:
    event = NormalizedEvent(
        timestamp=_datetime_from_storage(row["event_timestamp"]),
        provider=_required_str(row["provider"]),
        service=_required_str(row["service"]),
        action=_required_str(row["action"]),
        event_id=_optional_str(row["event_id"]),
        outcome=EventOutcome(_required_str(row["outcome"])),
        error_code=_optional_str(row["error_code"]),
        error_message=_optional_str(row["error_message"]),
        region=_optional_str(row["region"]),
        source_ip=_optional_str(row["source_ip"]),
        actor=_actor_from_json(row["actor_json"]),
        resources=_resources_from_json(row["resources_json"]),
        attributes=_object_from_json(row["attributes_json"]),
        raw_event={},
    )
    return Signal(
        signal_id=_required_str(row["signal_id"]),
        rule_id=_required_str(row["rule_id"]),
        title=_required_str(row["title"]),
        description=_required_str(row["description"]),
        severity=SignalSeverity(_required_str(row["severity"])),
        source_event=event,
        reason=_required_str(row["reason"]),
    )


def _datetime_to_storage(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Persisted timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _datetime_from_storage(value: object) -> datetime:
    timestamp = datetime.fromisoformat(_required_str(value))
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Persisted timestamp is not timezone-aware")
    return timestamp


def _actor_to_json(actor: Actor | None) -> str | None:
    if actor is None:
        return None
    return _json_to_storage(
        {
            "actor_type": actor.actor_type,
            "identifier": actor.identifier,
            "name": actor.name,
            "arn": actor.arn,
            "account_id": actor.account_id,
        }
    )


def _actor_from_json(value: object) -> Actor | None:
    if value is None:
        return None
    data = _object_from_json(value)
    expected = {"actor_type", "identifier", "name", "arn", "account_id"}
    if set(data) != expected:
        raise ValueError("Persisted actor fields are invalid")
    return Actor(**{key: _optional_str(data[key]) for key in expected})


def _resources_to_json(resources: tuple[Resource, ...]) -> str:
    return _json_to_storage(
        [
            {
                "resource_type": resource.resource_type,
                "identifier": resource.identifier,
                "arn": resource.arn,
                "account_id": resource.account_id,
                "region": resource.region,
            }
            for resource in resources
        ]
    )


def _resources_from_json(value: object) -> tuple[Resource, ...]:
    data = _decode_json(value)
    if not isinstance(data, list):
        raise TypeError("Persisted resources must be a list")
    expected = {"resource_type", "identifier", "arn", "account_id", "region"}
    resources: list[Resource] = []
    for item in data:
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("Persisted resource fields are invalid")
        resources.append(Resource(**{key: _optional_str(item[key]) for key in expected}))
    return tuple(resources)


def _json_to_storage(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _decode_json(value: object) -> object:
    if not isinstance(value, str):
        raise TypeError("Persisted JSON field is not text")
    return json.loads(value, parse_constant=_reject_json_constant)


def _object_from_json(value: object) -> JsonObject:
    data = _decode_json(value)
    if not isinstance(data, dict) or not all(isinstance(key, str) for key in data):
        raise ValueError("Persisted JSON field must be an object")
    return cast(JsonObject, data)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON numeric constant {value}")


def _required_str(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("Persisted required text field is invalid")
    return value


def _optional_str(value: object) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError("Persisted optional text field is invalid")
    return value
