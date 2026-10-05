"""SQLite-backed incident persistence kept outside TrailWeaver's domain layer."""

import json
import sqlite3
from collections.abc import Collection
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from trailweaver.analysis_ledger import (
    AnalysisRunRepositoryError,
    DuplicateAnalysisRunError,
    InvalidAnalysisRunTransitionError,
    InvalidStoredAnalysisRunError,
    validate_completion_identity,
)
from trailweaver.analysis_runs import (
    AnalysisFailurePhase,
    AnalysisRun,
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceType,
)
from trailweaver.api.service import IncidentAlreadyExistsError, SaveIncidentOutcome
from trailweaver.correlation import (
    ActorCorrelationKey,
    CorrelationMatch,
    actor_correlation_key,
)
from trailweaver.event_ledger import (
    EventIdentity,
    EventLedgerError,
)
from trailweaver.incidents import Incident
from trailweaver.models import (
    Actor,
    EventOutcome,
    JsonObject,
    NormalizedEvent,
    Resource,
)
from trailweaver.provenance import (
    IncidentProvenance,
    ProvenanceObservation,
    build_incident_provenance,
)
from trailweaver.signal_history import InvalidStoredSignalError, SignalHistoryError
from trailweaver.signals import Signal, SignalSeverity

_SCHEMA_VERSION = 5

_SIGNAL_HISTORY_TABLE_SQL = """CREATE TABLE signal_history (
    signal_id TEXT PRIMARY KEY CHECK (length(trim(signal_id)) > 0),
    provider TEXT NOT NULL CHECK (length(trim(provider)) > 0),
    event_identity TEXT NOT NULL CHECK (length(trim(event_identity)) > 0),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    reason TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    service TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error_code TEXT,
    error_message TEXT,
    region TEXT,
    source_ip TEXT,
    actor_json TEXT,
    resources_json TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    actor_provider TEXT,
    actor_account_id TEXT,
    actor_id_type TEXT,
    actor_id_value TEXT,
    UNIQUE (provider, event_identity, rule_id)
)"""

_EMITTED_CORRELATIONS_TABLE_SQL = """CREATE TABLE emitted_correlations (
    correlation_key TEXT PRIMARY KEY CHECK (length(trim(correlation_key)) > 0),
    rule_id TEXT NOT NULL,
    emitted_at TEXT NOT NULL
)"""

_SIGNAL_HISTORY_INDEX_SQL = """CREATE INDEX idx_signal_history_actor_time
ON signal_history (
    actor_provider,
    actor_id_type,
    actor_id_value,
    event_timestamp
)"""

_EVENT_IDENTITY_CHUNK_SIZE = 500

_EVENTS_TABLE_SQL = """CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL CHECK (length(trim(provider)) > 0),
    event_identity TEXT NOT NULL CHECK (length(trim(event_identity)) > 0),
    first_seen_at TEXT NOT NULL CHECK (length(first_seen_at) > 0),
    UNIQUE (provider, event_identity)
)"""

_RUN_EVENTS_TABLE_SQL = """CREATE TABLE analysis_run_events (
    analysis_run_id TEXT NOT NULL
        REFERENCES analysis_runs(analysis_run_id)
        ON DELETE CASCADE,
    provider TEXT NOT NULL,
    event_identity TEXT NOT NULL,
    PRIMARY KEY (
        analysis_run_id,
        provider,
        event_identity
    ),
    FOREIGN KEY (
        provider,
        event_identity
    )
    REFERENCES events(provider, event_identity)
)"""

_ANALYSIS_RUNS_TABLE_SQL = """CREATE TABLE analysis_runs (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id TEXT NOT NULL UNIQUE CHECK (length(trim(analysis_run_id)) > 0),
    source_type TEXT NOT NULL CHECK (
        source_type IN ('local_file', 'web_upload', 's3_object', 'direct_input')
    ),
    source_label TEXT CHECK (
        source_label IS NULL OR (
            length(trim(source_label)) > 0 AND length(source_label) <= 256
        )
    ),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'interrupted')),
    started_at TEXT NOT NULL CHECK (length(started_at) > 0),
    finished_at TEXT,
    records_seen INTEGER NOT NULL CHECK (records_seen >= 0),
    records_accepted INTEGER NOT NULL CHECK (
        records_accepted >= 0 AND records_accepted <= records_seen
    ),
    signals_created INTEGER CHECK (signals_created >= 0),
    correlations_created INTEGER CHECK (correlations_created >= 0),
    incidents_created INTEGER CHECK (incidents_created >= 0),
    failure_phase TEXT CHECK (failure_phase IN (
        'event_ordering', 'detection', 'correlation',
        'incident_creation', 'incident_persistence'
    )),
    CHECK (finished_at IS NULL OR finished_at >= started_at),
    CHECK (
        (status = 'running' AND finished_at IS NULL
            AND signals_created IS NULL AND correlations_created IS NULL
            AND incidents_created IS NULL AND failure_phase IS NULL)
        OR
        (status = 'completed' AND finished_at IS NOT NULL
            AND signals_created IS NOT NULL AND correlations_created IS NOT NULL
            AND incidents_created IS NOT NULL AND failure_phase IS NULL)
        OR
        (status = 'failed' AND finished_at IS NOT NULL AND failure_phase IS NOT NULL
            AND (
                (failure_phase IN ('event_ordering', 'detection')
                    AND signals_created IS NULL AND correlations_created IS NULL
                    AND incidents_created IS NULL)
                OR (failure_phase = 'correlation' AND signals_created IS NOT NULL
                    AND correlations_created IS NULL AND incidents_created IS NULL)
                OR (failure_phase = 'incident_creation' AND signals_created IS NOT NULL
                    AND correlations_created IS NOT NULL AND incidents_created IS NULL)
                OR (failure_phase = 'incident_persistence'
                    AND signals_created IS NOT NULL AND correlations_created IS NOT NULL
                    AND incidents_created IS NOT NULL)
            ))
        OR
        (status = 'interrupted' AND finished_at IS NOT NULL
            AND signals_created IS NULL AND correlations_created IS NULL
            AND incidents_created IS NULL AND failure_phase IS NULL)
    )
)"""

_ANALYSIS_RUNS_NEW_TABLE_SQL = _ANALYSIS_RUNS_TABLE_SQL.replace(
    "CREATE TABLE analysis_runs (", "CREATE TABLE analysis_runs_new (", 1
)

_ANALYSIS_RUNS_COPY_COLUMNS = (
    "sequence, analysis_run_id, source_type, source_label, status, "
    "started_at, finished_at, records_seen, records_accepted, "
    "signals_created, correlations_created, incidents_created, failure_phase"
)


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

    def start_run(self, record: AnalysisRunRecord) -> None:
        """Durably insert one RUNNING lifecycle record before analysis starts."""

        if record.status is not AnalysisRunStatus.RUNNING:
            raise InvalidAnalysisRunTransitionError("start_run requires a RUNNING record")
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM analysis_runs WHERE analysis_run_id = ?",
                    (record.analysis_run_id,),
                ).fetchone() is not None:
                    raise DuplicateAnalysisRunError(
                        f"Analysis run {record.analysis_run_id!r} already exists"
                    )
                connection.execute(
                    """
                    INSERT INTO analysis_runs (
                        analysis_run_id, source_type, source_label, status,
                        started_at, finished_at, records_seen, records_accepted,
                        signals_created, correlations_created, incidents_created,
                        failure_phase
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    _record_to_storage(record),
                )
        except (DuplicateAnalysisRunError, InvalidAnalysisRunTransitionError):
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise AnalysisRunRepositoryError("Unable to start analysis run") from error

    def complete_run(self, run: AnalysisRun) -> None:
        """Atomically transition a compatible RUNNING row to COMPLETED."""

        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                current = self._load_run(connection, run.analysis_run_id)
                _require_running(current, run.analysis_run_id)
                assert current is not None
                validate_completion_identity(current, run)
                record = AnalysisRunRecord(
                    analysis_run_id=run.analysis_run_id,
                    source_type=run.source_type,
                    source_label=run.source_label,
                    status=AnalysisRunStatus.COMPLETED,
                    started_at=run.started_at,
                    finished_at=run.completed_at,
                    records_seen=run.records_seen,
                    records_accepted=run.records_accepted,
                    signals_created=run.signals_created,
                    correlations_created=run.correlations_created,
                    incidents_created=run.incidents_created,
                    failure_phase=None,
                )
                _update_run(connection, record)
        except InvalidAnalysisRunTransitionError:
            raise
        except InvalidStoredAnalysisRunError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise AnalysisRunRepositoryError("Unable to complete analysis run") from error

    def fail_run(
        self,
        analysis_run_id: str,
        *,
        failed_at: datetime,
        failure_phase: AnalysisFailurePhase,
        signals_created: int | None = None,
        correlations_created: int | None = None,
        incidents_created: int | None = None,
    ) -> None:
        """Atomically transition a RUNNING row to FAILED with typed stage data."""

        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                current = self._load_run(connection, analysis_run_id)
                _require_running(current, analysis_run_id)
                assert current is not None
                record = AnalysisRunRecord(
                    analysis_run_id=current.analysis_run_id,
                    source_type=current.source_type,
                    source_label=current.source_label,
                    status=AnalysisRunStatus.FAILED,
                    started_at=current.started_at,
                    finished_at=failed_at,
                    records_seen=current.records_seen,
                    records_accepted=current.records_accepted,
                    signals_created=signals_created,
                    correlations_created=correlations_created,
                    incidents_created=incidents_created,
                    failure_phase=failure_phase,
                )
                _update_run(connection, record)
        except InvalidAnalysisRunTransitionError:
            raise
        except InvalidStoredAnalysisRunError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise AnalysisRunRepositoryError("Unable to fail analysis run") from error

    def get_run(self, analysis_run_id: str) -> AnalysisRunRecord | None:
        """Return one durable lifecycle record by exact ID."""

        try:
            with closing(self._connect()) as connection:
                return self._load_run(connection, analysis_run_id)
        except InvalidStoredAnalysisRunError:
            raise
        except sqlite3.Error as error:
            raise AnalysisRunRepositoryError("Unable to load analysis run") from error

    def list_runs(self) -> tuple[AnalysisRunRecord, ...]:
        """Return durable lifecycle records in insertion order."""

        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT * FROM analysis_runs ORDER BY sequence"
                ).fetchall()
                return tuple(_run_from_row(row) for row in rows)
        except InvalidStoredAnalysisRunError:
            raise
        except sqlite3.Error as error:
            raise AnalysisRunRepositoryError("Unable to list analysis runs") from error

    def mark_running_runs_interrupted(self, *, interrupted_at: datetime) -> int:
        """Atomically classify every inherited RUNNING row as INTERRUPTED.

        All transitioned rows receive the same classification timestamp.
        Validation precedes any write: a timestamp predating any candidate
        start, a malformed candidate, or a row-count mismatch aborts the
        whole operation without changing a single row. Terminal rows are
        never modified, so a second invocation returns 0.
        """

        if interrupted_at.tzinfo is None or interrupted_at.utcoffset() is None:
            raise ValueError("interrupted_at must be timezone-aware")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    rows = connection.execute(
                        "SELECT * FROM analysis_runs "
                        "WHERE status = 'running' ORDER BY sequence"
                    ).fetchall()
                    candidates = [_run_from_row(row) for row in rows]
                    for candidate in candidates:
                        if interrupted_at < candidate.started_at:
                            raise InvalidAnalysisRunTransitionError(
                                "interrupted_at predates an inherited RUNNING analysis run"
                            )
                    stamp = _datetime_to_storage(interrupted_at)
                    cursor = connection.execute(
                        "UPDATE analysis_runs SET status = 'interrupted', "
                        "finished_at = ?, signals_created = NULL, "
                        "correlations_created = NULL, incidents_created = NULL, "
                        "failure_phase = NULL WHERE status = 'running'",
                        (stamp,),
                    )
                    if cursor.rowcount != len(candidates):
                        raise AnalysisRunRepositoryError(
                            "Unable to classify inherited analysis runs"
                        )
                    connection.commit()
                    return len(candidates)
                except Exception:
                    connection.rollback()
                    raise
        except (AnalysisRunRepositoryError, InvalidAnalysisRunTransitionError):
            raise
        except sqlite3.Error as error:
            raise AnalysisRunRepositoryError(
                "Unable to classify inherited analysis runs"
            ) from error

    def known_identities(
        self, identities: Collection[EventIdentity]
    ) -> frozenset[EventIdentity]:
        """Return the subset already acknowledged in persistent event history."""

        unique = tuple(dict.fromkeys(identities))
        if not unique:
            return frozenset()
        try:
            with closing(self._connect()) as connection:
                stored: list[tuple[object, object]] = []
                for offset in range(0, len(unique), _EVENT_IDENTITY_CHUNK_SIZE):
                    chunk = unique[offset : offset + _EVENT_IDENTITY_CHUNK_SIZE]
                    placeholders = ",".join(["(?, ?)"] * len(chunk))
                    parameters: list[str] = []
                    for identity in chunk:
                        parameters.extend((identity.provider, identity.event_id))
                    stored.extend(
                        (row["provider"], row["event_identity"])
                        for row in connection.execute(
                            "SELECT provider, event_identity FROM events "
                            f"WHERE (provider, event_identity) IN (VALUES {placeholders})",
                            parameters,
                        ).fetchall()
                    )
        except sqlite3.Error as error:
            raise EventLedgerError("Unable to check event identities") from error
        return frozenset(
            EventIdentity(provider=provider, event_id=event_id)
            for provider, event_id in stored
        )

    def acknowledge_run_events(
        self,
        *,
        analysis_run_id: str,
        finished_at: datetime,
        observed: Collection[EventIdentity],
    ) -> None:
        """Atomically record one completed run's observed event identities.

        Missing identities are inserted with the run's finish time; existing
        identities keep their original first-seen time; every observed
        identity gains its run association. The whole operation is one
        transaction, and repeated acknowledgement is a safe no-op.
        """

        if not analysis_run_id or not analysis_run_id.strip():
            raise ValueError("analysis_run_id must be non-empty")
        unique = tuple(dict.fromkeys(observed))
        if not unique:
            return
        finished = _datetime_to_storage(finished_at)
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT OR IGNORE INTO events "
                    "(provider, event_identity, first_seen_at) VALUES (?, ?, ?)",
                    [
                        (identity.provider, identity.event_id, finished)
                        for identity in unique
                    ],
                )
                connection.executemany(
                    "INSERT OR IGNORE INTO analysis_run_events "
                    "(analysis_run_id, provider, event_identity) VALUES (?, ?, ?)",
                    [
                        (analysis_run_id, identity.provider, identity.event_id)
                        for identity in unique
                    ],
                )
        except sqlite3.Error as error:
            raise EventLedgerError("Unable to acknowledge run events") from error

    def store_signals(self, signals: Collection[Signal]) -> None:
        """Idempotently store identified signals for future correlation.

        Only signals carrying a trustworthy event identity are recorded;
        the first stored representation wins and later copies are ignored,
        which keeps deterministic correlation evidence stable across
        retries. One transaction covers the whole batch.
        """

        rows = []
        for signal in signals:
            event = signal.source_event
            if (
                event.event_id is None
                or not event.event_id.strip()
                or not event.provider
                or not event.provider.strip()
            ):
                continue
            rows.append(_history_signal_to_storage(signal))
        if not rows:
            return
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    """
                    INSERT OR IGNORE INTO signal_history (
                        signal_id, provider, event_identity, rule_id,
                        severity, title, description, reason, event_timestamp,
                        service, action, outcome, error_code, error_message,
                        region, source_ip, actor_json, resources_json,
                        attributes_json, actor_provider, actor_account_id,
                        actor_id_type, actor_id_value
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    rows,
                )
        except sqlite3.Error as error:
            raise SignalHistoryError("Unable to store signal history") from error

    def candidate_signals(
        self,
        *,
        actors: Collection[ActorCorrelationKey],
        start: datetime,
        end: datetime,
    ) -> tuple[Signal, ...]:
        """Return historical signals in range for the given actor keys.

        Time bounds compare serialized event timestamps; actor account IDs
        use NULL-safe comparison so missing accounts match exactly.
        Results arrive ordered by event time, then signal ID.
        """

        keys = tuple(dict.fromkeys(actors))
        if not keys:
            return ()
        start_text = _datetime_to_storage(start)
        end_text = _datetime_to_storage(end)
        try:
            with closing(self._connect()) as connection:
                found: list[Signal] = []
                for key in keys:
                    rows = connection.execute(
                        """
                        SELECT * FROM signal_history
                        WHERE actor_provider = ?
                          AND actor_id_type = ?
                          AND actor_id_value = ?
                          AND actor_account_id IS ?
                          AND event_timestamp >= ?
                          AND event_timestamp <= ?
                        ORDER BY event_timestamp, signal_id
                        """,
                        (
                            key[0],
                            key[2],
                            key[3],
                            key[1],
                            start_text,
                            end_text,
                        ),
                    ).fetchall()
                    found.extend(_history_signal_from_row(row) for row in rows)
        except sqlite3.Error as error:
            raise SignalHistoryError("Unable to load signal history") from error
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise InvalidStoredSignalError(
                "Persisted signal history is invalid"
            ) from error
        found.sort(key=lambda signal: (signal.source_event.timestamp, signal.signal_id))
        return tuple(found)

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
                self._insert_incident(connection, incident)
        except IncidentAlreadyExistsError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise IncidentRepositoryError("Unable to save incident") from error

    def save_incident_if_correlation_new(
        self, incident: Incident, correlation_key: str
    ) -> SaveIncidentOutcome:
        """Persist an incident with its correlation identity, at most once.

        The tombstone insert and the incident, match, and child-signal
        inserts share one transaction: a duplicate key rolls everything back
        and reports ALREADY_EMITTED, while any other failure rolls back a
        partially written incident. There is no committed intermediate state.
        """

        if not correlation_key or not correlation_key.strip():
            raise ValueError("correlation_key must be non-empty")
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        INSERT INTO emitted_correlations (
                            correlation_key, rule_id, emitted_at
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            correlation_key,
                            incident.correlation_match.rule_id,
                            _datetime_to_storage(incident.created_at),
                        ),
                    )
                except sqlite3.IntegrityError:
                    return SaveIncidentOutcome.ALREADY_EMITTED
                self._insert_incident(connection, incident)
        except IncidentAlreadyExistsError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise IncidentRepositoryError("Unable to save incident") from error
        return SaveIncidentOutcome.CREATED

    @staticmethod
    def _insert_incident(
        connection: sqlite3.Connection, incident: Incident
    ) -> None:
        """Insert incident, match, and child-signal rows on one connection."""

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

    def clear_incidents(self) -> None:
        """Remove every persisted incident and its related rows atomically.

        Deleting from ``incidents`` cascades to ``correlation_matches`` and
        ``signals`` through the schema's foreign keys, so no orphaned rows
        can remain. The database file, schema version, and sequence metadata
        are left untouched; the single statement runs in one transaction, so
        a failure cannot leave a partial deletion behind.
        """

        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM incidents")
        except sqlite3.Error as error:
            raise IncidentRepositoryError(
                "Unable to clear persisted incidents"
            ) from error

    def check_health(self) -> None:
        """Verify SQLite connectivity and schema version without loading evidence."""

        try:
            with closing(self._connect()) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version != _SCHEMA_VERSION:
                    raise UnsupportedSchemaVersionError(
                        f"Unsupported SQLite incident schema version {version}; "
                        f"this application supports {_SCHEMA_VERSION}"
                    )
                connection.execute("SELECT 1").fetchone()
        except UnsupportedSchemaVersionError:
            raise
        except sqlite3.Error as error:
            raise IncidentRepositoryError(
                "Incident repository readiness check failed"
            ) from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize_schema(self) -> None:
        try:
            with closing(self._connect()) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version == _SCHEMA_VERSION:
                    return
                if version not in {0, 1, 2, 3, 4}:
                    raise UnsupportedSchemaVersionError(
                        f"Unsupported SQLite incident schema version {version}; "
                        f"this application supports {_SCHEMA_VERSION}"
                    )
                if version in {2, 3, 4}:
                    # The v5 analysis_runs CHECK cannot be altered in place.
                    # Disable FK enforcement before opening the migration
                    # transaction so the parent rebuild uses legacy rename
                    # behavior (dependent analysis_run_events keeps resolving
                    # the parent by name). The pragma is per-connection and
                    # dies with this migration-only connection.
                    connection.execute("PRAGMA foreign_keys = OFF")
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    if version == 0:
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
                    if version in {0, 1}:
                        connection.execute(_ANALYSIS_RUNS_TABLE_SQL)
                    if version in {0, 1, 2}:
                        connection.execute(_EVENTS_TABLE_SQL)
                        connection.execute(_RUN_EVENTS_TABLE_SQL)
                    if version in {2, 3, 4}:
                        _migrate_analysis_runs_to_v5(connection)
                    if version in {0, 1, 2, 3}:
                        connection.execute(_SIGNAL_HISTORY_TABLE_SQL)
                        connection.execute(_EMITTED_CORRELATIONS_TABLE_SQL)
                        connection.execute(_SIGNAL_HISTORY_INDEX_SQL)
                    violations = connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                    if violations:
                        raise IncidentRepositoryError(
                            "Incident database foreign-key integrity check failed"
                        )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except UnsupportedSchemaVersionError:
            raise
        except IncidentRepositoryError:
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

    @staticmethod
    def _load_run(
        connection: sqlite3.Connection, analysis_run_id: str
    ) -> AnalysisRunRecord | None:
        row = connection.execute(
            "SELECT * FROM analysis_runs WHERE analysis_run_id = ?",
            (analysis_run_id,),
        ).fetchone()
        return None if row is None else _run_from_row(row)

    def get_incident_provenance(
        self, incident_id: str
    ) -> IncidentProvenance | None:
        """Return recorded observation provenance for one incident's evidence.

        The incident itself is reconstructed with the existing loader; all
        observation facts and run records come from ONE set-based query
        scoped to ``incident_id`` that walks persisted signal positions
        through the durable event/run associations. Signals without a
        provider event ID survive the ``LEFT JOIN``s with empty history.
        Returns None only when the incident itself is absent; an existing
        incident without recorded history still yields a complete
        response. ``signal_history`` is never consulted.
        """

        try:
            with closing(self._connect()) as connection:
                incident = self._load_incident(connection, incident_id)
                if incident is None:
                    return None
                rows = connection.execute(
                    """
                    SELECT s.position AS position,
                           s.provider AS provider,
                           s.event_id AS event_id,
                           e.first_seen_at AS first_seen_at,
                           ar.analysis_run_id AS analysis_run_id,
                           ar.source_type AS source_type,
                           ar.source_label AS source_label,
                           ar.status AS status,
                           ar.started_at AS started_at,
                           ar.finished_at AS finished_at,
                           ar.records_seen AS records_seen,
                           ar.records_accepted AS records_accepted,
                           ar.signals_created AS signals_created,
                           ar.correlations_created AS correlations_created,
                           ar.incidents_created AS incidents_created,
                           ar.failure_phase AS failure_phase,
                           ar.sequence AS run_sequence
                    FROM signals AS s
                    LEFT JOIN events AS e
                      ON e.provider = s.provider
                     AND e.event_identity = s.event_id
                    LEFT JOIN analysis_run_events AS are
                      ON are.provider = s.provider
                     AND are.event_identity = s.event_id
                    LEFT JOIN analysis_runs AS ar
                      ON ar.analysis_run_id = are.analysis_run_id
                    WHERE s.incident_id = ?
                    ORDER BY s.position, ar.started_at, ar.sequence
                    """,
                    (incident_id,),
                ).fetchall()
                grouped: dict[tuple[str, str], set[str]] = {}
                first_seen: dict[tuple[str, str], str] = {}
                run_records: dict[str, AnalysisRunRecord] = {}
                run_sequence: dict[str, int] = {}
                for row in rows:
                    event_id = _optional_str(row["event_id"])
                    if event_id is None:
                        continue
                    key = (_required_str(row["provider"]), event_id)
                    if row["first_seen_at"] is not None and key not in first_seen:
                        first_seen[key] = _required_str(row["first_seen_at"])
                    run_id = _optional_str(row["analysis_run_id"])
                    if run_id is None:
                        continue
                    grouped.setdefault(key, set()).add(run_id)
                    if run_id not in run_records:
                        run_records[run_id] = _run_from_row(row)
                        sequence_value = row["run_sequence"]
                        if not isinstance(sequence_value, int):
                            raise TypeError(
                                "Persisted analysis-run sequence is invalid"
                            )
                        run_sequence[run_id] = sequence_value
                observations: dict[
                    tuple[str, str], ProvenanceObservation
                ] = {}
                for key in first_seen.keys() | grouped.keys():
                    first_seen_text = first_seen.get(key)
                    observations[key] = ProvenanceObservation(
                        first_recorded_at=(
                            None
                            if first_seen_text is None
                            else _datetime_from_storage(first_seen_text)
                        ),
                        run_ids=tuple(sorted(grouped.get(key, ()))),
                    )
                return build_incident_provenance(
                    incident,
                    run_records=run_records,
                    observations=observations,
                    run_sequence=run_sequence,
                )
        except sqlite3.Error as error:
            raise IncidentRepositoryError(
                "Unable to load incident provenance"
            ) from error
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            InvalidStoredAnalysisRunError,
        ) as error:
            raise InvalidStoredIncidentError(
                f"Persisted provenance for incident {incident_id!r} is invalid"
            ) from error


def _migrate_analysis_runs_to_v5(connection: sqlite3.Connection) -> None:
    """Rebuild analysis_runs with the v5 CHECK constraints, preserving data.

    SQLite cannot alter CHECK constraints in place. The caller disables FK
    enforcement before the migration transaction, so the dependent
    analysis_run_events table (which references the parent by name) needs
    no rebuild of its own. Every row and explicit ``sequence`` value is
    copied; the AUTOINCREMENT counter follows the preserved maximum.
    """

    connection.execute(_ANALYSIS_RUNS_NEW_TABLE_SQL)
    before = connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0]
    connection.execute(
        f"INSERT INTO analysis_runs_new ({_ANALYSIS_RUNS_COPY_COLUMNS}) "
        f"SELECT {_ANALYSIS_RUNS_COPY_COLUMNS} FROM analysis_runs ORDER BY sequence"
    )
    after = connection.execute("SELECT COUNT(*) FROM analysis_runs_new").fetchone()[0]
    if before != after:
        raise IncidentRepositoryError(
            "Incident database migration did not preserve analysis runs"
        )
    connection.execute("DROP TABLE analysis_runs")
    connection.execute("ALTER TABLE analysis_runs_new RENAME TO analysis_runs")


def _require_running(
    record: AnalysisRunRecord | None, analysis_run_id: str
) -> None:
    if record is None:
        raise InvalidAnalysisRunTransitionError(
            f"Analysis run {analysis_run_id!r} does not exist"
        )
    if record.status is not AnalysisRunStatus.RUNNING:
        raise InvalidAnalysisRunTransitionError(
            f"Analysis run {analysis_run_id!r} is already terminal"
        )


def _record_to_storage(record: AnalysisRunRecord) -> tuple[object, ...]:
    return (
        record.analysis_run_id,
        record.source_type.value,
        record.source_label,
        record.status.value,
        _datetime_to_storage(record.started_at),
        None if record.finished_at is None else _datetime_to_storage(record.finished_at),
        record.records_seen,
        record.records_accepted,
        record.signals_created,
        record.correlations_created,
        record.incidents_created,
        None if record.failure_phase is None else record.failure_phase.value,
    )


def _update_run(connection: sqlite3.Connection, record: AnalysisRunRecord) -> None:
    values = _record_to_storage(record)
    cursor = connection.execute(
        """
        UPDATE analysis_runs SET
            source_type = ?, source_label = ?, status = ?, started_at = ?,
            finished_at = ?, records_seen = ?, records_accepted = ?,
            signals_created = ?, correlations_created = ?, incidents_created = ?,
            failure_phase = ?
        WHERE analysis_run_id = ? AND status = 'running'
        """,
        (*values[1:], values[0]),
    )
    if cursor.rowcount != 1:
        raise InvalidAnalysisRunTransitionError(
            f"Analysis run {record.analysis_run_id!r} is not RUNNING"
        )


def _run_from_row(row: sqlite3.Row) -> AnalysisRunRecord:
    try:
        return AnalysisRunRecord(
            analysis_run_id=_required_str(row["analysis_run_id"]),
            source_type=AnalysisSourceType(_required_str(row["source_type"])),
            source_label=_optional_str(row["source_label"]),
            status=AnalysisRunStatus(_required_str(row["status"])),
            started_at=_datetime_from_storage(row["started_at"]),
            finished_at=(
                None
                if row["finished_at"] is None
                else _datetime_from_storage(row["finished_at"])
            ),
            records_seen=_required_int(row["records_seen"]),
            records_accepted=_required_int(row["records_accepted"]),
            signals_created=_optional_int(row["signals_created"]),
            correlations_created=_optional_int(row["correlations_created"]),
            incidents_created=_optional_int(row["incidents_created"]),
            failure_phase=(
                None
                if row["failure_phase"] is None
                else AnalysisFailurePhase(_required_str(row["failure_phase"]))
            ),
        )
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise InvalidStoredAnalysisRunError(
            "Persisted analysis-run data is invalid"
        ) from error


def _history_signal_to_storage(signal: Signal) -> tuple[object, ...]:
    """Serialize a history signal, including its actor query key columns."""

    event = signal.source_event
    actor_key = actor_correlation_key(event)
    return (
        signal.signal_id,
        event.provider,
        event.event_id,
        signal.rule_id,
        signal.severity.value,
        signal.title,
        signal.description,
        signal.reason,
        _datetime_to_storage(event.timestamp),
        event.service,
        event.action,
        event.outcome.value,
        event.error_code,
        event.error_message,
        event.region,
        event.source_ip,
        _actor_to_json(event.actor),
        _resources_to_json(event.resources),
        _json_to_storage(event.attributes),
        actor_key[0] if actor_key is not None else None,
        actor_key[1] if actor_key is not None else None,
        actor_key[2] if actor_key is not None else None,
        actor_key[3] if actor_key is not None else None,
    )


def _history_signal_from_row(row: sqlite3.Row) -> Signal:
    """Rebuild a history signal with the same mapping as incident signals.

    The event identity column substitutes for the incident table's event ID
    column; every other field shares conversion behavior, including the
    empty ``raw_event`` that incident reloads already use.
    """

    event = NormalizedEvent(
        timestamp=_datetime_from_storage(row["event_timestamp"]),
        provider=_required_str(row["provider"]),
        service=_required_str(row["service"]),
        action=_required_str(row["action"]),
        event_id=_required_str(row["event_identity"]),
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


def _required_int(value: object) -> int:
    if not isinstance(value, int):
        raise TypeError("Persisted required integer field is invalid")
    return value


def _optional_int(value: object) -> int | None:
    if value is not None and not isinstance(value, int):
        raise TypeError("Persisted optional integer field is invalid")
    return value
