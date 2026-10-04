"""Focused tests for durable standalone signal history (M32).

Signal history preserves successfully produced signals so later runs can
correlate them with fresh evidence. Rows are keyed by stable logical
identity and never rewritten; the first stored representation wins.
"""

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from trailweaver.api.execution import create_default_investigation_runner
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import (
    InvalidStoredSignalError,
    SQLiteIncidentRepository,
)
from trailweaver.correlation import correlation_evidence_key
from trailweaver.models import NormalizedEvent
from trailweaver.signal_history import InMemorySignalHistory, SignalHistoryError
from trailweaver.signals import Signal, SignalSeverity

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"

STARTED = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)


def _attack_records() -> list[dict[str, Any]]:
    return json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))["Records"]


def test_evidence_key_is_deterministic_and_member_order_independent() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    assert len(result.signals) == 3

    forward = correlation_evidence_key("rule", result.signals)
    backward = correlation_evidence_key("rule", tuple(reversed(result.signals)))

    assert forward == backward
    decoded = json.loads(forward)
    assert decoded[0] == "rule"
    assert decoded[1] == sorted(decoded[1])
    assert all(len(member) == 4 and member[0] == "event" for member in decoded[1])


def test_evidence_key_distinguishes_rules_and_members() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)

    same_rule = correlation_evidence_key("rule", result.signals)
    other_rule = correlation_evidence_key("other", result.signals)
    subset = correlation_evidence_key("rule", result.signals[:2])

    assert same_rule != other_rule
    assert same_rule != subset


def test_evidence_key_survives_delimiter_containing_strings() -> None:
    event_id = 'a|b,c"d\\e:aws'
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)
    document = json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))
    document["Records"][0]["eventID"] = event_id
    result = runner.run_cloudtrail_json(json.dumps(document))

    key = correlation_evidence_key("rule", result.signals)
    decoded = json.loads(key)

    assert decoded[0] == "rule"
    assert ["event", "aws", event_id, "aws.iam.admin_policy_attached_to_user"] in (
        decoded[1]
    )


def test_evidence_key_uses_signal_id_fallback_for_unidentified_signals() -> None:
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)
    document = json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))
    for record in document["Records"]:
        del record["eventID"]
    result = runner.run_cloudtrail_json(json.dumps(document))

    key = correlation_evidence_key("rule", result.signals)
    decoded = json.loads(key)

    assert decoded[0] == "rule"
    assert len(decoded[1]) == 3
    assert all(member[0] == "signal_id" and len(member) == 2 for member in decoded[1])
    assert {member[1] for member in decoded[1]} == {
        signal.signal_id for signal in result.signals
    }


def test_in_memory_history_keeps_first_representation_and_matches_bounds() -> None:
    history = InMemorySignalHistory()
    repository = InMemoryIncidentRepository()
    runner = create_default_investigation_runner(repository)
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    history.store_signals(result.signals)
    history.store_signals(result.signals)

    actor = ("aws", "111122223333", "arn", "arn:aws:iam::111122223333:user/developer")
    found = history.candidate_signals(
        actors={actor},
        start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
    )

    assert [signal.signal_id for signal in found] == [
        signal.signal_id for signal in result.signals
    ]
    assert history.candidate_signals(
        actors={actor},
        start=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, 0, tzinfo=UTC),
    ) == ()
    assert history.candidate_signals(
        actors={("aws", "999999999999", "arn", "arn:aws:iam::999999999999:user/other")},
        start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
    ) == ()
    assert history.candidate_signals(actors=set(), start=STARTED, end=STARTED) == ()


def test_in_memory_history_skips_unidentified_signals() -> None:
    history = InMemorySignalHistory()
    event = NormalizedEvent(
        timestamp=STARTED,
        provider="aws",
        service="iam",
        action="CreateAccessKey",
        event_id=None,
        region="us-east-1",
        raw_event={},
    )
    signal = Signal(
        rule_id="aws.iam.access_key_created",
        title="IAM access key created",
        description="A new IAM access key was created.",
        severity=SignalSeverity.MEDIUM,
        source_event=event,
        reason="A new IAM access key was created.",
    )

    history.store_signals([signal])

    assert history._signals == {}


def test_sqlite_history_round_trip_preserves_full_signal_without_raw_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "history.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    result = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    expected = {signal.signal_id: signal for signal in result.signals}

    reopened = SQLiteIncidentRepository(database)
    actor = ("aws", "111122223333", "arn", "arn:aws:iam::111122223333:user/developer")
    loaded = reopened.candidate_signals(
        actors={actor},
        start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
    )

    assert {signal.signal_id for signal in loaded} == set(expected)
    for signal in loaded:
        original = expected[signal.signal_id]
        assert signal.source_event.raw_event == {}
        assert replace(
            signal, source_event=replace(signal.source_event, raw_event={})
        ) == replace(
            original, source_event=replace(original.source_event, raw_event={})
        )


def test_sqlite_history_rejects_retry_uuid_copies(tmp_path: Path) -> None:
    database = tmp_path / "stable.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    first = runner.run_cloudtrail_file(ATTACK_FIXTURE)
    repeat = tuple(
        Signal(
            rule_id=signal.rule_id,
            title=signal.title,
            description=signal.description,
            severity=signal.severity,
            source_event=signal.source_event,
            reason=signal.reason,
        )
        for signal in first.signals
    )
    repository.store_signals(repeat)

    actor = ("aws", "111122223333", "arn", "arn:aws:iam::111122223333:user/developer")
    loaded = repository.candidate_signals(
        actors={actor},
        start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
    )

    assert [signal.signal_id for signal in loaded] == [
        signal.signal_id for signal in first.signals
    ]


def test_corrupt_history_row_fails_instead_of_partial_data(
    tmp_path: Path,
) -> None:
    from trailweaver.api.sqlite_repository import InvalidStoredSignalError as _Invalid

    assert _Invalid is not None
    database = tmp_path / "corrupt.sqlite3"
    repository = SQLiteIncidentRepository(database)
    runner = create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )
    runner.run_cloudtrail_file(ATTACK_FIXTURE)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE signal_history SET severity = 'bogus' WHERE rule_id LIKE 'aws.auth.%'"
        )
        connection.commit()

    actor = ("aws", "111122223333", "arn", "arn:aws:iam::111122223333:user/developer")
    with pytest.raises(InvalidStoredSignalError):
        repository.candidate_signals(
            actors={actor},
            start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
            end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
        )


def test_history_storage_failure_surfaces_sanitized_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "unavailable.sqlite3")
    runner = create_default_investigation_runner(InMemoryIncidentRepository())
    signals = runner.run_cloudtrail_file(ATTACK_FIXTURE).signals
    assert len(signals) == 3

    def _unavailable(*args: object, **kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("storage unavailable for this test")

    monkeypatch.setattr(sqlite3, "connect", _unavailable)
    with pytest.raises(SignalHistoryError, match="Unable to store signal history"):
        repository.store_signals(signals)
    with pytest.raises(SignalHistoryError, match="Unable to load signal history"):
        repository.candidate_signals(
            actors={
                (
                    "aws",
                    "111122223333",
                    "arn",
                    "arn:aws:iam::111122223333:user/developer",
                )
            },
            start=datetime(2026, 9, 23, 9, 0, tzinfo=UTC),
            end=datetime(2026, 9, 23, 11, 0, tzinfo=UTC),
        )
