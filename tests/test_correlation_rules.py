from datetime import UTC, datetime, timedelta

from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import (
    AWS_CORRELATION_RULES,
    AwsAccountCompromiseSequenceRule,
)
from trailweaver.models import Actor, JsonObject, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
USER_ADMIN = "aws.iam.admin_policy_attached_to_user"
ROLE_ADMIN = "aws.iam.admin_policy_attached_to_role"
DEFAULT_ACTOR = Actor(
    arn="arn:aws:iam::123456789012:user/alice",
    identifier="AIDAALICE",
    name="alice",
    account_id="123456789012",
)


def _signal(
    rule_id: str,
    *,
    minutes: int = 0,
    seconds: int = 0,
    actor: Actor | None = DEFAULT_ACTOR,
    raw_event: JsonObject | None = None,
    signal_id: str | None = None,
) -> Signal:
    timestamp = BASE_TIME + timedelta(minutes=minutes, seconds=seconds)
    return Signal(
        signal_id=signal_id or f"{rule_id}-{minutes}-{seconds}",
        rule_id=rule_id,
        title="Source signal",
        description="A source signal for correlation tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=timestamp,
            provider="aws",
            service="test",
            action="TestAction",
            actor=actor,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason="The source detection matched.",
    )


def _sequence(
    *,
    actor: Actor | None = DEFAULT_ACTOR,
    final_rule_id: str = USER_ADMIN,
    start_minute: int = 0,
) -> tuple[Signal, Signal, Signal]:
    return (
        _signal(LOGIN, minutes=start_minute, actor=actor),
        _signal(ACCESS_KEY, minutes=start_minute + 5, actor=actor),
        _signal(final_rule_id, minutes=start_minute + 10, actor=actor),
    )


def test_correct_three_stage_sequence_produces_one_match() -> None:
    signals = _sequence()

    matches = AwsAccountCompromiseSequenceRule().evaluate(signals)

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "aws.identity.possible_account_compromise_sequence"
    assert match.title == "Possible AWS account compromise sequence"
    assert match.signals == signals
    assert match.reason == (
        "A successful console login without MFA was followed by access-key creation "
        "and administrator privilege assignment for the same actor within 15 minutes."
    )


def test_user_policy_privilege_escalation_path_matches() -> None:
    matches = AwsAccountCompromiseSequenceRule().evaluate(
        _sequence(final_rule_id=USER_ADMIN)
    )

    assert len(matches) == 1
    assert matches[0].signals[-1].rule_id == USER_ADMIN


def test_role_policy_privilege_escalation_path_matches() -> None:
    matches = AwsAccountCompromiseSequenceRule().evaluate(
        _sequence(final_rule_id=ROLE_ADMIN)
    )

    assert len(matches) == 1
    assert matches[0].signals[-1].rule_id == ROLE_ADMIN


def test_wrong_chronological_order_does_not_match() -> None:
    signals = (
        _signal(USER_ADMIN, minutes=0),
        _signal(LOGIN, minutes=1),
        _signal(ACCESS_KEY, minutes=2),
    )

    assert AwsAccountCompromiseSequenceRule().evaluate(signals) == ()


def test_sequence_beyond_fifteen_minute_window_does_not_match() -> None:
    signals = (
        _signal(LOGIN),
        _signal(ACCESS_KEY, minutes=5),
        _signal(USER_ADMIN, minutes=15, seconds=1),
    )

    assert AwsAccountCompromiseSequenceRule().evaluate(signals) == ()


def test_sequence_at_fifteen_minute_boundary_matches() -> None:
    signals = (
        _signal(LOGIN),
        _signal(ACCESS_KEY, minutes=8),
        _signal(USER_ADMIN, minutes=15),
    )

    assert len(AwsAccountCompromiseSequenceRule().evaluate(signals)) == 1


def test_different_actors_do_not_correlate() -> None:
    bob = Actor(
        arn="arn:aws:iam::123456789012:user/bob",
        identifier="AIDABOB",
        account_id="123456789012",
    )
    signals = (
        _signal(LOGIN),
        _signal(ACCESS_KEY, minutes=5, actor=bob),
        _signal(USER_ADMIN, minutes=10),
    )

    assert AwsAccountCompromiseSequenceRule().evaluate(signals) == ()


def test_actor_matching_uses_arn_before_less_stable_fields() -> None:
    arn = "arn:aws:iam::123456789012:user/alice"
    actors = (
        Actor(arn=arn, identifier="first-id", name="first", account_id="123456789012"),
        Actor(arn=arn, identifier="second-id", name="second", account_id="123456789012"),
        Actor(arn=arn, identifier="third-id", name="third", account_id="123456789012"),
    )
    signals = (
        _signal(LOGIN, actor=actors[0]),
        _signal(ACCESS_KEY, minutes=5, actor=actors[1]),
        _signal(USER_ADMIN, minutes=10, actor=actors[2]),
    )

    assert len(AwsAccountCompromiseSequenceRule().evaluate(signals)) == 1


def test_actor_matching_falls_back_to_identifier_when_arn_is_absent() -> None:
    actors = (
        Actor(identifier="AIDAEXAMPLE", name="first", account_id="123456789012"),
        Actor(identifier="AIDAEXAMPLE", name="second", account_id="123456789012"),
        Actor(identifier="AIDAEXAMPLE", name="third", account_id="123456789012"),
    )
    signals = (
        _signal(LOGIN, actor=actors[0]),
        _signal(ACCESS_KEY, minutes=5, actor=actors[1]),
        _signal(USER_ADMIN, minutes=10, actor=actors[2]),
    )

    assert len(AwsAccountCompromiseSequenceRule().evaluate(signals)) == 1


def test_missing_usable_actor_identity_prevents_correlation() -> None:
    actor = Actor(account_id="123456789012")

    assert AwsAccountCompromiseSequenceRule().evaluate(_sequence(actor=actor)) == ()


def test_unrelated_signals_do_not_break_the_sequence() -> None:
    signals = (
        _signal(LOGIN),
        _signal("aws.cloudtrail.logging_stopped", minutes=2),
        _signal(ACCESS_KEY, minutes=5),
        _signal("example.unrelated", minutes=7),
        _signal(USER_ADMIN, minutes=10),
    )

    matches = AwsAccountCompromiseSequenceRule().evaluate(signals)

    assert len(matches) == 1
    assert tuple(signal.rule_id for signal in matches[0].signals) == (
        LOGIN,
        ACCESS_KEY,
        USER_ADMIN,
    )


def test_unsorted_input_is_evaluated_by_signal_timestamp() -> None:
    chronological = _sequence()

    matches = AwsAccountCompromiseSequenceRule().evaluate(tuple(reversed(chronological)))

    assert len(matches) == 1
    assert matches[0].signals == chronological


def test_correlation_match_signals_and_derived_times_are_chronological() -> None:
    signals = _sequence()

    match = AwsAccountCompromiseSequenceRule().evaluate(
        (signals[2], signals[0], signals[1])
    )[0]

    assert tuple(signal.timestamp for signal in match.signals) == tuple(
        sorted(signal.timestamp for signal in signals)
    )
    assert match.started_at == signals[0].timestamp
    assert match.ended_at == signals[2].timestamp


def test_correlation_engine_returns_reference_rule_match() -> None:
    matches = CorrelationEngine(AWS_CORRELATION_RULES).evaluate(_sequence())

    assert len(matches) == 1
    assert matches[0].rule_id == AwsAccountCompromiseSequenceRule.rule_id


def test_no_valid_sequence_returns_empty_tuple() -> None:
    signals = (_signal(LOGIN), _signal(ACCESS_KEY, minutes=5))

    assert AwsAccountCompromiseSequenceRule().evaluate(signals) == ()


def test_two_independent_actor_sequences_produce_two_matches() -> None:
    bob = Actor(
        arn="arn:aws:iam::123456789012:user/bob",
        account_id="123456789012",
    )
    alice_signals = _sequence()
    bob_signals = _sequence(actor=bob, start_minute=1)

    matches = AwsAccountCompromiseSequenceRule().evaluate(
        alice_signals + bob_signals
    )

    assert len(matches) == 2
    assert matches[0].signals == alice_signals
    assert matches[1].signals == bob_signals


def test_signals_are_not_reused_in_overlapping_matches() -> None:
    login = _signal(LOGIN)
    first_key = _signal(ACCESS_KEY, minutes=3, signal_id="first-key")
    second_key = _signal(ACCESS_KEY, minutes=4, signal_id="second-key")
    first_admin = _signal(USER_ADMIN, minutes=5, signal_id="first-admin")
    second_admin = _signal(USER_ADMIN, minutes=6, signal_id="second-admin")

    matches = AwsAccountCompromiseSequenceRule().evaluate(
        (login, first_key, second_key, first_admin, second_admin)
    )

    assert len(matches) == 1
    assert matches[0].signals == (login, first_key, first_admin)


def test_correlation_ignores_contradictory_raw_event_contents() -> None:
    signals = (
        _signal(
            LOGIN,
            raw_event={"userIdentity": {"arn": "arn:aws:iam::1:user/one"}},
        ),
        _signal(
            ACCESS_KEY,
            minutes=5,
            raw_event={"userIdentity": {"arn": "arn:aws:iam::2:user/two"}},
        ),
        _signal(
            USER_ADMIN,
            minutes=10,
            raw_event={"userIdentity": {"arn": "arn:aws:iam::3:user/three"}},
        ),
    )

    matches = AwsAccountCompromiseSequenceRule().evaluate(signals)

    assert len(matches) == 1
    assert matches[0].signals == signals
