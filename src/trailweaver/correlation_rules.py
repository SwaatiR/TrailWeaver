"""Initial AWS signal-correlation rules."""

from collections.abc import Collection
from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar

from trailweaver.correlation import (
    ActorCorrelationKey,
    CorrelationMatch,
    CorrelationRule,
    actor_correlation_key,
)
from trailweaver.signals import Signal

_CONSOLE_LOGIN_WITHOUT_MFA = "aws.auth.console_login_without_mfa"
_ACCESS_KEY_CREATED = "aws.iam.access_key_created"
_ADMIN_POLICY_ATTACHED = frozenset(
    {
        "aws.iam.admin_policy_attached_to_user",
        "aws.iam.admin_policy_attached_to_role",
    }
)


@dataclass(frozen=True, slots=True)
class AwsAccountCompromiseSequenceRule:
    """Correlate a bounded same-actor AWS security-sensitive sequence.

    The rule greedily selects the earliest valid chronological sequence for
    each actor. Signals used by a match are removed from consideration, so
    matches from one evaluation do not overlap.
    """

    rule_id: ClassVar[str] = "aws.identity.possible_account_compromise_sequence"
    title: ClassVar[str] = "Possible AWS account compromise sequence"
    description: ClassVar[str] = (
        "A console login without MFA was followed by access-key creation and "
        "administrator privilege assignment for the same AWS actor."
    )
    window: ClassVar[timedelta] = timedelta(minutes=15)
    reason: ClassVar[str] = (
        "A successful console login without MFA was followed by access-key creation "
        "and administrator privilege assignment for the same actor within 15 minutes."
    )

    def evaluate(self, signals: Collection[Signal]) -> tuple[CorrelationMatch, ...]:
        """Return non-overlapping same-actor sequences ordered by start time."""

        ordered_signals = tuple(
            signal
            for _, signal in sorted(
                enumerate(signals),
                key=lambda item: (item[1].timestamp, item[0]),
            )
        )
        signals_by_actor: dict[ActorCorrelationKey, list[Signal]] = {}
        for signal in ordered_signals:
            key = actor_correlation_key(signal.source_event)
            if key is not None:
                signals_by_actor.setdefault(key, []).append(signal)

        matched_sequences: list[tuple[Signal, Signal, Signal]] = []
        for actor_signals in signals_by_actor.values():
            available = actor_signals.copy()
            while sequence := self._find_earliest_sequence(available):
                matched_sequences.append(sequence)
                consumed = {id(signal) for signal in sequence}
                available = [signal for signal in available if id(signal) not in consumed]

        matched_sequences.sort(
            key=lambda sequence: (
                sequence[0].timestamp,
                sequence[-1].timestamp,
                tuple(signal.signal_id for signal in sequence),
            )
        )
        return tuple(
            CorrelationMatch(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                reason=self.reason,
                signals=sequence,
            )
            for sequence in matched_sequences
        )

    def _find_earliest_sequence(
        self, signals: list[Signal]
    ) -> tuple[Signal, Signal, Signal] | None:
        for first_index, first in enumerate(signals):
            if first.rule_id != _CONSOLE_LOGIN_WITHOUT_MFA:
                continue

            deadline = first.timestamp + self.window
            for second_index in range(first_index + 1, len(signals)):
                second = signals[second_index]
                if second.timestamp > deadline:
                    break
                if second.rule_id != _ACCESS_KEY_CREATED:
                    continue

                for third in signals[second_index + 1 :]:
                    if third.timestamp > deadline:
                        break
                    if third.rule_id in _ADMIN_POLICY_ATTACHED:
                        return first, second, third
        return None


AWS_CORRELATION_RULES: tuple[CorrelationRule, ...] = (
    AwsAccountCompromiseSequenceRule(),
)
