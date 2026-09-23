from datetime import UTC, datetime

import pytest

from trailweaver.detection import DetectionEngine, DetectionRule
from trailweaver.models import EventOutcome, JsonObject, NormalizedEvent, SecurityAttributes
from trailweaver.rules import (
    AWS_RULES,
    AccessKeyCreatedRule,
    AdministratorPolicyAttachedToRoleRule,
    AdministratorPolicyAttachedToUserRule,
    ConsoleLoginWithoutMfaRule,
    SuccessfulCloudTrailStopLoggingRule,
)
from trailweaver.signals import SignalSeverity

ADMINISTRATOR_ACCESS_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _event(
    *,
    service: str,
    action: str,
    outcome: EventOutcome = EventOutcome.SUCCESS,
    attributes: SecurityAttributes | None = None,
    raw_event: JsonObject | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 23, 10, 30, tzinfo=UTC),
        provider="aws",
        service=service,
        action=action,
        outcome=outcome,
        attributes={} if attributes is None else attributes,
        raw_event={} if raw_event is None else raw_event,
    )


def test_console_login_without_mfa_matches_explicit_false() -> None:
    signal = ConsoleLoginWithoutMfaRule().evaluate(
        _event(service="signin", action="ConsoleLogin", attributes={"mfa_used": False})
    )

    assert signal is not None
    assert signal.rule_id == "aws.auth.console_login_without_mfa"
    assert signal.severity is SignalSeverity.MEDIUM
    assert signal.reason == "Successful AWS console login occurred without MFA."


@pytest.mark.parametrize("attributes", [{"mfa_used": True}, {}])
def test_console_login_without_mfa_requires_explicit_false(
    attributes: SecurityAttributes,
) -> None:
    signal = ConsoleLoginWithoutMfaRule().evaluate(
        _event(service="signin", action="ConsoleLogin", attributes=attributes)
    )

    assert signal is None


def test_failed_console_login_without_mfa_does_not_match() -> None:
    signal = ConsoleLoginWithoutMfaRule().evaluate(
        _event(
            service="signin",
            action="ConsoleLogin",
            outcome=EventOutcome.FAILURE,
            attributes={"mfa_used": False},
        )
    )

    assert signal is None


def test_admin_policy_attached_to_user_matches_exact_arn_and_names_target() -> None:
    signal = AdministratorPolicyAttachedToUserRule().evaluate(
        _event(
            service="iam",
            action="AttachUserPolicy",
            attributes={
                "policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN,
                "target_user": "developer",
            },
        )
    )

    assert signal is not None
    assert signal.rule_id == "aws.iam.admin_policy_attached_to_user"
    assert signal.severity is SignalSeverity.HIGH
    assert signal.reason == "AdministratorAccess was attached to IAM user developer."


def test_admin_policy_attached_to_user_rejects_different_policy() -> None:
    signal = AdministratorPolicyAttachedToUserRule().evaluate(
        _event(
            service="iam",
            action="AttachUserPolicy",
            attributes={
                "policy_arn": "arn:aws:iam::123456789012:policy/AdministratorAccess"
            },
        )
    )

    assert signal is None


def test_failed_admin_policy_attachment_to_user_does_not_match() -> None:
    signal = AdministratorPolicyAttachedToUserRule().evaluate(
        _event(
            service="iam",
            action="AttachUserPolicy",
            outcome=EventOutcome.FAILURE,
            attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
        )
    )

    assert signal is None


def test_admin_policy_attached_to_role_matches_exact_arn_and_names_target() -> None:
    signal = AdministratorPolicyAttachedToRoleRule().evaluate(
        _event(
            service="iam",
            action="AttachRolePolicy",
            attributes={
                "policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN,
                "target_role": "DeploymentRole",
            },
        )
    )

    assert signal is not None
    assert signal.rule_id == "aws.iam.admin_policy_attached_to_role"
    assert signal.severity is SignalSeverity.HIGH
    assert signal.reason == (
        "AdministratorAccess was attached to IAM role DeploymentRole."
    )


def test_admin_policy_attached_to_role_rejects_different_policy() -> None:
    signal = AdministratorPolicyAttachedToRoleRule().evaluate(
        _event(
            service="iam",
            action="AttachRolePolicy",
            attributes={
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"
            },
        )
    )

    assert signal is None


def test_failed_admin_policy_attachment_to_role_does_not_match() -> None:
    signal = AdministratorPolicyAttachedToRoleRule().evaluate(
        _event(
            service="iam",
            action="AttachRolePolicy",
            outcome=EventOutcome.FAILURE,
            attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
        )
    )

    assert signal is None


def test_successful_access_key_creation_matches_and_names_target() -> None:
    signal = AccessKeyCreatedRule().evaluate(
        _event(
            service="iam",
            action="CreateAccessKey",
            attributes={"target_user": "developer"},
        )
    )

    assert signal is not None
    assert signal.rule_id == "aws.iam.access_key_created"
    assert signal.severity is SignalSeverity.MEDIUM
    assert signal.reason == "A new access key was created for IAM user developer."


def test_failed_access_key_creation_does_not_match() -> None:
    signal = AccessKeyCreatedRule().evaluate(
        _event(
            service="iam",
            action="CreateAccessKey",
            outcome=EventOutcome.FAILURE,
        )
    )

    assert signal is None


@pytest.mark.parametrize(
    ("rule", "event", "expected_reason"),
    [
        (
            AdministratorPolicyAttachedToUserRule(),
            _event(
                service="iam",
                action="AttachUserPolicy",
                attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
            ),
            "AdministratorAccess was attached to an IAM user.",
        ),
        (
            AdministratorPolicyAttachedToRoleRule(),
            _event(
                service="iam",
                action="AttachRolePolicy",
                attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
            ),
            "AdministratorAccess was attached to an IAM role.",
        ),
        (
            AccessKeyCreatedRule(),
            _event(service="iam", action="CreateAccessKey"),
            "A new IAM access key was created.",
        ),
    ],
)
def test_reasons_do_not_invent_missing_targets(
    rule: DetectionRule, event: NormalizedEvent, expected_reason: str
) -> None:
    signal = rule.evaluate(event)

    assert signal is not None
    assert signal.reason == expected_reason


def test_aws_rule_pack_contains_exactly_the_initial_rules() -> None:
    assert tuple(type(rule) for rule in AWS_RULES) == (
        ConsoleLoginWithoutMfaRule,
        AdministratorPolicyAttachedToUserRule,
        AdministratorPolicyAttachedToRoleRule,
        AccessKeyCreatedRule,
        SuccessfulCloudTrailStopLoggingRule,
    )


def test_detection_engine_with_aws_pack_returns_expected_match() -> None:
    event = _event(
        service="iam",
        action="AttachRolePolicy",
        attributes={
            "policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN,
            "target_role": "DeploymentRole",
        },
    )

    signals = DetectionEngine(AWS_RULES).evaluate(event)

    assert tuple(signal.rule_id for signal in signals) == (
        "aws.iam.admin_policy_attached_to_role",
    )


@pytest.mark.parametrize(
    ("rule", "event"),
    [
        (
            ConsoleLoginWithoutMfaRule(),
            _event(
                service="signin",
                action="ConsoleLogin",
                attributes={"mfa_used": False},
                raw_event={"eventName": "DifferentAction"},
            ),
        ),
        (
            AdministratorPolicyAttachedToUserRule(),
            _event(
                service="iam",
                action="AttachUserPolicy",
                attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
                raw_event={"errorCode": "AccessDenied"},
            ),
        ),
        (
            AdministratorPolicyAttachedToRoleRule(),
            _event(
                service="iam",
                action="AttachRolePolicy",
                attributes={"policy_arn": ADMINISTRATOR_ACCESS_POLICY_ARN},
                raw_event={"eventSource": "different.amazonaws.com"},
            ),
        ),
        (
            AccessKeyCreatedRule(),
            _event(
                service="iam",
                action="CreateAccessKey",
                raw_event={"eventName": "DeleteAccessKey"},
            ),
        ),
        (
            SuccessfulCloudTrailStopLoggingRule(),
            _event(
                service="cloudtrail",
                action="StopLogging",
                raw_event={"eventName": "StartLogging"},
            ),
        ),
    ],
)
def test_aws_rules_use_normalized_fields_instead_of_raw_event(
    rule: DetectionRule, event: NormalizedEvent
) -> None:
    assert rule.evaluate(event) is not None
