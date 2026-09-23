"""Initial AWS security detection rules."""

from dataclasses import dataclass
from typing import ClassVar

from trailweaver.detection import DetectionRule
from trailweaver.models import EventOutcome, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

_ADMINISTRATOR_ACCESS_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _is_successful_aws_event(
    event: NormalizedEvent, *, service: str, action: str
) -> bool:
    return (
        event.provider == "aws"
        and event.service == service
        and event.action == action
        and event.outcome is EventOutcome.SUCCESS
    )


@dataclass(frozen=True, slots=True)
class ConsoleLoginWithoutMfaRule:
    """Detect a successful AWS console login performed without MFA."""

    rule_id: ClassVar[str] = "aws.auth.console_login_without_mfa"
    title: ClassVar[str] = "AWS console login without MFA"
    description: ClassVar[str] = "An AWS console login succeeded without MFA."
    severity: ClassVar[SignalSeverity] = SignalSeverity.MEDIUM

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal only when MFA usage is explicitly false."""

        if not _is_successful_aws_event(
            event, service="signin", action="ConsoleLogin"
        ) or event.attributes.get("mfa_used") is not False:
            return None

        return Signal(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            source_event=event,
            reason="Successful AWS console login occurred without MFA.",
        )


@dataclass(frozen=True, slots=True)
class AdministratorPolicyAttachedToUserRule:
    """Detect AdministratorAccess attachment to an IAM user."""

    rule_id: ClassVar[str] = "aws.iam.admin_policy_attached_to_user"
    title: ClassVar[str] = "AdministratorAccess attached to IAM user"
    description: ClassVar[str] = (
        "The AWS managed AdministratorAccess policy was attached to an IAM user."
    )
    severity: ClassVar[SignalSeverity] = SignalSeverity.HIGH

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal for the exact AWS AdministratorAccess policy ARN."""

        if not _is_successful_aws_event(
            event, service="iam", action="AttachUserPolicy"
        ) or event.attributes.get("policy_arn") != _ADMINISTRATOR_ACCESS_POLICY_ARN:
            return None

        target_user = event.attributes.get("target_user")
        if isinstance(target_user, str) and target_user:
            reason = f"AdministratorAccess was attached to IAM user {target_user}."
        else:
            reason = "AdministratorAccess was attached to an IAM user."

        return Signal(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            source_event=event,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class AdministratorPolicyAttachedToRoleRule:
    """Detect AdministratorAccess attachment to an IAM role."""

    rule_id: ClassVar[str] = "aws.iam.admin_policy_attached_to_role"
    title: ClassVar[str] = "AdministratorAccess attached to IAM role"
    description: ClassVar[str] = (
        "The AWS managed AdministratorAccess policy was attached to an IAM role."
    )
    severity: ClassVar[SignalSeverity] = SignalSeverity.HIGH

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal for the exact AWS AdministratorAccess policy ARN."""

        if not _is_successful_aws_event(
            event, service="iam", action="AttachRolePolicy"
        ) or event.attributes.get("policy_arn") != _ADMINISTRATOR_ACCESS_POLICY_ARN:
            return None

        target_role = event.attributes.get("target_role")
        if isinstance(target_role, str) and target_role:
            reason = f"AdministratorAccess was attached to IAM role {target_role}."
        else:
            reason = "AdministratorAccess was attached to an IAM role."

        return Signal(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            source_event=event,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class AccessKeyCreatedRule:
    """Detect successful creation of a new IAM access key."""

    rule_id: ClassVar[str] = "aws.iam.access_key_created"
    title: ClassVar[str] = "IAM access key created"
    description: ClassVar[str] = (
        "A new IAM access key was created and may require security review."
    )
    severity: ClassVar[SignalSeverity] = SignalSeverity.MEDIUM

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal for successful IAM CreateAccessKey activity."""

        if not _is_successful_aws_event(
            event, service="iam", action="CreateAccessKey"
        ):
            return None

        target_user = event.attributes.get("target_user")
        if isinstance(target_user, str) and target_user:
            reason = f"A new access key was created for IAM user {target_user}."
        else:
            reason = "A new IAM access key was created."

        return Signal(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            source_event=event,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class SuccessfulCloudTrailStopLoggingRule:
    """Detect a successful request to stop CloudTrail logging."""

    rule_id: ClassVar[str] = "aws.cloudtrail.logging_stopped"
    title: ClassVar[str] = "CloudTrail logging stopped"
    description: ClassVar[str] = "CloudTrail logging was stopped for an audit trail."
    severity: ClassVar[SignalSeverity] = SignalSeverity.HIGH

    def evaluate(self, event: NormalizedEvent) -> Signal | None:
        """Return a signal for a successful AWS CloudTrail StopLogging event."""

        if not _is_successful_aws_event(
            event, service="cloudtrail", action="StopLogging"
        ):
            return None

        trail_name = event.attributes.get("trail_name")
        if isinstance(trail_name, str) and trail_name:
            reason = f"Successful StopLogging action was observed for trail {trail_name}."
        else:
            reason = "Successful StopLogging action was observed."

        return Signal(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            source_event=event,
            reason=reason,
        )


AWS_RULES: tuple[DetectionRule, ...] = (
    ConsoleLoginWithoutMfaRule(),
    AdministratorPolicyAttachedToUserRule(),
    AdministratorPolicyAttachedToRoleRule(),
    AccessKeyCreatedRule(),
    SuccessfulCloudTrailStopLoggingRule(),
)
