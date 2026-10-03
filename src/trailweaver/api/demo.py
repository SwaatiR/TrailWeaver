"""Explicit local-development API populated with deterministic demo evidence."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI

from trailweaver.api.app import create_app
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.cloud_context import (
    CloudAsset,
    CloudAssetType,
    CloudContext,
    PermissionEffect,
    PermissionGrant,
)
from trailweaver.correlation import CorrelationEngine
from trailweaver.correlation_rules import AWS_CORRELATION_RULES
from trailweaver.detection import DetectionEngine
from trailweaver.incidents import Incident, IncidentFactory
from trailweaver.models import Actor, EventOutcome, NormalizedEvent
from trailweaver.rules import AWS_RULES

DEMO_INCIDENT_ID = "demo-incident-aws-account-compromise"
DEMO_ACCOUNT_ID = "123456789012"
DEMO_ACTOR_ARN = f"arn:aws:iam::{DEMO_ACCOUNT_ID}:user/developer"
DEMO_STARTED_AT = datetime(2026, 9, 23, 10, 1, tzinfo=UTC)

_ADMINISTRATOR_ACCESS_POLICY_ARN = (
    "arn:aws:iam::aws:policy/AdministratorAccess"
)
_EXPECTED_RULE_IDS = (
    "aws.auth.console_login_without_mfa",
    "aws.iam.access_key_created",
    "aws.iam.admin_policy_attached_to_user",
)


def create_demo_incident() -> Incident:
    """Build one deterministic incident through detection and correlation."""

    detector = DetectionEngine(AWS_RULES)
    detected_signals = tuple(
        signal
        for event in _demo_events()
        for signal in detector.evaluate(event)
    )
    if tuple(signal.rule_id for signal in detected_signals) != _EXPECTED_RULE_IDS:
        raise RuntimeError("Demo evidence did not produce the expected detection sequence")

    signals = tuple(
        replace(signal, signal_id=f"demo-signal-{position}")
        for position, signal in enumerate(detected_signals, start=1)
    )
    matches = CorrelationEngine(AWS_CORRELATION_RULES).evaluate(signals)
    if len(matches) != 1:
        raise RuntimeError("Demo signals did not produce exactly one correlation match")

    match = replace(matches[0], correlation_id="demo-correlation-account-compromise")
    return IncidentFactory().create(
        match,
        incident_id=DEMO_INCIDENT_ID,
        created_at=DEMO_STARTED_AT + timedelta(minutes=8),
    )


def create_demo_cloud_context() -> CloudContext:
    """Return known demo assets and one explicit permission fact for the actor."""

    assets = (
        CloudAsset(
            asset_type=CloudAssetType.STORAGE,
            provider="aws",
            account_id=DEMO_ACCOUNT_ID,
            region="us-east-1",
            name="trailweaver-demo-audit-archive",
            arn="arn:aws:s3:::trailweaver-demo-audit-archive",
            metadata={"environment": "demo", "data_class": "audit"},
        ),
        CloudAsset(
            asset_type=CloudAssetType.STORAGE,
            provider="aws",
            account_id=DEMO_ACCOUNT_ID,
            region="us-east-1",
            name="trailweaver-demo-application-exports",
            arn="arn:aws:s3:::trailweaver-demo-application-exports",
            metadata={"environment": "demo", "data_class": "application"},
        ),
        CloudAsset(
            asset_type=CloudAssetType.COMPUTE,
            provider="aws",
            account_id=DEMO_ACCOUNT_ID,
            region="us-east-1",
            name="demo-application-server",
            arn=(
                f"arn:aws:ec2:us-east-1:{DEMO_ACCOUNT_ID}:"
                "instance/i-0123456789abcdef0"
            ),
            metadata={"environment": "demo", "role": "application"},
        ),
        CloudAsset(
            asset_type=CloudAssetType.DATABASE,
            provider="aws",
            account_id=DEMO_ACCOUNT_ID,
            region="us-east-1",
            name="demo-orders",
            arn=f"arn:aws:rds:us-east-1:{DEMO_ACCOUNT_ID}:db:demo-orders",
            metadata={"environment": "demo", "engine": "postgres"},
        ),
        CloudAsset(
            asset_type=CloudAssetType.SECRET,
            provider="aws",
            account_id=DEMO_ACCOUNT_ID,
            region="us-east-1",
            name="demo-application-api-key",
            arn=(
                f"arn:aws:secretsmanager:us-east-1:{DEMO_ACCOUNT_ID}:"
                "secret:demo/application-api-key-AbCdEf"
            ),
            metadata={"environment": "demo", "sensitivity": "high"},
        ),
    )
    return CloudContext(
        assets=assets,
        permission_grants=(
            PermissionGrant(
                subject=DEMO_ACTOR_ARN,
                actions=("*",),
                resources=("*",),
                effect=PermissionEffect.ALLOW,
                source=(
                    "demo:attached_managed_policy:"
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                ),
            ),
        ),
    )


def create_demo_app() -> FastAPI:
    """Create the opt-in demo API starting from an empty workspace.

    The demo runs the same production file-analysis pipeline over an
    in-memory repository, keeps the deterministic demo cloud context for
    blast-radius analysis, and additionally exposes a demo-only workspace
    reset. S3 analysis stays disabled: the local demo must never need AWS
    credentials, network access, or a real account.
    """

    return create_app(
        repository=InMemoryIncidentRepository(),
        cloud_context=create_demo_cloud_context(),
        enable_analysis=True,
        enable_s3_analysis=False,
        demo_mode=True,
        enable_demo_reset=True,
    )


def _demo_events() -> tuple[NormalizedEvent, ...]:
    actor = Actor(
        actor_type="IAMUser",
        identifier="AIDADEMO000000000001",
        name="developer",
        arn=DEMO_ACTOR_ARN,
        account_id=DEMO_ACCOUNT_ID,
    )
    return (
        NormalizedEvent(
            event_id="demo-event-console-login",
            timestamp=DEMO_STARTED_AT,
            provider="aws",
            service="signin",
            action="ConsoleLogin",
            outcome=EventOutcome.SUCCESS,
            region="us-east-1",
            source_ip="198.51.100.24",
            actor=actor,
            attributes={"mfa_used": False},
            raw_event={
                "eventName": "ConsoleLogin",
                "demo_only_raw_marker": "m16-1-raw-evidence",
            },
        ),
        NormalizedEvent(
            event_id="demo-event-access-key",
            timestamp=DEMO_STARTED_AT + timedelta(minutes=3),
            provider="aws",
            service="iam",
            action="CreateAccessKey",
            outcome=EventOutcome.SUCCESS,
            region="us-east-1",
            source_ip="198.51.100.24",
            actor=actor,
            attributes={"target_user": "developer"},
            raw_event={
                "eventName": "CreateAccessKey",
                "demo_only_raw_marker": "m16-1-raw-evidence",
            },
        ),
        NormalizedEvent(
            event_id="demo-event-administrator-access",
            timestamp=DEMO_STARTED_AT + timedelta(minutes=7),
            provider="aws",
            service="iam",
            action="AttachUserPolicy",
            outcome=EventOutcome.SUCCESS,
            region="us-east-1",
            source_ip="198.51.100.24",
            actor=actor,
            attributes={
                "target_user": "developer",
                "policy_arn": _ADMINISTRATOR_ACCESS_POLICY_ARN,
            },
            raw_event={
                "eventName": "AttachUserPolicy",
                "demo_only_raw_marker": "m16-1-raw-evidence",
            },
        ),
    )


app = create_demo_app()
