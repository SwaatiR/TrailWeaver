import socket
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from trailweaver.blast_radius import (
    BlastRadiusAnalyzer,
    BlastRadiusResult,
    actor_subject_key,
)
from trailweaver.cloud_context import (
    CloudAsset,
    CloudAssetType,
    CloudContext,
    PermissionEffect,
    PermissionGrant,
)
from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.models import Actor, JsonObject, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
ACCOUNT_ID = "123456789012"
ACTOR_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
ACTOR = Actor(
    actor_type="IAMUser",
    identifier="AIDAALICE",
    name="alice",
    arn=ACTOR_ARN,
    account_id=ACCOUNT_ID,
)


def _asset(
    name: str,
    asset_type: CloudAssetType,
    *,
    service: str,
) -> CloudAsset:
    return CloudAsset(
        asset_type=asset_type,
        provider="aws",
        account_id=ACCOUNT_ID,
        name=name,
        arn=f"arn:aws:{service}:us-east-1:{ACCOUNT_ID}:resource/{name}",
    )


def _grant(
    *resources: str,
    subject: str = ACTOR_ARN,
    actions: tuple[str, ...] = ("example:Read",),
    effect: PermissionEffect = PermissionEffect.ALLOW,
    source: str = "imported_fixture:test",
) -> PermissionGrant:
    return PermissionGrant(
        subject=subject,
        actions=actions,
        resources=resources,
        effect=effect,
        source=source,
    )


def _incident(
    *,
    actor: Actor | None = ACTOR,
    provider: str = "aws",
    raw_event: JsonObject | None = None,
) -> Incident:
    signal = Signal(
        signal_id="signal-1",
        rule_id="test.signal",
        title="Test signal",
        description="A test signal for blast-radius analysis.",
        severity=SignalSeverity.HIGH,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME,
            provider=provider,
            service="test",
            action="TestAction",
            actor=actor,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason="Normalized incident evidence identified the primary actor.",
    )
    match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="test.correlation",
        title="Test correlation",
        description="A correlation for blast-radius tests.",
        reason="The test evidence was correlated.",
        signals=(signal,),
    )
    return Incident(
        incident_id="incident-1",
        title="Potential identity compromise",
        description="Identity activity requires investigation.",
        severity=SignalSeverity.HIGH,
        correlation_match=match,
        summary="Potential identity compromise activity was observed.",
        created_at=BASE_TIME,
    )


def test_one_allow_grant_reaches_one_known_asset() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    context = CloudContext(
        assets=(bucket,),
        permission_grants=(_grant(bucket.asset_id),),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert isinstance(result, BlastRadiusResult)
    assert result.subject == ACTOR_ARN
    assert result.reachable_assets == (bucket,)
    assert result.total_reachable_assets == 1


def test_blast_radius_result_is_immutable() -> None:
    result = BlastRadiusResult(
        subject=None,
        reachable_assets=[],  # type: ignore[arg-type]
        matched_grants=[],  # type: ignore[arg-type]
        summary="No potential reachability was identified.",
    )

    assert result.reachable_assets == ()
    assert result.matched_grants == ()
    with pytest.raises(FrozenInstanceError):
        result.summary = "changed"  # type: ignore[misc]


def test_multiple_grants_reach_multiple_assets() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    database = _asset("customers", CloudAssetType.DATABASE, service="rds")
    context = CloudContext(
        assets=(bucket, database),
        permission_grants=(
            _grant(bucket.asset_id, source="inline_policy:storage"),
            _grant(database.asset_id, source="inline_policy:database"),
        ),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert {asset.asset_id for asset in result.reachable_assets} == {
        bucket.asset_id,
        database.asset_id,
    }
    assert len(result.matched_grants) == 2


def test_exact_resource_matching_does_not_parse_arn_patterns() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    arn_pattern = f"{bucket.asset_id[:-4]}*"
    context = CloudContext(
        assets=(bucket,),
        permission_grants=(_grant(arn_pattern),),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert result.reachable_assets == ()
    assert result.matched_grants == ()


def test_unknown_resource_reference_does_not_create_an_asset() -> None:
    known = _asset("known", CloudAssetType.SECRET, service="secretsmanager")
    context = CloudContext(
        assets=(known,),
        permission_grants=(_grant("arn:aws:example:::unknown"),),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert result.reachable_assets == ()
    assert context.assets == (known,)


def test_no_primary_actor_returns_empty_result() -> None:
    asset = _asset("known", CloudAssetType.COMPUTE, service="ec2")

    result = BlastRadiusAnalyzer().analyze(
        _incident(actor=None),
        CloudContext(assets=(asset,), permission_grants=(_grant("*"),)),
    )

    assert result.subject is None
    assert result.reachable_assets == ()
    assert result.matched_grants == ()
    assert result.total_reachable_assets == 0


def test_primary_actor_without_usable_identity_returns_empty_result() -> None:
    actor = Actor(account_id=ACCOUNT_ID)

    result = BlastRadiusAnalyzer().analyze(_incident(actor=actor), CloudContext())

    assert result.subject is None
    assert result.reachable_assets == ()


def test_no_matching_grants_returns_empty_result() -> None:
    asset = _asset("known", CloudAssetType.COMPUTE, service="ec2")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(asset,)),
    )

    assert result.subject == ACTOR_ARN
    assert result.reachable_assets == ()
    assert result.matched_grants == ()


def test_exact_deny_overrides_allow() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    allow = _grant(bucket.asset_id, source="attached_managed_policy:allow")
    deny = _grant(
        bucket.asset_id,
        effect=PermissionEffect.DENY,
        source="inline_policy:deny",
    )

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(bucket,), permission_grants=(allow, deny)),
    )

    assert result.reachable_assets == ()
    assert result.matched_grants == ()


def test_deny_with_different_action_scope_does_not_override_allow() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    allow = _grant(bucket.asset_id, actions=("s3:GetObject",))
    deny = _grant(
        bucket.asset_id,
        actions=("s3:DeleteObject",),
        effect=PermissionEffect.DENY,
    )

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(bucket,), permission_grants=(allow, deny)),
    )

    assert result.reachable_assets == (bucket,)
    assert result.matched_grants == (allow,)


def test_unrelated_subject_grants_are_ignored() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    context = CloudContext(
        assets=(bucket,),
        permission_grants=(_grant(bucket.asset_id, subject="unrelated-subject"),),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert result.reachable_assets == ()


def test_wildcard_resource_scope_reaches_only_known_context_assets() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    secret = _asset("api-key", CloudAssetType.SECRET, service="secretsmanager")
    context = CloudContext(
        assets=(secret, bucket),
        permission_grants=(_grant("*"),),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert result.reachable_assets == context.assets
    assert result.total_reachable_assets == 2


def test_wildcard_action_counts_as_broad_permission() -> None:
    database = _asset("customers", CloudAssetType.DATABASE, service="rds")
    grant = _grant(database.asset_id, actions=("*",))

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(database,), permission_grants=(grant,)),
    )

    assert result.reachable_assets == (database,)
    assert result.matched_grants == (grant,)


def test_reachable_assets_are_deduplicated() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    first = _grant(bucket.asset_id, actions=("s3:GetObject",), source="inline:first")
    second = _grant(bucket.asset_id, actions=("s3:PutObject",), source="inline:second")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(bucket,), permission_grants=(first, second)),
    )

    assert result.reachable_assets == (bucket,)
    assert len(result.matched_grants) == 2


def test_matched_grants_preserve_explanation_sources() -> None:
    bucket = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    grant = _grant(bucket.asset_id, source="attached_managed_policy:ReadOnlyAccess")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(bucket,), permission_grants=(grant,)),
    )

    assert result.matched_grants == (grant,)
    assert result.matched_grants[0] is grant
    assert result.matched_grants[0].source == "attached_managed_policy:ReadOnlyAccess"


def test_arn_subject_is_preferred_over_identifier_and_name() -> None:
    actor = Actor(
        arn=ACTOR_ARN,
        identifier="different-identifier",
        name="different-name",
        account_id=ACCOUNT_ID,
    )

    assert actor_subject_key(actor, "aws") == ACTOR_ARN


def test_identifier_subject_fallback_matches_identity_asset_id() -> None:
    actor = Actor(identifier="AIDAALICE", name="alice", account_id=ACCOUNT_ID)
    identity = CloudAsset(
        asset_type=CloudAssetType.IDENTITY,
        provider="aws",
        account_id=ACCOUNT_ID,
        native_identifier="AIDAALICE",
    )
    target = _asset("production-data", CloudAssetType.STORAGE, service="s3")
    grant = _grant(target.asset_id, subject=identity.asset_id)

    result = BlastRadiusAnalyzer().analyze(
        _incident(actor=actor),
        CloudContext(assets=(identity, target), permission_grants=(grant,)),
    )

    assert result.subject == identity.asset_id
    assert result.reachable_assets == (target,)


def test_name_subject_fallback_includes_provider_and_account_context() -> None:
    actor = Actor(name="alice", account_id=ACCOUNT_ID)
    same_context = actor_subject_key(actor, "aws")

    assert same_context is not None
    assert same_context == actor_subject_key(actor, "aws")
    assert same_context != actor_subject_key(actor, "example-cloud")
    assert same_context != actor_subject_key(
        Actor(name="alice", account_id="999999999999"), "aws"
    )


def test_result_order_follows_cloud_context_canonical_order() -> None:
    compute = _asset("z-compute", CloudAssetType.COMPUTE, service="ec2")
    database = _asset("a-database", CloudAssetType.DATABASE, service="rds")
    first = _grant(compute.asset_id, source="source:z")
    second = _grant(database.asset_id, source="source:a")
    context = CloudContext(
        assets=(compute, database),
        permission_grants=(first, second),
    )

    result = BlastRadiusAnalyzer().analyze(_incident(), context)

    assert result.reachable_assets == context.assets
    assert result.matched_grants == tuple(
        grant
        for grant in context.permission_grants
        if grant.effect is PermissionEffect.ALLOW
    )


def test_repeated_analysis_is_identical() -> None:
    asset = _asset("known", CloudAssetType.OTHER, service="example")
    context = CloudContext(
        assets=(asset,),
        permission_grants=(_grant(asset.asset_id),),
    )
    analyzer = BlastRadiusAnalyzer()
    incident = _incident()

    assert analyzer.analyze(incident, context) == analyzer.analyze(incident, context)


def test_analysis_does_not_mutate_incident_or_context() -> None:
    asset = _asset("known", CloudAssetType.OTHER, service="example")
    grant = _grant(asset.asset_id)
    context = CloudContext(assets=(asset,), permission_grants=(grant,))
    incident = _incident()
    original_match = incident.correlation_match
    original_signals = incident.correlation_match.signals
    original_assets = context.assets
    original_grants = context.permission_grants

    BlastRadiusAnalyzer().analyze(incident, context)

    assert incident.correlation_match is original_match
    assert incident.correlation_match.signals is original_signals
    assert context.assets is original_assets
    assert context.permission_grants is original_grants


def test_analysis_does_not_inspect_raw_event() -> None:
    asset = _asset("known", CloudAssetType.OTHER, service="example")
    raw_event: JsonObject = {
        "userIdentity": {"arn": "arn:aws:iam::999999999999:user/raw"},
        "permissions": [{"resource": "*"}],
    }

    result = BlastRadiusAnalyzer().analyze(
        _incident(raw_event=raw_event),
        CloudContext(assets=(asset,), permission_grants=(_grant(asset.asset_id),)),
    )

    assert result.subject == ACTOR_ARN
    assert result.reachable_assets == (asset,)


def test_analysis_makes_no_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("Blast-radius analysis attempted a network call")

    monkeypatch.setattr(socket, "create_connection", fail_if_called)
    asset = _asset("known", CloudAssetType.OTHER, service="example")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(asset,), permission_grants=(_grant(asset.asset_id),)),
    )

    assert result.reachable_assets == (asset,)


def test_summary_uses_cautious_potential_wording() -> None:
    asset = _asset("known", CloudAssetType.OTHER, service="example")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(asset,), permission_grants=(_grant(asset.asset_id),)),
    )

    wording = result.summary.lower()
    assert "potentially reachable" in wording
    assert "known asset" in wording
    assert "attacker" not in wording
    assert "can access" not in wording


def test_analysis_requires_only_incident_and_cloud_context() -> None:
    asset = _asset("known", CloudAssetType.OTHER, service="example")

    result = BlastRadiusAnalyzer().analyze(
        _incident(),
        CloudContext(assets=(asset,), permission_grants=(_grant(asset.asset_id),)),
    )

    assert isinstance(result, BlastRadiusResult)
