import json
import socket
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from trailweaver.attack_graph import AttackGraph
from trailweaver.cloud_context import (
    CloudAsset,
    CloudAssetType,
    CloudContext,
    CloudContextFixtureError,
    PermissionEffect,
    PermissionGrant,
    cloud_context_from_json,
    load_cloud_context,
)

ACCOUNT_ID = "123456789012"
ROLE_ARN = "arn:aws:iam::123456789012:role/DeploymentRole"
BUCKET_ARN = "arn:aws:s3:::production-data"


def _role(**overrides: object) -> CloudAsset:
    values: dict[str, object] = {
        "asset_type": CloudAssetType.ROLE,
        "provider": "aws",
        "account_id": ACCOUNT_ID,
        "name": "DeploymentRole",
        "arn": ROLE_ARN,
    }
    values.update(overrides)
    return CloudAsset(**values)  # type: ignore[arg-type]


def _grant(**overrides: object) -> PermissionGrant:
    values: dict[str, object] = {
        "subject": ROLE_ARN,
        "actions": ("s3:GetObject",),
        "resources": (f"{BUCKET_ARN}/*",),
        "effect": PermissionEffect.ALLOW,
        "source": "attached_managed_policy:ReadProductionData",
    }
    values.update(overrides)
    return PermissionGrant(**values)  # type: ignore[arg-type]


def test_create_cloud_asset() -> None:
    asset = _role(metadata={"owner": "platform", "tags": ["prod", "security"]})

    assert asset.asset_type is CloudAssetType.ROLE
    assert asset.provider == "aws"
    assert asset.account_id == ACCOUNT_ID
    assert asset.name == "DeploymentRole"
    assert asset.metadata == {"owner": "platform", "tags": ("prod", "security")}


def test_optional_asset_fields_can_be_absent() -> None:
    asset = CloudAsset(
        asset_type=CloudAssetType.OTHER,
        provider="example-cloud",
        native_identifier="asset-123",
    )

    assert asset.account_id is None
    assert asset.region is None
    assert asset.name is None
    assert asset.arn is None
    assert asset.metadata == {}


def test_arn_is_the_stable_asset_id() -> None:
    first = _role(name="first", native_identifier="role-1")
    second = _role(name="second", native_identifier="role-2", region="us-east-1")

    assert first.asset_id == ROLE_ARN
    assert second.asset_id == ROLE_ARN


def test_asset_id_fallback_is_deterministic() -> None:
    values = {
        "asset_type": CloudAssetType.COMPUTE,
        "provider": "example-cloud",
        "account_id": "account-1",
        "native_identifier": "instance-123",
    }

    assert CloudAsset(**values).asset_id == CloudAsset(**values).asset_id
    assert CloudAsset(**values).asset_id.startswith("cloud_asset:")


def test_native_identifier_is_preferred_to_name_for_fallback_id() -> None:
    first = CloudAsset(
        asset_type=CloudAssetType.COMPUTE,
        provider="example-cloud",
        account_id="account-1",
        native_identifier="instance-123",
        name="first",
    )
    second = CloudAsset(
        asset_type=CloudAssetType.COMPUTE,
        provider="example-cloud",
        account_id="account-1",
        native_identifier="instance-123",
        name="second",
    )

    assert first.asset_id == second.asset_id


def test_fallback_id_changes_with_identity_context() -> None:
    first = CloudAsset(
        asset_type=CloudAssetType.COMPUTE,
        provider="example-cloud",
        account_id="account-1",
        name="worker",
    )
    second = CloudAsset(
        asset_type=CloudAssetType.COMPUTE,
        provider="example-cloud",
        account_id="account-2",
        name="worker",
    )

    assert first.asset_id != second.asset_id


def test_asset_requires_a_stable_identifier() -> None:
    with pytest.raises(ValueError, match="ARN, native identifier, or name"):
        CloudAsset(asset_type=CloudAssetType.OTHER, provider="example-cloud")


def test_cloud_asset_and_nested_metadata_are_immutable() -> None:
    asset = _role(metadata={"labels": {"environment": "production"}})

    with pytest.raises(FrozenInstanceError):
        asset.name = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        asset.metadata["owner"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        asset.metadata["labels"]["environment"] = "changed"  # type: ignore[index]


def test_create_allow_permission_grant() -> None:
    grant = _grant()

    assert grant.subject == ROLE_ARN
    assert grant.effect is PermissionEffect.ALLOW
    assert grant.source == "attached_managed_policy:ReadProductionData"


def test_create_deny_permission_grant() -> None:
    grant = _grant(effect=PermissionEffect.DENY, source="inline_policy:RestrictDeletes")

    assert grant.effect is PermissionEffect.DENY


def test_permission_grant_canonicalizes_multiple_actions_and_resources() -> None:
    grant = _grant(
        actions=("s3:PutObject", "s3:GetObject", "s3:GetObject"),
        resources=(BUCKET_ARN, f"{BUCKET_ARN}/*", BUCKET_ARN),
    )

    assert grant.actions == ("s3:GetObject", "s3:PutObject")
    assert grant.resources == (BUCKET_ARN, f"{BUCKET_ARN}/*")


@pytest.mark.parametrize("effect", ["permit", "block", ""])
def test_permission_effect_rejects_unknown_values(effect: str) -> None:
    with pytest.raises(ValueError, match="allow.*deny"):
        _grant(effect=effect)


def test_permission_grant_keeps_wildcards_literal() -> None:
    grant = _grant(actions=("*",), resources=("*",))

    assert grant.actions == ("*",)
    assert grant.resources == ("*",)


def test_context_uses_immutable_collections_and_supports_lookups() -> None:
    asset = _role()
    grant = _grant()
    context = CloudContext(assets=[asset], permission_grants=[grant])  # type: ignore[arg-type]

    assert context.assets == (asset,)
    assert context.permission_grants == (grant,)
    assert context.find_asset(asset.asset_id) is asset
    assert context.find_asset("missing") is None
    assert context.grants_for_subject(ROLE_ARN) == (grant,)
    assert context.grants_for_subject("missing") == ()


def test_duplicate_logical_assets_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate cloud asset IDs"):
        CloudContext(assets=(_role(name="first"), _role(name="second")))


def test_context_construction_has_canonical_order() -> None:
    role = _role()
    bucket = CloudAsset(
        asset_type=CloudAssetType.STORAGE,
        provider="aws",
        name="production-data",
        arn=BUCKET_ARN,
    )
    allow = _grant()
    deny = _grant(
        actions=("s3:DeleteBucket",),
        resources=(BUCKET_ARN,),
        effect=PermissionEffect.DENY,
        source="inline_policy:ProtectBucket",
    )

    first = CloudContext(assets=(role, bucket), permission_grants=(deny, allow))
    second = CloudContext(assets=(bucket, role), permission_grants=(allow, deny))

    assert first == second


def test_load_json_fixture(tmp_path: Path) -> None:
    fixture = tmp_path / "cloud-context.json"
    fixture.write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "asset_type": "role",
                        "provider": "aws",
                        "account_id": ACCOUNT_ID,
                        "name": "DeploymentRole",
                        "arn": ROLE_ARN,
                        "metadata": {"environment": "production"},
                    }
                ],
                "permissions": [
                    {
                        "subject": ROLE_ARN,
                        "actions": ["*"],
                        "resources": ["*"],
                        "effect": "allow",
                        "source": (
                            "attached_managed_policy:"
                            "arn:aws:iam::aws:policy/AdministratorAccess"
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    context = load_cloud_context(fixture)

    assert context.assets[0].asset_id == ROLE_ARN
    assert context.permission_grants[0].effect is PermissionEffect.ALLOW
    assert context.permission_grants[0].actions == ("*",)


def test_fixture_loading_makes_no_network_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "cloud-context.json"
    fixture.write_text('{"assets": [], "permissions": []}', encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("Cloud context loading attempted a network call")

    monkeypatch.setattr(socket, "create_connection", fail_if_called)

    assert load_cloud_context(fixture) == CloudContext()


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        ({"assets": {} , "permissions": []}, "assets must be an array"),
        ({"assets": [], "permissions": [{}]}, "permissions\\[0\\].subject"),
        (
            {
                "assets": [
                    {
                        "asset_type": "unsupported",
                        "provider": "aws",
                        "name": "asset",
                    }
                ],
                "permissions": [],
            },
            "Unsupported cloud asset type",
        ),
    ],
)
def test_invalid_fixture_data_fails_clearly(
    fixture: object, message: str
) -> None:
    with pytest.raises(CloudContextFixtureError, match=message):
        cloud_context_from_json(fixture)


def test_cloud_context_has_no_raw_event_dependency() -> None:
    asset = _role()
    grant = _grant()

    assert not hasattr(asset, "raw_event")
    assert not hasattr(grant, "raw_event")
    assert not hasattr(CloudContext(assets=(asset,)), "raw_event")


def test_cloud_context_and_attack_graph_are_separate_types() -> None:
    context = CloudContext()
    graph = AttackGraph(nodes=(), edges=())

    assert type(context) is CloudContext
    assert type(graph) is AttackGraph
    assert not isinstance(context, AttackGraph)
