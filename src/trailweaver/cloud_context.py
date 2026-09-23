"""Provider-neutral cloud assets and known permission context."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TypeAlias

from trailweaver.models import JsonObject, JsonValue

FrozenJsonValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | None
    | tuple["FrozenJsonValue", ...]
    | Mapping[str, "FrozenJsonValue"]
)
FrozenMetadata: TypeAlias = Mapping[str, FrozenJsonValue]


class CloudAssetType(StrEnum):
    """The initial provider-neutral cloud asset categories."""

    IDENTITY = "identity"
    ROLE = "role"
    STORAGE = "storage"
    COMPUTE = "compute"
    DATABASE = "database"
    SECRET = "secret"
    OTHER = "other"


class PermissionEffect(StrEnum):
    """Whether a known permission fact allows or denies access."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudAsset:
    """An immutable provider-neutral description of a known cloud asset.

    The asset ID is the ARN itself when one is present. Otherwise it is a
    stable digest of the provider, account, type, and native identifier or
    name. Region and metadata do not affect identity.
    """

    asset_type: CloudAssetType
    provider: str
    account_id: str | None = None
    region: str | None = None
    name: str | None = None
    arn: str | None = None
    native_identifier: str | None = None
    metadata: FrozenMetadata = field(default_factory=dict)
    asset_id: str = field(init=False)

    def __post_init__(self) -> None:
        asset_type = _asset_type(self.asset_type)
        _require_non_empty_string(self.provider, "provider")
        for field_name in ("account_id", "region", "name", "arn", "native_identifier"):
            _validate_optional_string(getattr(self, field_name), field_name)

        if self.arn is None and self.native_identifier is None and self.name is None:
            raise ValueError(
                "Cloud asset requires an ARN, native identifier, or name for stable identity"
            )

        object.__setattr__(self, "asset_type", asset_type)
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))
        object.__setattr__(self, "asset_id", _asset_id(self))


@dataclass(frozen=True, slots=True, kw_only=True)
class PermissionGrant:
    """A known permission fact without final authorization semantics.

    Actions and resources are canonicalized as sorted, duplicate-free tuples.
    Wildcards remain literal facts and are not expanded.
    """

    subject: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    effect: PermissionEffect
    source: str

    def __post_init__(self) -> None:
        _require_non_empty_string(self.subject, "subject")
        _require_non_empty_string(self.source, "source")
        object.__setattr__(self, "actions", _canonical_strings(self.actions, "actions"))
        object.__setattr__(
            self,
            "resources",
            _canonical_strings(self.resources, "resources"),
        )
        try:
            effect = PermissionEffect(self.effect)
        except (TypeError, ValueError) as error:
            raise ValueError("Permission effect must be 'allow' or 'deny'") from error
        object.__setattr__(self, "effect", effect)


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudContext:
    """Known assets and permission facts, kept separate from observed activity."""

    assets: tuple[CloudAsset, ...] = ()
    permission_grants: tuple[PermissionGrant, ...] = ()

    def __post_init__(self) -> None:
        assets = tuple(sorted(self.assets, key=lambda asset: asset.asset_id))
        duplicate_ids = _duplicate_asset_ids(assets)
        if duplicate_ids:
            duplicates = ", ".join(repr(asset_id) for asset_id in duplicate_ids)
            raise ValueError(f"Duplicate cloud asset IDs: {duplicates}")

        grants = tuple(sorted(self.permission_grants, key=_grant_sort_key))
        object.__setattr__(self, "assets", assets)
        object.__setattr__(self, "permission_grants", grants)

    def find_asset(self, asset_id: str) -> CloudAsset | None:
        """Return the asset with the exact deterministic ID, if known."""

        return next((asset for asset in self.assets if asset.asset_id == asset_id), None)

    def grants_for_subject(self, subject: str) -> tuple[PermissionGrant, ...]:
        """Return known grants for an exact subject without resolving permissions."""

        return tuple(
            grant for grant in self.permission_grants if grant.subject == subject
        )


class CloudContextFixtureError(ValueError):
    """Raised when a TrailWeaver cloud-context fixture is invalid."""


def load_cloud_context(path: str | Path) -> CloudContext:
    """Load a CloudContext from TrailWeaver's deterministic JSON fixture format."""

    fixture_path = Path(path)
    try:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise CloudContextFixtureError(
            f"Unable to read cloud context fixture {fixture_path}: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise CloudContextFixtureError(
            f"Invalid JSON in cloud context fixture {fixture_path}: {error.msg}"
        ) from error

    return cloud_context_from_json(data)


def cloud_context_from_json(data: object) -> CloudContext:
    """Build a CloudContext from an already-decoded fixture object."""

    root = _fixture_object(data, "fixture root")
    _reject_unknown_fields(root, {"assets", "permissions"}, "fixture root")
    assets_data = _fixture_list(root.get("assets"), "assets")
    permissions_data = _fixture_list(root.get("permissions"), "permissions")

    assets = tuple(
        _asset_from_fixture(item, index) for index, item in enumerate(assets_data)
    )
    grants = tuple(
        _grant_from_fixture(item, index)
        for index, item in enumerate(permissions_data)
    )
    try:
        return CloudContext(assets=assets, permission_grants=grants)
    except ValueError as error:
        raise CloudContextFixtureError(f"Invalid cloud context fixture: {error}") from error


def _asset_id(asset: CloudAsset) -> str:
    if asset.arn is not None:
        return asset.arn

    identity_kind = "native_identifier" if asset.native_identifier is not None else "name"
    identity_value = asset.native_identifier or asset.name
    canonical = json.dumps(
        (
            asset.provider,
            asset.account_id,
            asset.asset_type.value,
            identity_kind,
            identity_value,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"cloud_asset:{digest}"


def _asset_type(value: object) -> CloudAssetType:
    try:
        return CloudAssetType(value)
    except (TypeError, ValueError) as error:
        supported = ", ".join(asset_type.value for asset_type in CloudAssetType)
        raise ValueError(f"Unsupported cloud asset type; expected one of: {supported}") from error


def _require_non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_optional_string(value: object, field_name: str) -> None:
    if value is not None:
        _require_non_empty_string(value, field_name)


def _canonical_strings(values: object, field_name: str) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise TypeError(f"Permission {field_name} must be a non-empty sequence of strings")
    result = tuple(values)
    if not result:
        raise ValueError(f"Permission {field_name} cannot be empty")
    for value in result:
        _require_non_empty_string(value, f"permission {field_name} entry")
    return tuple(sorted(set(result)))


def _freeze_metadata(metadata: object) -> FrozenMetadata:
    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be an object")
    frozen: dict[str, FrozenJsonValue] = {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise TypeError("metadata keys must be strings")
        frozen[key] = _freeze_json_value(value)
    return MappingProxyType(frozen)


def _freeze_json_value(value: object) -> FrozenJsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return _freeze_metadata(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(item) for item in value)
    raise ValueError(f"metadata contains unsupported value of type {type(value).__name__}")


def _duplicate_asset_ids(assets: tuple[CloudAsset, ...]) -> tuple[str, ...]:
    duplicates: list[str] = []
    previous: str | None = None
    for asset in assets:
        if asset.asset_id == previous and asset.asset_id not in duplicates:
            duplicates.append(asset.asset_id)
        previous = asset.asset_id
    return tuple(duplicates)


def _grant_sort_key(
    grant: PermissionGrant,
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], str]:
    return (
        grant.subject,
        grant.effect.value,
        grant.actions,
        grant.resources,
        grant.source,
    )


def _asset_from_fixture(value: object, index: int) -> CloudAsset:
    location = f"assets[{index}]"
    item = _fixture_object(value, location)
    _reject_unknown_fields(
        item,
        {
            "asset_type",
            "provider",
            "account_id",
            "region",
            "name",
            "arn",
            "native_identifier",
            "metadata",
        },
        location,
    )
    try:
        return CloudAsset(
            asset_type=_fixture_string(item.get("asset_type"), f"{location}.asset_type"),
            provider=_fixture_string(item.get("provider"), f"{location}.provider"),
            account_id=_fixture_optional_string(item.get("account_id"), f"{location}.account_id"),
            region=_fixture_optional_string(item.get("region"), f"{location}.region"),
            name=_fixture_optional_string(item.get("name"), f"{location}.name"),
            arn=_fixture_optional_string(item.get("arn"), f"{location}.arn"),
            native_identifier=_fixture_optional_string(
                item.get("native_identifier"), f"{location}.native_identifier"
            ),
            metadata=_fixture_object(item.get("metadata", {}), f"{location}.metadata"),
        )
    except (TypeError, ValueError) as error:
        raise CloudContextFixtureError(f"Invalid {location}: {error}") from error


def _grant_from_fixture(value: object, index: int) -> PermissionGrant:
    location = f"permissions[{index}]"
    item = _fixture_object(value, location)
    _reject_unknown_fields(
        item,
        {"subject", "actions", "resources", "effect", "source"},
        location,
    )
    try:
        return PermissionGrant(
            subject=_fixture_string(item.get("subject"), f"{location}.subject"),
            actions=tuple(_fixture_string_list(item.get("actions"), f"{location}.actions")),
            resources=tuple(
                _fixture_string_list(item.get("resources"), f"{location}.resources")
            ),
            effect=_fixture_string(item.get("effect"), f"{location}.effect"),
            source=_fixture_string(item.get("source"), f"{location}.source"),
        )
    except (TypeError, ValueError) as error:
        raise CloudContextFixtureError(f"Invalid {location}: {error}") from error


def _fixture_object(value: object, location: str) -> JsonObject:
    if not isinstance(value, dict):
        raise CloudContextFixtureError(f"{location} must be an object")
    return value


def _fixture_list(value: object, location: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise CloudContextFixtureError(f"{location} must be an array")
    return value


def _fixture_string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CloudContextFixtureError(f"{location} must be a non-empty string")
    return value


def _fixture_optional_string(value: object, location: str) -> str | None:
    if value is None:
        return None
    return _fixture_string(value, location)


def _fixture_string_list(value: object, location: str) -> list[str]:
    values = _fixture_list(value, location)
    return [
        _fixture_string(item, f"{location}[{index}]")
        for index, item in enumerate(values)
    ]


def _reject_unknown_fields(
    value: JsonObject, allowed: set[str], location: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        fields = ", ".join(repr(field) for field in unknown)
        raise CloudContextFixtureError(f"{location} has unknown fields: {fields}")
