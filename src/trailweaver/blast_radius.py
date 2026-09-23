"""Estimate potential reachability over known cloud context."""

from dataclasses import dataclass

from trailweaver.cloud_context import (
    CloudAsset,
    CloudAssetType,
    CloudContext,
    PermissionEffect,
    PermissionGrant,
)
from trailweaver.incidents import Incident
from trailweaver.models import Actor


@dataclass(frozen=True, slots=True, kw_only=True)
class BlastRadiusResult:
    """A deterministic potential-reachability estimate for one incident subject."""

    subject: str | None
    reachable_assets: tuple[CloudAsset, ...]
    matched_grants: tuple[PermissionGrant, ...]
    summary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reachable_assets", tuple(self.reachable_assets))
        object.__setattr__(self, "matched_grants", tuple(self.matched_grants))

    @property
    def total_reachable_assets(self) -> int:
        """Return the number of distinct known assets in the estimate."""

        return len(self.reachable_assets)


class BlastRadiusAnalyzer:
    """Estimate reachability from explicit grants in a CloudContext.

    This deliberately is not an IAM authorization engine. It performs exact
    subject and resource matching, expands a resource value of ``*`` only to
    assets currently loaded in the context, and applies deny precedence only
    to grants with identical subject, action, and resource scopes.
    """

    def analyze(self, incident: Incident, context: CloudContext) -> BlastRadiusResult:
        """Return known assets potentially reachable by the primary actor."""

        subject = _incident_subject(incident)
        if subject is None:
            return BlastRadiusResult(
                subject=None,
                reachable_assets=(),
                matched_grants=(),
                summary=(
                    "No usable primary identity was available, so potential "
                    "reachability over the known cloud context could not be estimated."
                ),
            )

        subject_grants = context.grants_for_subject(subject)
        effective_allows = tuple(
            grant
            for grant in subject_grants
            if grant.effect is PermissionEffect.ALLOW
            and not _has_exact_deny(grant, subject_grants)
        )

        known_asset_ids = {asset.asset_id for asset in context.assets}
        reachable_ids: set[str] = set()
        matched_grants: list[PermissionGrant] = []
        for grant in effective_allows:
            matched_asset_ids = _matched_asset_ids(grant, known_asset_ids)
            if not matched_asset_ids:
                continue
            reachable_ids.update(matched_asset_ids)
            matched_grants.append(grant)

        reachable_assets = tuple(
            asset for asset in context.assets if asset.asset_id in reachable_ids
        )
        matched_grant_tuple = tuple(matched_grants)
        return BlastRadiusResult(
            subject=subject,
            reachable_assets=reachable_assets,
            matched_grants=matched_grant_tuple,
            summary=_summary(len(matched_grant_tuple), len(reachable_assets)),
        )


def actor_subject_key(actor: Actor, provider: str) -> str | None:
    """Return the actor's stable PermissionGrant subject key.

    ARN is used directly. Identifier and name fallbacks use the same identity
    inputs as deterministic CloudAsset IDs, including provider and account
    context.
    """

    if actor.arn is not None and actor.arn.strip():
        return actor.arn
    if not provider.strip():
        return None

    account_id = (
        actor.account_id
        if actor.account_id is not None and actor.account_id.strip()
        else None
    )
    if actor.identifier is not None and actor.identifier.strip():
        return CloudAsset(
            asset_type=CloudAssetType.IDENTITY,
            provider=provider,
            account_id=account_id,
            native_identifier=actor.identifier,
        ).asset_id
    if actor.name is not None and actor.name.strip():
        return CloudAsset(
            asset_type=CloudAssetType.IDENTITY,
            provider=provider,
            account_id=account_id,
            name=actor.name,
        ).asset_id
    return None


def _incident_subject(incident: Incident) -> str | None:
    primary_actor = incident.primary_actor
    if primary_actor is None:
        return None

    for signal in incident.correlation_match.signals:
        if signal.source_event.actor is primary_actor:
            return actor_subject_key(primary_actor, signal.source_event.provider)
    return None


def _has_exact_deny(
    allow: PermissionGrant, subject_grants: tuple[PermissionGrant, ...]
) -> bool:
    return any(
        grant.effect is PermissionEffect.DENY
        and grant.actions == allow.actions
        and grant.resources == allow.resources
        for grant in subject_grants
    )


def _matched_asset_ids(
    grant: PermissionGrant, known_asset_ids: set[str]
) -> set[str]:
    if "*" in grant.resources:
        return known_asset_ids.copy()
    return known_asset_ids.intersection(grant.resources)


def _summary(matched_grant_count: int, reachable_asset_count: int) -> str:
    grant_word = "grant" if matched_grant_count == 1 else "grants"
    asset_word = "asset is" if reachable_asset_count == 1 else "assets are"
    return (
        f"Based on {matched_grant_count} explicit permission {grant_word} in the loaded "
        f"cloud context, {reachable_asset_count} known {asset_word} potentially "
        "reachable by the primary identity."
    )
