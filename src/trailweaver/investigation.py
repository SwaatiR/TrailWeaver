"""Deterministic investigation guidance from normalized TrailWeaver evidence."""

from dataclasses import dataclass
from enum import StrEnum

from trailweaver.blast_radius import BlastRadiusResult
from trailweaver.incidents import Incident
from trailweaver.risk import RiskAssessment

_LOGIN_WITHOUT_MFA = "aws.auth.console_login_without_mfa"
_ACCESS_KEY_CREATED = "aws.iam.access_key_created"
_ADMIN_POLICY_TO_USER = "aws.iam.admin_policy_attached_to_user"
_ADMIN_POLICY_TO_ROLE = "aws.iam.admin_policy_attached_to_role"
_CLOUDTRAIL_LOGGING_STOPPED = "aws.cloudtrail.logging_stopped"


class RecommendationPriority(StrEnum):
    """The urgency assigned to an investigation recommendation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationRecommendation:
    """One deterministic next step supported by incident evidence."""

    recommendation_id: str
    title: str
    description: str
    priority: RecommendationPriority
    rationale: str


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationGuidance:
    """An immutable ordered set of investigation recommendations."""

    recommendations: tuple[InvestigationRecommendation, ...]
    summary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "recommendations", tuple(self.recommendations))


class InvestigationAdvisor:
    """Generate guidance from existing normalized evidence without retaining state."""

    def advise(
        self,
        incident: Incident,
        *,
        risk_assessment: RiskAssessment | None = None,
        blast_radius: BlastRadiusResult | None = None,
    ) -> InvestigationGuidance:
        """Return deterministic next steps for the available derived evidence.

        ``risk_assessment`` is accepted so callers can pass their existing derived
        analysis through one interface. Current recommendation priorities are fixed
        by evidence category and do not depend on a numeric risk score.
        """

        signals = incident.correlation_match.signals
        first_positions: dict[str, int] = {}
        source_ips: list[str] = []
        access_key_users: list[str] = []
        admin_targets: list[str] = []
        trail_names: list[str] = []

        for position, signal in enumerate(signals):
            event = signal.source_event
            if signal.rule_id == _LOGIN_WITHOUT_MFA:
                first_positions.setdefault("login", position)
                _append_unique(source_ips, event.source_ip)
            elif signal.rule_id == _ACCESS_KEY_CREATED:
                first_positions.setdefault("access_key", position)
                _append_unique(
                    access_key_users,
                    _string_attribute(event.attributes, "target_user"),
                )
            elif signal.rule_id == _ADMIN_POLICY_TO_USER:
                first_positions.setdefault("admin", position)
                target_user = _string_attribute(event.attributes, "target_user")
                if target_user is not None:
                    _append_unique(admin_targets, f"IAM user {target_user}")
            elif signal.rule_id == _ADMIN_POLICY_TO_ROLE:
                first_positions.setdefault("admin", position)
                target_role = _string_attribute(event.attributes, "target_role")
                if target_role is not None:
                    _append_unique(admin_targets, f"IAM role {target_role}")
            elif signal.rule_id == _CLOUDTRAIL_LOGGING_STOPPED:
                first_positions.setdefault("logging", position)
                _append_unique(
                    trail_names,
                    _string_attribute(event.attributes, "trail_name"),
                )

        candidates: list[tuple[int, InvestigationRecommendation]] = []
        topics: list[str] = []

        if "login" in first_positions:
            candidates.append(
                (
                    first_positions["login"],
                    _login_recommendation(source_ips),
                )
            )
            topics.append("identity activity")

        if "access_key" in first_positions:
            candidates.append(
                (
                    first_positions["access_key"],
                    _access_key_recommendation(access_key_users),
                )
            )
            topics.append("credential creation")

        if "admin" in first_positions:
            candidates.append(
                (
                    first_positions["admin"],
                    _admin_recommendation(admin_targets),
                )
            )
            topics.append("privilege changes")

        if "logging" in first_positions:
            candidates.append(
                (
                    first_positions["logging"],
                    _logging_recommendation(trail_names),
                )
            )
            topics.append("audit logging")

        if blast_radius is not None and blast_radius.reachable_assets:
            candidates.append(
                (
                    len(signals),
                    _blast_radius_recommendation(blast_radius),
                )
            )
            topics.append("potentially reachable assets")

        priority_order = {
            RecommendationPriority.HIGH: 0,
            RecommendationPriority.MEDIUM: 1,
            RecommendationPriority.LOW: 2,
        }
        candidates.sort(
            key=lambda candidate: (
                priority_order[candidate[1].priority],
                candidate[0],
            )
        )
        recommendations = tuple(recommendation for _, recommendation in candidates)

        return InvestigationGuidance(
            recommendations=recommendations,
            summary=_guidance_summary(topics),
        )


def _login_recommendation(source_ips: list[str]) -> InvestigationRecommendation:
    if source_ips:
        label = "source IP" if len(source_ips) == 1 else "source IPs"
        rationale = (
            "TrailWeaver observed a successful AWS console login without MFA from "
            f"{label} {_join_items(source_ips)}."
        )
    else:
        rationale = (
            "TrailWeaver observed a successful AWS console login without MFA; no "
            "source IP was available in the normalized evidence."
        )

    return InvestigationRecommendation(
        recommendation_id="verify-console-login-without-mfa",
        title="Verify console login without MFA",
        description=(
            "Verify whether the login was expected and whether the source IP is "
            "recognized by the user or team."
        ),
        priority=RecommendationPriority.MEDIUM,
        rationale=rationale,
    )


def _access_key_recommendation(
    target_users: list[str],
) -> InvestigationRecommendation:
    if target_users:
        label = "IAM user" if len(target_users) == 1 else "IAM users"
        rationale = (
            f"TrailWeaver observed access-key creation for {label} "
            f"{_join_items(target_users)}."
        )
    else:
        rationale = "TrailWeaver observed access-key creation in the incident."

    return InvestigationRecommendation(
        recommendation_id="review-access-key-creation",
        title="Review access-key creation",
        description=(
            "Confirm whether the access-key creation was authorized and review activity "
            "performed after the key was created."
        ),
        priority=RecommendationPriority.MEDIUM,
        rationale=rationale,
    )


def _admin_recommendation(targets: list[str]) -> InvestigationRecommendation:
    if targets:
        rationale = (
            "TrailWeaver observed AdministratorAccess assignment to "
            f"{_join_items(targets)}."
        )
    else:
        rationale = (
            "TrailWeaver observed an AdministratorAccess assignment in normalized "
            "incident evidence."
        )

    return InvestigationRecommendation(
        recommendation_id="review-administrator-access-assignment",
        title="Review AdministratorAccess assignment",
        description=(
            "Verify who authorized the privilege change, review whether the user or role "
            "still requires that access, and check subsequent activity performed with "
            "the elevated privilege."
        ),
        priority=RecommendationPriority.HIGH,
        rationale=rationale,
    )


def _logging_recommendation(trail_names: list[str]) -> InvestigationRecommendation:
    if trail_names:
        label = "trail" if len(trail_names) == 1 else "trails"
        rationale = (
            f"TrailWeaver observed CloudTrail logging stopped for {label} "
            f"{_join_items(trail_names)}."
        )
    else:
        rationale = "TrailWeaver observed that CloudTrail logging was stopped."

    return InvestigationRecommendation(
        recommendation_id="review-cloudtrail-logging-stop",
        title="Investigate stopped CloudTrail logging",
        description=(
            "Verify whether logging was intentionally stopped, review audit gaps around "
            "the event, and restore logging if the action was unauthorized."
        ),
        priority=RecommendationPriority.HIGH,
        rationale=rationale,
    )


def _blast_radius_recommendation(
    blast_radius: BlastRadiusResult,
) -> InvestigationRecommendation:
    count = blast_radius.total_reachable_assets
    asset_word = "asset" if count == 1 else "assets"
    access_verb = "was" if count == 1 else "were"
    return InvestigationRecommendation(
        recommendation_id="review-potentially-reachable-assets",
        title="Review potentially reachable assets",
        description=(
            f"Review the {count} known {asset_word} potentially reachable by this "
            "identity, with priority on secrets, databases, and other sensitive "
            "resources."
        ),
        priority=RecommendationPriority.MEDIUM,
        rationale=(
            f"The provided blast-radius result contains {count} known {asset_word} "
            "identified as potentially reachable; it does not establish that the "
            f"{asset_word} {access_verb} accessed."
        ),
    )


def _string_attribute(attributes: object, name: str) -> str | None:
    if not isinstance(attributes, dict):
        return None
    value = attributes.get(name)
    return value if isinstance(value, str) and value.strip() else None


def _append_unique(values: list[str], value: str | None) -> None:
    if value is not None and value.strip() and value not in values:
        values.append(value)


def _join_items(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"


def _guidance_summary(topics: list[str]) -> str:
    if not topics:
        return (
            "TrailWeaver found no current investigation recommendation supported by "
            "the normalized evidence available for this incident."
        )
    return (
        f"TrailWeaver recommends reviewing {_join_items(topics)} associated with this "
        "incident."
    )
