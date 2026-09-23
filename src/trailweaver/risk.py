"""Deterministic and explainable incident risk scoring."""

from dataclasses import dataclass
from enum import StrEnum

from trailweaver.incidents import Incident

_ADMIN_POLICY_RULE_IDS = frozenset(
    {
        "aws.iam.admin_policy_attached_to_user",
        "aws.iam.admin_policy_attached_to_role",
    }
)


class RiskLevel(StrEnum):
    """A categorical level derived from a numeric risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def risk_level_for_score(score: int) -> RiskLevel:
    """Map 0-24 to low, 25-49 to medium, 50-79 to high, and 80-100 to critical."""

    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")
    if score <= 24:
        return RiskLevel.LOW
    if score <= 49:
        return RiskLevel.MEDIUM
    if score <= 79:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


@dataclass(frozen=True, slots=True, kw_only=True)
class RiskFactor:
    """One deterministic contribution to an incident risk score."""

    identifier: str
    description: str
    points: int

    def __post_init__(self) -> None:
        if self.points < 0:
            raise ValueError("Risk factor points cannot be negative")


@dataclass(frozen=True, slots=True, kw_only=True)
class RiskAssessment:
    """An explainable risk result derived from a collection of factors."""

    factors: tuple[RiskFactor, ...]
    explanation: str

    @property
    def score(self) -> int:
        """Return the factor total capped at 100."""

        return min(sum(factor.points for factor in self.factors), 100)

    @property
    def level(self) -> RiskLevel:
        """Return the categorical level for the capped score."""

        return risk_level_for_score(self.score)


_RISK_FACTORS: dict[str, RiskFactor] = {
    "aws.auth.console_login_without_mfa": RiskFactor(
        identifier="aws.auth.console_login_without_mfa",
        description="Successful AWS console login occurred without MFA.",
        points=20,
    ),
    "aws.iam.access_key_created": RiskFactor(
        identifier="aws.iam.access_key_created",
        description="A new IAM access key was created.",
        points=20,
    ),
    "aws.iam.admin_policy_attached_to_user": RiskFactor(
        identifier="aws.iam.admin_policy_attached_to_user",
        description="AWS AdministratorAccess policy was attached to an IAM user.",
        points=40,
    ),
    "aws.iam.admin_policy_attached_to_role": RiskFactor(
        identifier="aws.iam.admin_policy_attached_to_role",
        description="AWS AdministratorAccess policy was attached to an IAM role.",
        points=40,
    ),
}


class RiskScorer:
    """Derive a risk assessment from existing normalized incident evidence.

    Each defined factor contributes at most once per incident. User and role
    AdministratorAccess attachments share one privilege-assignment category,
    so they cannot both increase the same assessment.
    """

    def score(self, incident: Incident) -> RiskAssessment:
        """Return a deterministic assessment without mutating the incident."""

        factors: list[RiskFactor] = []
        seen_rule_ids: set[str] = set()
        admin_policy_counted = False

        for signal in incident.correlation_match.signals:
            if signal.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(signal.rule_id)

            factor = _RISK_FACTORS.get(signal.rule_id)
            if factor is None:
                continue

            if signal.rule_id in _ADMIN_POLICY_RULE_IDS:
                if admin_policy_counted:
                    continue
                admin_policy_counted = True

            factors.append(factor)

        factor_tuple = tuple(factors)
        return RiskAssessment(
            factors=factor_tuple,
            explanation=self._explain(factor_tuple),
        )

    @staticmethod
    def _explain(factors: tuple[RiskFactor, ...]) -> str:
        if not factors:
            return (
                "Score 0 of 100 because no correlated signals matched a defined risk "
                "factor. This assessment does not confirm or rule out compromise."
            )

        score = min(sum(factor.points for factor in factors), 100)
        return (
            f"Score {score} of 100 is the capped sum of {len(factors)} distinct risk "
            "factors from multiple related identity-security behaviors. The observed "
            "security-sensitive activity requires investigation and does not confirm "
            "compromise."
        )
