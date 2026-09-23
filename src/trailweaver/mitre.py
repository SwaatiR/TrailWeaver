"""Deterministic MITRE ATT&CK mapping for incident signal evidence."""

from dataclasses import dataclass

from trailweaver.incidents import Incident


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackTechnique:
    """A concise TrailWeaver representation of one ATT&CK technique."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str


@dataclass(frozen=True, slots=True, kw_only=True)
class MitreMapping:
    """Deduplicated ATT&CK techniques and tactics derived from an incident."""

    techniques: tuple[AttackTechnique, ...]
    tactics: tuple[str, ...]


_CLOUD_ACCOUNTS = AttackTechnique(
    technique_id="T1078.004",
    name="Cloud Accounts",
    tactics=("Stealth", "Persistence", "Privilege Escalation", "Initial Access"),
    description=(
        "Observed cloud-console authentication maps to use of an existing cloud account."
    ),
)

_ADDITIONAL_CLOUD_CREDENTIALS = AttackTechnique(
    technique_id="T1098.001",
    name="Additional Cloud Credentials",
    tactics=("Persistence", "Privilege Escalation"),
    description=(
        "Observed access-key creation maps to adding credentials to a cloud account."
    ),
)

_ADDITIONAL_CLOUD_ROLES = AttackTechnique(
    technique_id="T1098.003",
    name="Additional Cloud Roles",
    tactics=("Persistence", "Privilege Escalation"),
    description=(
        "Observed administrator-policy attachment maps to adding cloud permissions."
    ),
)

_DISABLE_OR_MODIFY_CLOUD_LOG = AttackTechnique(
    technique_id="T1685.002",
    name="Disable or Modify Cloud Log",
    tactics=("Defense Impairment",),
    description=(
        "Observed suspension of cloud audit logging maps to impairment of cloud logs."
    ),
)

_TECHNIQUES_BY_RULE_ID: dict[str, AttackTechnique] = {
    "aws.auth.console_login_without_mfa": _CLOUD_ACCOUNTS,
    "aws.iam.access_key_created": _ADDITIONAL_CLOUD_CREDENTIALS,
    "aws.iam.admin_policy_attached_to_user": _ADDITIONAL_CLOUD_ROLES,
    "aws.iam.admin_policy_attached_to_role": _ADDITIONAL_CLOUD_ROLES,
    "aws.cloudtrail.logging_stopped": _DISABLE_OR_MODIFY_CLOUD_LOG,
}


class MitreMapper:
    """Map normalized incident signals to ATT&CK without retaining state."""

    def map(self, incident: Incident) -> MitreMapping:
        """Return techniques and tactics in first-evidence order."""

        techniques: list[AttackTechnique] = []
        tactics: list[str] = []
        seen_technique_ids: set[str] = set()
        seen_tactics: set[str] = set()

        for signal in incident.correlation_match.signals:
            technique = _TECHNIQUES_BY_RULE_ID.get(signal.rule_id)
            if technique is None or technique.technique_id in seen_technique_ids:
                continue

            seen_technique_ids.add(technique.technique_id)
            techniques.append(technique)
            for tactic in technique.tactics:
                if tactic not in seen_tactics:
                    seen_tactics.add(tactic)
                    tactics.append(tactic)

        return MitreMapping(
            techniques=tuple(techniques),
            tactics=tuple(tactics),
        )
