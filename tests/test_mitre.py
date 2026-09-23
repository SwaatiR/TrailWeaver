from datetime import UTC, datetime, timedelta

from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.mitre import MitreMapper
from trailweaver.models import JsonObject, NormalizedEvent
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
USER_ADMIN = "aws.iam.admin_policy_attached_to_user"
ROLE_ADMIN = "aws.iam.admin_policy_attached_to_role"
LOGGING_STOPPED = "aws.cloudtrail.logging_stopped"


def _signal(
    rule_id: str,
    *,
    minutes: int,
    raw_event: JsonObject | None = None,
) -> Signal:
    return Signal(
        signal_id=f"signal-{minutes}-{rule_id}",
        rule_id=rule_id,
        title=f"Signal for {rule_id}",
        description="A source signal for ATT&CK mapping tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider="aws",
            service="test",
            action="TestAction",
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=f"Normalized signal reason for {rule_id}.",
    )


def _incident(
    rule_ids: tuple[str, ...],
    *,
    raw_events: tuple[JsonObject, ...] | None = None,
) -> Incident:
    evidence = raw_events or tuple({} for _ in rule_ids)
    signals = tuple(
        _signal(rule_id, minutes=index, raw_event=evidence[index])
        for index, rule_id in enumerate(rule_ids)
    )
    correlation_match = CorrelationMatch(
        correlation_id="correlation-1",
        rule_id="aws.identity.possible_account_compromise_sequence",
        title="Possible AWS account compromise sequence",
        description="Related AWS identity-security activity was observed.",
        reason="The signals matched a suspicious sequence.",
        signals=signals,
    )
    return Incident(
        incident_id="incident-1",
        title="Possible AWS account compromise",
        description="Related identity-security events require investigation.",
        severity=SignalSeverity.HIGH,
        created_at=BASE_TIME + timedelta(minutes=20),
        correlation_match=correlation_match,
        summary="Possible account compromise activity was observed.",
    )


def test_login_rule_maps_to_cloud_accounts() -> None:
    mapping = MitreMapper().map(_incident((LOGIN,)))

    assert len(mapping.techniques) == 1
    assert mapping.techniques[0].technique_id == "T1078.004"
    assert mapping.techniques[0].name == "Cloud Accounts"


def test_access_key_rule_maps_to_additional_cloud_credentials() -> None:
    mapping = MitreMapper().map(_incident((ACCESS_KEY,)))

    assert len(mapping.techniques) == 1
    assert mapping.techniques[0].technique_id == "T1098.001"
    assert mapping.techniques[0].name == "Additional Cloud Credentials"


def test_admin_user_rule_maps_to_additional_cloud_roles() -> None:
    mapping = MitreMapper().map(_incident((USER_ADMIN,)))

    assert len(mapping.techniques) == 1
    assert mapping.techniques[0].technique_id == "T1098.003"
    assert mapping.techniques[0].name == "Additional Cloud Roles"


def test_admin_role_rule_maps_to_additional_cloud_roles() -> None:
    mapping = MitreMapper().map(_incident((ROLE_ADMIN,)))

    assert len(mapping.techniques) == 1
    assert mapping.techniques[0].technique_id == "T1098.003"
    assert mapping.techniques[0].name == "Additional Cloud Roles"


def test_cloudtrail_logging_stop_maps_to_disable_or_modify_cloud_log() -> None:
    mapping = MitreMapper().map(_incident((LOGGING_STOPPED,)))

    assert len(mapping.techniques) == 1
    assert mapping.techniques[0].technique_id == "T1685.002"
    assert mapping.techniques[0].name == "Disable or Modify Cloud Log"


def test_unknown_rule_ids_are_ignored() -> None:
    mapping = MitreMapper().map(_incident((LOGIN, "example.unknown", ACCESS_KEY)))

    assert tuple(technique.technique_id for technique in mapping.techniques) == (
        "T1078.004",
        "T1098.001",
    )


def test_duplicate_techniques_are_deduplicated() -> None:
    mapping = MitreMapper().map(
        _incident((USER_ADMIN, ROLE_ADMIN, USER_ADMIN, ROLE_ADMIN))
    )

    assert tuple(technique.technique_id for technique in mapping.techniques) == (
        "T1098.003",
    )


def test_tactics_are_deduplicated() -> None:
    mapping = MitreMapper().map(_incident((ACCESS_KEY, USER_ADMIN)))

    assert mapping.tactics == ("Persistence", "Privilege Escalation")


def test_ordering_follows_first_signal_appearance() -> None:
    mapping = MitreMapper().map(
        _incident((LOGGING_STOPPED, USER_ADMIN, LOGIN, ACCESS_KEY))
    )

    assert tuple(technique.technique_id for technique in mapping.techniques) == (
        "T1685.002",
        "T1098.003",
        "T1078.004",
        "T1098.001",
    )
    assert mapping.tactics == (
        "Defense Impairment",
        "Persistence",
        "Privilege Escalation",
        "Stealth",
        "Initial Access",
    )


def test_mapping_is_deterministic_across_repeated_calls() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, USER_ADMIN, LOGGING_STOPPED))
    mapper = MitreMapper()

    assert mapper.map(incident) == mapper.map(incident)


def test_mapping_does_not_mutate_incident() -> None:
    incident = _incident((LOGIN, ACCESS_KEY, USER_ADMIN))
    original_match = incident.correlation_match
    original_signals = incident.correlation_match.signals

    MitreMapper().map(incident)

    assert incident.correlation_match is original_match
    assert incident.correlation_match.signals is original_signals
    assert tuple(signal.rule_id for signal in original_signals) == (
        LOGIN,
        ACCESS_KEY,
        USER_ADMIN,
    )


def test_mapping_does_not_inspect_raw_event() -> None:
    raw_events: tuple[JsonObject, ...] = (
        {"rule_id": LOGGING_STOPPED},
        {"eventName": "StopLogging"},
        {"technique_id": "T1685.002"},
    )
    incident = _incident(
        (LOGIN, ACCESS_KEY, USER_ADMIN),
        raw_events=raw_events,
    )

    mapping = MitreMapper().map(incident)

    assert tuple(technique.technique_id for technique in mapping.techniques) == (
        "T1078.004",
        "T1098.001",
        "T1098.003",
    )


def test_unknown_only_incident_returns_empty_mapping() -> None:
    mapping = MitreMapper().map(_incident(("example.unknown",)))

    assert mapping.techniques == ()
    assert mapping.tactics == ()


def test_technique_ids_names_and_tactics_match_documented_values() -> None:
    mapping = MitreMapper().map(
        _incident((LOGIN, ACCESS_KEY, USER_ADMIN, ROLE_ADMIN, LOGGING_STOPPED))
    )

    assert tuple(
        (technique.technique_id, technique.name, technique.tactics)
        for technique in mapping.techniques
    ) == (
        (
            "T1078.004",
            "Cloud Accounts",
            ("Stealth", "Persistence", "Privilege Escalation", "Initial Access"),
        ),
        (
            "T1098.001",
            "Additional Cloud Credentials",
            ("Persistence", "Privilege Escalation"),
        ),
        (
            "T1098.003",
            "Additional Cloud Roles",
            ("Persistence", "Privilege Escalation"),
        ),
        (
            "T1685.002",
            "Disable or Modify Cloud Log",
            ("Defense Impairment",),
        ),
    )


def test_technique_descriptions_use_cautious_behavioral_wording() -> None:
    mapping = MitreMapper().map(
        _incident((LOGIN, ACCESS_KEY, USER_ADMIN, LOGGING_STOPPED))
    )

    assert all(
        technique.description.startswith("Observed ")
        for technique in mapping.techniques
    )
    assert all("attacker" not in technique.description for technique in mapping.techniques)
