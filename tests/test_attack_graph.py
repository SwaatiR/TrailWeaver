from datetime import UTC, datetime, timedelta

from trailweaver.attack_graph import (
    AttackGraph,
    AttackGraphBuilder,
    EdgeRelationship,
    GraphNode,
    NodeType,
)
from trailweaver.correlation import CorrelationMatch
from trailweaver.incidents import Incident
from trailweaver.models import Actor, JsonObject, NormalizedEvent, SecurityAttributes
from trailweaver.signals import Signal, SignalSeverity

BASE_TIME = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
LOGIN = "aws.auth.console_login_without_mfa"
ACCESS_KEY = "aws.iam.access_key_created"
USER_ADMIN = "aws.iam.admin_policy_attached_to_user"
ROLE_ADMIN = "aws.iam.admin_policy_attached_to_role"
LOGGING_STOPPED = "aws.cloudtrail.logging_stopped"
ACTOR = Actor(
    actor_type="IAMUser",
    identifier="AIDAALICE",
    name="alice",
    arn="arn:aws:iam::123456789012:user/alice",
    account_id="123456789012",
)


def _signal(
    rule_id: str,
    *,
    minutes: int = 0,
    actor: Actor | None = ACTOR,
    source_ip: str | None = None,
    attributes: SecurityAttributes | None = None,
    raw_event: JsonObject | None = None,
    signal_id: str | None = None,
    provider: str = "aws",
    region: str | None = "us-east-1",
) -> Signal:
    return Signal(
        signal_id=signal_id or f"signal-{minutes}-{rule_id}",
        rule_id=rule_id,
        title=f"Signal for {rule_id}",
        description="A source signal for attack graph tests.",
        severity=SignalSeverity.MEDIUM,
        source_event=NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=minutes),
            provider=provider,
            service="test",
            action="TestAction",
            region=region,
            source_ip=source_ip,
            actor=actor,
            attributes={} if attributes is None else attributes,
            raw_event={} if raw_event is None else raw_event,
        ),
        reason=f"Normalized signal reason for {rule_id}.",
    )


def _incident(*signals: Signal) -> Incident:
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


def _nodes_of_type(graph: AttackGraph, node_type: NodeType) -> tuple[GraphNode, ...]:
    return tuple(node for node in graph.nodes if node.node_type is node_type)


def test_incident_creates_attack_graph() -> None:
    incident = _incident(_signal(LOGIN, source_ip="192.0.2.10"))

    graph = AttackGraphBuilder().build(incident)

    assert isinstance(graph, AttackGraph)
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1


def test_repeated_actor_references_create_one_identity_node() -> None:
    incident = _incident(
        _signal(LOGIN, source_ip="192.0.2.10"),
        _signal(ACCESS_KEY, minutes=1, attributes={"target_user": "alice"}),
        _signal(USER_ADMIN, minutes=2, attributes={"target_user": "alice"}),
    )

    graph = AttackGraphBuilder().build(incident)

    assert len(_nodes_of_type(graph, NodeType.IDENTITY)) == 1


def test_actor_node_id_is_deterministic() -> None:
    incident = _incident(_signal(LOGIN))
    builder = AttackGraphBuilder()

    first = _nodes_of_type(builder.build(incident), NodeType.IDENTITY)[0]
    second = _nodes_of_type(builder.build(incident), NodeType.IDENTITY)[0]

    assert first.node_id == second.node_id


def test_actor_arn_is_preferred_for_node_stability() -> None:
    arn = "arn:aws:iam::123456789012:user/alice"
    first_actor = Actor(arn=arn, identifier="first-id", name="first")
    second_actor = Actor(arn=arn, identifier="second-id", name="second")

    first = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=first_actor)))
    second = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=second_actor)))

    assert first.nodes[0].node_id == second.nodes[0].node_id


def test_actor_identifier_fallback_is_deterministic() -> None:
    first_actor = Actor(identifier="AIDAEXAMPLE", name="first", account_id="123")
    second_actor = Actor(identifier="AIDAEXAMPLE", name="second", account_id="123")

    first = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=first_actor)))
    second = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=second_actor)))

    assert first.nodes[0].node_id == second.nodes[0].node_id


def test_actor_name_fallback_is_deterministic() -> None:
    actor = Actor(name="alice", account_id="123456789012")

    first = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=actor)))
    second = AttackGraphBuilder().build(_incident(_signal(LOGIN, actor=actor)))

    assert first.nodes[0].node_id == second.nodes[0].node_id
    assert first.nodes[0].label == "alice"


def test_source_ip_node_is_created_when_available() -> None:
    graph = AttackGraphBuilder().build(
        _incident(_signal(LOGIN, source_ip="192.0.2.10"))
    )

    ip_node = _nodes_of_type(graph, NodeType.SOURCE_IP)[0]
    assert ip_node.label == "192.0.2.10"
    assert ip_node.metadata == {"ip": "192.0.2.10"}


def test_missing_source_ip_does_not_create_fake_node() -> None:
    graph = AttackGraphBuilder().build(_incident(_signal(LOGIN)))

    assert _nodes_of_type(graph, NodeType.SOURCE_IP) == ()
    assert graph.edges == ()


def test_login_relationship_is_identity_to_source_ip() -> None:
    graph = AttackGraphBuilder().build(
        _incident(_signal(LOGIN, source_ip="192.0.2.10"))
    )
    identity = _nodes_of_type(graph, NodeType.IDENTITY)[0]
    source_ip = _nodes_of_type(graph, NodeType.SOURCE_IP)[0]

    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source_node_id == identity.node_id
    assert edge.target_node_id == source_ip.node_id
    assert edge.relationship is EdgeRelationship.LOGGED_IN_FROM


def test_admin_target_user_is_represented() -> None:
    graph = AttackGraphBuilder().build(
        _incident(_signal(USER_ADMIN, attributes={"target_user": "bob"}))
    )

    target = next(node for node in graph.nodes if node.label == "bob")
    assert target.node_type is NodeType.IDENTITY
    assert graph.edges[0].target_node_id == target.node_id
    assert graph.edges[0].relationship is EdgeRelationship.GRANTED


def test_admin_target_role_is_represented() -> None:
    graph = AttackGraphBuilder().build(
        _incident(_signal(ROLE_ADMIN, attributes={"target_role": "DeploymentRole"}))
    )

    target = next(node for node in graph.nodes if node.label == "DeploymentRole")
    assert target.node_type is NodeType.ROLE
    assert graph.edges[0].target_node_id == target.node_id
    assert graph.edges[0].relationship is EdgeRelationship.GRANTED


def test_missing_admin_target_does_not_invent_node() -> None:
    graph = AttackGraphBuilder().build(_incident(_signal(USER_ADMIN)))

    assert len(graph.nodes) == 1
    assert graph.nodes[0].node_type is NodeType.IDENTITY
    assert graph.edges == ()


def test_trail_resource_is_represented_when_name_exists() -> None:
    graph = AttackGraphBuilder().build(
        _incident(
            _signal(
                LOGGING_STOPPED,
                attributes={"trail_name": "security-audit"},
            )
        )
    )

    trail = _nodes_of_type(graph, NodeType.RESOURCE)[0]
    assert trail.label == "security-audit"
    assert trail.metadata == {
        "resource_type": "cloud_audit_trail",
        "account_id": "123456789012",
        "region": "us-east-1",
    }
    assert graph.edges[0].relationship is EdgeRelationship.MODIFIED


def test_node_deduplication_preserves_first_appearance() -> None:
    graph = AttackGraphBuilder().build(
        _incident(
            _signal(LOGIN, source_ip="192.0.2.10", signal_id="login-1"),
            _signal(
                LOGIN,
                minutes=1,
                source_ip="192.0.2.10",
                signal_id="login-2",
            ),
        )
    )

    assert tuple(node.node_type for node in graph.nodes) == (
        NodeType.IDENTITY,
        NodeType.SOURCE_IP,
    )


def test_edge_deduplication_removes_repeated_same_evidence() -> None:
    login = _signal(LOGIN, source_ip="192.0.2.10", signal_id="login-1")

    graph = AttackGraphBuilder().build(_incident(login, login))

    assert len(graph.edges) == 1
    assert graph.edges[0].signal_id == "login-1"


def test_node_and_edge_order_follow_signal_chronology() -> None:
    incident = _incident(
        _signal(LOGIN, source_ip="192.0.2.10"),
        _signal(
            ROLE_ADMIN,
            minutes=1,
            attributes={"target_role": "DeploymentRole"},
        ),
        _signal(
            LOGGING_STOPPED,
            minutes=2,
            attributes={"trail_name": "security-audit"},
        ),
    )

    graph = AttackGraphBuilder().build(incident)

    assert tuple(node.label for node in graph.nodes) == (
        "alice",
        "192.0.2.10",
        "DeploymentRole",
        "security-audit",
    )
    assert tuple(edge.relationship for edge in graph.edges) == (
        EdgeRelationship.LOGGED_IN_FROM,
        EdgeRelationship.GRANTED,
        EdgeRelationship.MODIFIED,
    )


def test_graph_construction_does_not_inspect_raw_event() -> None:
    raw_event: JsonObject = {
        "sourceIPAddress": "198.51.100.20",
        "userIdentity": {"arn": "arn:aws:iam::999999999999:user/raw"},
        "requestParameters": {"trail_name": "raw-trail"},
    }
    incident = _incident(
        _signal(
            LOGIN,
            actor=None,
            source_ip=None,
            raw_event=raw_event,
        )
    )

    graph = AttackGraphBuilder().build(incident)

    assert graph == AttackGraph(nodes=(), edges=())


def test_same_incident_produces_identical_graph_repeatedly() -> None:
    incident = _incident(
        _signal(LOGIN, source_ip="192.0.2.10"),
        _signal(ACCESS_KEY, minutes=1, attributes={"target_user": "alice"}),
        _signal(USER_ADMIN, minutes=2, attributes={"target_user": "alice"}),
    )
    builder = AttackGraphBuilder()

    assert builder.build(incident) == builder.build(incident)


def test_unknown_only_incident_produces_valid_empty_graph() -> None:
    graph = AttackGraphBuilder().build(_incident(_signal("example.unknown")))

    assert graph == AttackGraph(nodes=(), edges=())


def test_access_key_without_key_id_does_not_invent_credential_node() -> None:
    graph = AttackGraphBuilder().build(
        _incident(_signal(ACCESS_KEY, attributes={"target_user": "bob"}))
    )

    assert _nodes_of_type(graph, NodeType.CREDENTIAL) == ()
    assert tuple(node.label for node in graph.nodes) == ("alice", "bob")
    assert graph.edges[0].relationship is EdgeRelationship.AFFECTED
