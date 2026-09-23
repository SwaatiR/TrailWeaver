"""Provider-neutral attack graph models and incident graph construction."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from trailweaver.incidents import Incident
from trailweaver.models import Actor, JsonObject, NormalizedEvent
from trailweaver.signals import Signal

_LOGIN_WITHOUT_MFA = "aws.auth.console_login_without_mfa"
_ACCESS_KEY_CREATED = "aws.iam.access_key_created"
_ADMIN_POLICY_TO_USER = "aws.iam.admin_policy_attached_to_user"
_ADMIN_POLICY_TO_ROLE = "aws.iam.admin_policy_attached_to_role"
_CLOUDTRAIL_LOGGING_STOPPED = "aws.cloudtrail.logging_stopped"


class NodeType(StrEnum):
    """The supported categories of graph entities."""

    IDENTITY = "identity"
    CREDENTIAL = "credential"
    ROLE = "role"
    RESOURCE = "resource"
    SOURCE_IP = "source_ip"


class EdgeRelationship(StrEnum):
    """The small relationship vocabulary currently supported by the graph."""

    LOGGED_IN_FROM = "logged_in_from"
    AFFECTED = "affected"
    GRANTED = "granted"
    MODIFIED = "modified"


@dataclass(frozen=True, slots=True, kw_only=True)
class GraphNode:
    """A provider-neutral entity supported by normalized incident evidence."""

    node_id: str
    node_type: NodeType
    label: str
    provider: str
    metadata: JsonObject


@dataclass(frozen=True, slots=True, kw_only=True)
class GraphEdge:
    """A timestamped relationship backed by one signal occurrence."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship: EdgeRelationship
    timestamp: datetime
    signal_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackGraph:
    """An ordered collection of deduplicated graph nodes and edges."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


class AttackGraphBuilder:
    """Build a graph from normalized incident evidence without retaining state.

    Login relationships point from an identity to its observed source IP, so
    the edge reads as ``identity logged_in_from source_ip``. Nodes retain their
    first appearance and are deduplicated by deterministic node ID. Edges are
    deduplicated by a deterministic ID that includes the source signal
    occurrence. Access-key signals create no credential node until a normalized
    credential identifier is available; they only relate actor and target
    identities when both are supported by evidence.
    """

    def build(self, incident: Incident) -> AttackGraph:
        """Return a deterministic graph for the incident's correlated signals."""

        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        for signal in incident.correlation_match.signals:
            if signal.rule_id == _LOGIN_WITHOUT_MFA:
                self._add_login(signal, nodes, edges)
            elif signal.rule_id == _ACCESS_KEY_CREATED:
                self._add_access_key_creation(signal, nodes, edges)
            elif signal.rule_id == _ADMIN_POLICY_TO_USER:
                self._add_admin_user(signal, nodes, edges)
            elif signal.rule_id == _ADMIN_POLICY_TO_ROLE:
                self._add_admin_role(signal, nodes, edges)
            elif signal.rule_id == _CLOUDTRAIL_LOGGING_STOPPED:
                self._add_logging_stopped(signal, nodes, edges)

        return AttackGraph(nodes=tuple(nodes.values()), edges=tuple(edges.values()))

    def _add_login(
        self,
        signal: Signal,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
    ) -> None:
        event = signal.source_event
        actor_node = _actor_node(event)
        ip_node = _source_ip_node(event)
        _add_node(nodes, actor_node)
        _add_node(nodes, ip_node)
        _add_edge(edges, actor_node, ip_node, EdgeRelationship.LOGGED_IN_FROM, signal)

    def _add_access_key_creation(
        self,
        signal: Signal,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
    ) -> None:
        event = signal.source_event
        actor_node = _actor_node(event)
        target_user = _string_attribute(event, "target_user")
        target_node = (
            _target_user_node(event, target_user, actor_node)
            if target_user is not None
            else None
        )
        _add_node(nodes, actor_node)
        _add_node(nodes, target_node)
        _add_edge(edges, actor_node, target_node, EdgeRelationship.AFFECTED, signal)

    def _add_admin_user(
        self,
        signal: Signal,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
    ) -> None:
        event = signal.source_event
        actor_node = _actor_node(event)
        target_user = _string_attribute(event, "target_user")
        target_node = (
            _target_user_node(event, target_user, actor_node)
            if target_user is not None
            else None
        )
        _add_node(nodes, actor_node)
        _add_node(nodes, target_node)
        _add_edge(edges, actor_node, target_node, EdgeRelationship.GRANTED, signal)

    def _add_admin_role(
        self,
        signal: Signal,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
    ) -> None:
        event = signal.source_event
        actor_node = _actor_node(event)
        target_role = _string_attribute(event, "target_role")
        target_node = (
            _target_role_node(event, target_role)
            if target_role is not None
            else None
        )
        _add_node(nodes, actor_node)
        _add_node(nodes, target_node)
        _add_edge(edges, actor_node, target_node, EdgeRelationship.GRANTED, signal)

    def _add_logging_stopped(
        self,
        signal: Signal,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
    ) -> None:
        event = signal.source_event
        actor_node = _actor_node(event)
        trail_name = _string_attribute(event, "trail_name")
        trail_node = (
            _trail_node(event, trail_name) if trail_name is not None else None
        )
        _add_node(nodes, actor_node)
        _add_node(nodes, trail_node)
        _add_edge(edges, actor_node, trail_node, EdgeRelationship.MODIFIED, signal)


def _actor_node(event: NormalizedEvent) -> GraphNode | None:
    actor = event.actor
    if actor is None:
        return None

    identity = _actor_identity(actor)
    if identity is None:
        return None
    identity_type, identity_value = identity
    account_context = None if identity_type == "arn" else actor.account_id
    metadata: JsonObject = {}
    if actor.arn is not None:
        metadata["arn"] = actor.arn
    if actor.identifier is not None:
        metadata["identifier"] = actor.identifier
    if actor.account_id is not None:
        metadata["account_id"] = actor.account_id
    if actor.actor_type is not None:
        metadata["actor_type"] = actor.actor_type

    return GraphNode(
        node_id=_stable_id(
            NodeType.IDENTITY.value,
            event.provider,
            account_context,
            identity_type,
            identity_value,
        ),
        node_type=NodeType.IDENTITY,
        label=actor.name or actor.arn or actor.identifier or identity_value,
        provider=event.provider,
        metadata=metadata,
    )


def _actor_identity(actor: Actor) -> tuple[str, str] | None:
    identities = (("arn", actor.arn), ("identifier", actor.identifier), ("name", actor.name))
    for identity_type, value in identities:
        if value is not None and value.strip():
            return identity_type, value
    return None


def _source_ip_node(event: NormalizedEvent) -> GraphNode | None:
    if event.source_ip is None or not event.source_ip.strip():
        return None
    return GraphNode(
        node_id=_stable_id(NodeType.SOURCE_IP.value, event.provider, event.source_ip),
        node_type=NodeType.SOURCE_IP,
        label=event.source_ip,
        provider=event.provider,
        metadata={"ip": event.source_ip},
    )


def _target_user_node(
    event: NormalizedEvent, target_user: str, actor_node: GraphNode | None
) -> GraphNode:
    if event.actor is not None and event.actor.name == target_user and actor_node is not None:
        return actor_node

    account_id = event.actor.account_id if event.actor is not None else None
    metadata: JsonObject = {}
    if account_id is not None:
        metadata["account_id"] = account_id
    return GraphNode(
        node_id=_stable_id(
            NodeType.IDENTITY.value,
            event.provider,
            account_id,
            "name",
            target_user,
        ),
        node_type=NodeType.IDENTITY,
        label=target_user,
        provider=event.provider,
        metadata=metadata,
    )


def _target_role_node(event: NormalizedEvent, target_role: str) -> GraphNode:
    account_id = event.actor.account_id if event.actor is not None else None
    metadata: JsonObject = {}
    if account_id is not None:
        metadata["account_id"] = account_id
    return GraphNode(
        node_id=_stable_id(
            NodeType.ROLE.value,
            event.provider,
            account_id,
            "name",
            target_role,
        ),
        node_type=NodeType.ROLE,
        label=target_role,
        provider=event.provider,
        metadata=metadata,
    )


def _trail_node(event: NormalizedEvent, trail_name: str) -> GraphNode:
    account_id = event.actor.account_id if event.actor is not None else None
    metadata: JsonObject = {"resource_type": "cloud_audit_trail"}
    if account_id is not None:
        metadata["account_id"] = account_id
    if event.region is not None:
        metadata["region"] = event.region
    return GraphNode(
        node_id=_stable_id(
            NodeType.RESOURCE.value,
            event.provider,
            account_id,
            "cloud_audit_trail",
            trail_name,
        ),
        node_type=NodeType.RESOURCE,
        label=trail_name,
        provider=event.provider,
        metadata=metadata,
    )


def _string_attribute(event: NormalizedEvent, name: str) -> str | None:
    value = event.attributes.get(name)
    return value if isinstance(value, str) and value.strip() else None


def _add_node(nodes: dict[str, GraphNode], node: GraphNode | None) -> None:
    if node is not None:
        nodes.setdefault(node.node_id, node)


def _add_edge(
    edges: dict[str, GraphEdge],
    source: GraphNode | None,
    target: GraphNode | None,
    relationship: EdgeRelationship,
    signal: Signal,
) -> None:
    if source is None or target is None:
        return
    edge_id = _stable_id(
        "edge",
        source.node_id,
        target.node_id,
        relationship.value,
        signal.timestamp.isoformat(),
        signal.signal_id,
    )
    edges.setdefault(
        edge_id,
        GraphEdge(
            edge_id=edge_id,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relationship=relationship,
            timestamp=signal.timestamp,
            signal_id=signal.signal_id,
        ),
    )


def _stable_id(prefix: str, *parts: str | None) -> str:
    canonical = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"
