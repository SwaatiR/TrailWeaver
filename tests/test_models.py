from datetime import UTC, datetime

from trailweaver.models import Actor, EventOutcome, NormalizedEvent, Resource


def test_construct_complete_event() -> None:
    timestamp = datetime(2026, 9, 23, 10, 30, tzinfo=UTC)
    actor = Actor(
        actor_type="user",
        identifier="AIDAEXAMPLE",
        name="security-admin",
        arn="arn:example:iam::123456789012:user/security-admin",
        account_id="123456789012",
    )
    resource = Resource(
        resource_type="object-store",
        identifier="audit-archive",
        arn="arn:example:storage:::audit-archive",
        account_id="123456789012",
        region="example-region-1",
    )

    event = NormalizedEvent(
        timestamp=timestamp,
        provider="example-cloud",
        service="object-storage",
        action="DeleteContainer",
        region="example-region-1",
        source_ip="192.0.2.10",
        actor=actor,
        resources=(resource,),
        raw_event={"event_id": "event-123"},
    )

    assert event.timestamp == timestamp
    assert event.provider == "example-cloud"
    assert event.service == "object-storage"
    assert event.action == "DeleteContainer"
    assert event.region == "example-region-1"
    assert event.source_ip == "192.0.2.10"
    assert event.actor == actor
    assert event.resources == (resource,)


def test_construct_event_with_optional_fields_absent() -> None:
    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 23, tzinfo=UTC),
        provider="example-cloud",
        service="identity",
        action="Authenticate",
        raw_event={},
    )

    assert event.region is None
    assert event.source_ip is None
    assert event.actor is None
    assert event.resources == ()
    assert event.event_id is None
    assert event.outcome is EventOutcome.UNKNOWN
    assert event.error_code is None
    assert event.error_message is None
    assert event.attributes == {}


def test_event_supports_multiple_resources() -> None:
    first = Resource(resource_type="compute-instance", identifier="instance-1")
    second = Resource(resource_type="network-interface", identifier="interface-1")

    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 23, tzinfo=UTC),
        provider="example-cloud",
        service="compute",
        action="AttachNetworkInterface",
        resources=(first, second),
        raw_event={},
    )

    assert event.resources == (first, second)


def test_event_preserves_raw_event() -> None:
    raw_event = {
        "request": {"enabled": True, "tags": ["security", "audit"]},
        "response": None,
    }

    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 23, tzinfo=UTC),
        provider="example-cloud",
        service="configuration",
        action="UpdateSetting",
        raw_event=raw_event,
    )

    assert event.raw_event is raw_event
