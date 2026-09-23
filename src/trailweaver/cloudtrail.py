"""Convert AWS CloudTrail events into TrailWeaver's normalized model."""

from datetime import datetime

from trailweaver.models import (
    Actor,
    EventOutcome,
    JsonObject,
    JsonValue,
    NormalizedEvent,
    Resource,
    SecurityAttributes,
)


class CloudTrailParseError(ValueError):
    """Raised when required CloudTrail data cannot be parsed."""


def parse_cloudtrail_event(event: JsonObject) -> NormalizedEvent:
    """Convert one CloudTrail event dictionary into a normalized event.

    The presence of ``errorCode`` marks the event as a failure. A recorded
    event without one is treated as successful; other response fields do not
    affect the outcome.
    """

    timestamp = _parse_timestamp(event.get("eventTime"))
    event_source = _required_string(event, "eventSource")
    action = _required_string(event, "eventName")
    service = _normalize_service(event_source)
    error_code = _optional_string(event, "errorCode")

    return NormalizedEvent(
        timestamp=timestamp,
        provider="aws",
        service=service,
        action=action,
        event_id=_optional_string(event, "eventID"),
        outcome=EventOutcome.FAILURE if "errorCode" in event else EventOutcome.SUCCESS,
        error_code=error_code,
        error_message=_optional_string(event, "errorMessage"),
        region=_optional_string(event, "awsRegion"),
        source_ip=_optional_string(event, "sourceIPAddress"),
        actor=_parse_actor(event.get("userIdentity")),
        resources=_parse_resources(event.get("resources")),
        attributes=_parse_security_attributes(event, service, action),
        raw_event=event,
    )


def _parse_timestamp(value: JsonValue | None) -> datetime:
    if not isinstance(value, str) or not value:
        raise CloudTrailParseError(
            "CloudTrail event is missing required string field 'eventTime'"
        )

    timestamp_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value

    try:
        timestamp = datetime.fromisoformat(timestamp_value)
    except ValueError as error:
        raise CloudTrailParseError(f"Invalid CloudTrail eventTime: {value!r}") from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise CloudTrailParseError(f"CloudTrail eventTime must include a timezone: {value!r}")

    return timestamp


def _required_string(event: JsonObject, field: str) -> str:
    value = _optional_string(event, field)
    if value is None:
        raise CloudTrailParseError(
            f"CloudTrail event is missing required string field {field!r}"
        )
    return value


def _optional_string(value: JsonObject, field: str) -> str | None:
    candidate = value.get(field)
    return candidate if isinstance(candidate, str) and candidate else None


def _normalize_service(event_source: str) -> str:
    return event_source.removesuffix(".amazonaws.com")


def _parse_security_attributes(
    event: JsonObject, service: str, action: str
) -> SecurityAttributes:
    attributes: SecurityAttributes = {}

    if service == "signin" and action == "ConsoleLogin":
        additional_data = _as_object(event.get("additionalEventData"))
        if additional_data is not None:
            mfa_used = _optional_string(additional_data, "MFAUsed")
            if mfa_used == "Yes":
                attributes["mfa_used"] = True
            elif mfa_used == "No":
                attributes["mfa_used"] = False
        return attributes

    request_parameters = _as_object(event.get("requestParameters"))
    if request_parameters is None:
        return attributes

    if service == "iam":
        if action == "AttachUserPolicy":
            _copy_string_attribute(
                attributes, "target_user", request_parameters, "userName"
            )
            _copy_string_attribute(
                attributes, "policy_arn", request_parameters, "policyArn"
            )
        elif action == "AttachRolePolicy":
            _copy_string_attribute(
                attributes, "target_role", request_parameters, "roleName"
            )
            _copy_string_attribute(
                attributes, "policy_arn", request_parameters, "policyArn"
            )
        elif action == "CreateAccessKey":
            _copy_string_attribute(
                attributes, "target_user", request_parameters, "userName"
            )
    elif service == "cloudtrail" and action in {"StopLogging", "DeleteTrail"}:
        _copy_string_attribute(attributes, "trail_name", request_parameters, "name")

    return attributes


def _copy_string_attribute(
    attributes: SecurityAttributes,
    attribute_name: str,
    source: JsonObject,
    source_name: str,
) -> None:
    value = _optional_string(source, source_name)
    if value is not None:
        attributes[attribute_name] = value


def _parse_actor(value: JsonValue | None) -> Actor | None:
    identity = _as_object(value)
    if identity is None:
        return None

    actor_type = _optional_string(identity, "type")
    identifier = _optional_string(identity, "principalId")
    name = _optional_string(identity, "userName")
    arn = _optional_string(identity, "arn")
    account_id = _optional_string(identity, "accountId")

    if actor_type == "AssumedRole":
        session_context = _as_object(identity.get("sessionContext"))
        session_issuer = (
            _as_object(session_context.get("sessionIssuer"))
            if session_context is not None
            else None
        )
        if session_issuer is not None:
            identifier = _optional_string(session_issuer, "principalId") or identifier
            name = _optional_string(session_issuer, "userName") or name
            arn = _optional_string(session_issuer, "arn") or arn
            account_id = _optional_string(session_issuer, "accountId") or account_id
    elif actor_type == "AWSService":
        invoked_by = _optional_string(identity, "invokedBy")
        identifier = identifier or invoked_by
        name = name or invoked_by

    if all(item is None for item in (actor_type, identifier, name, arn, account_id)):
        return None

    return Actor(
        actor_type=actor_type,
        identifier=identifier,
        name=name,
        arn=arn,
        account_id=account_id,
    )


def _parse_resources(value: JsonValue | None) -> tuple[Resource, ...]:
    if not isinstance(value, list):
        return ()

    resources: list[Resource] = []
    for item in value:
        resource = _parse_resource(item)
        if resource is not None:
            resources.append(resource)

    return tuple(resources)


def _parse_resource(value: JsonValue) -> Resource | None:
    item = _as_object(value)
    if item is None:
        return None

    resource_type = _optional_string(item, "type")
    identifier = _first_string(item, "resourceId", "resourceName", "identifier")
    arn = _first_string(item, "ARN", "arn")
    account_id = _optional_string(item, "accountId")
    region = _first_string(item, "region", "awsRegion")

    if all(
        field is None
        for field in (resource_type, identifier, arn, account_id, region)
    ):
        return None

    return Resource(
        resource_type=resource_type,
        identifier=identifier,
        arn=arn,
        account_id=account_id,
        region=region,
    )


def _first_string(value: JsonObject, *fields: str) -> str | None:
    for field in fields:
        candidate = _optional_string(value, field)
        if candidate is not None:
            return candidate
    return None


def _as_object(value: JsonValue | None) -> JsonObject | None:
    return value if isinstance(value, dict) else None
