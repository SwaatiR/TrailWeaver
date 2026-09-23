from datetime import UTC, datetime

import pytest

from trailweaver.cloudtrail import CloudTrailParseError, parse_cloudtrail_event
from trailweaver.models import EventOutcome, JsonObject, JsonValue


def _event(**overrides: JsonValue) -> JsonObject:
    event: JsonObject = {
        "eventVersion": "1.11",
        "eventTime": "2026-09-23T10:30:45Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
    }
    event.update(overrides)
    return event


def test_parse_iam_user_event() -> None:
    raw_event = _event(
        awsRegion="us-east-1",
        sourceIPAddress="192.0.2.10",
        userIdentity={
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
            "userName": "alice",
        },
    )

    event = parse_cloudtrail_event(raw_event)

    assert event.timestamp == datetime(2026, 9, 23, 10, 30, 45, tzinfo=UTC)
    assert event.provider == "aws"
    assert event.service == "iam"
    assert event.action == "CreateAccessKey"
    assert event.region == "us-east-1"
    assert event.source_ip == "192.0.2.10"
    assert event.actor is not None
    assert event.actor.actor_type == "IAMUser"
    assert event.actor.identifier == "AIDAEXAMPLE"
    assert event.actor.name == "alice"
    assert event.actor.arn == "arn:aws:iam::123456789012:user/alice"
    assert event.actor.account_id == "123456789012"


def test_parse_assumed_role_prefers_stable_session_issuer() -> None:
    raw_event = _event(
        eventSource="ec2.amazonaws.com",
        eventName="RunInstances",
        userIdentity={
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE:deployment-session",
            "arn": "arn:aws:sts::123456789012:assumed-role/DeploymentRole/deployment-session",
            "accountId": "123456789012",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAEXAMPLE",
                    "arn": "arn:aws:iam::123456789012:role/DeploymentRole",
                    "accountId": "123456789012",
                    "userName": "DeploymentRole",
                }
            },
        },
    )

    event = parse_cloudtrail_event(raw_event)

    assert event.actor is not None
    assert event.actor.actor_type == "AssumedRole"
    assert event.actor.identifier == "AROAEXAMPLE"
    assert event.actor.name == "DeploymentRole"
    assert event.actor.arn == "arn:aws:iam::123456789012:role/DeploymentRole"
    assert event.actor.account_id == "123456789012"


def test_parse_event_with_optional_fields_absent() -> None:
    event = parse_cloudtrail_event(_event())

    assert event.region is None
    assert event.source_ip is None
    assert event.actor is None
    assert event.resources == ()


def test_parse_multiple_top_level_resources() -> None:
    raw_event = _event(
        resources=[
            {
                "type": "AWS::EC2::Instance",
                "ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
                "accountId": "123456789012",
            },
            {
                "type": "AWS::EC2::SecurityGroup",
                "ARN": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
                "accountId": "123456789012",
            },
            {},
        ]
    )

    event = parse_cloudtrail_event(raw_event)

    assert len(event.resources) == 2
    assert event.resources[0].resource_type == "AWS::EC2::Instance"
    assert event.resources[0].identifier is None
    assert event.resources[0].arn == (
        "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"
    )
    assert event.resources[0].account_id == "123456789012"
    assert event.resources[0].region is None
    assert event.resources[1].resource_type == "AWS::EC2::SecurityGroup"


@pytest.mark.parametrize("event_time", [None, "not-a-timestamp", "2026-09-23T10:30:45"])
def test_invalid_or_missing_event_time_raises_parser_error(event_time: JsonValue) -> None:
    raw_event = _event()
    if event_time is None:
        del raw_event["eventTime"]
    else:
        raw_event["eventTime"] = event_time

    with pytest.raises(CloudTrailParseError, match="eventTime"):
        parse_cloudtrail_event(raw_event)


@pytest.mark.parametrize(
    ("event_source", "expected_service"),
    [
        ("iam.amazonaws.com", "iam"),
        ("s3.amazonaws.com", "s3"),
        ("ec2.amazonaws.com", "ec2"),
    ],
)
def test_normalize_service(event_source: str, expected_service: str) -> None:
    event = parse_cloudtrail_event(_event(eventSource=event_source))

    assert event.service == expected_service


def test_preserve_raw_event() -> None:
    raw_event = _event(requestParameters={"userName": "alice"})

    event = parse_cloudtrail_event(raw_event)

    assert event.raw_event is raw_event


def test_parse_aws_service_identity() -> None:
    raw_event = _event(
        userIdentity={
            "type": "AWSService",
            "invokedBy": "config.amazonaws.com",
        }
    )

    event = parse_cloudtrail_event(raw_event)

    assert event.actor is not None
    assert event.actor.actor_type == "AWSService"
    assert event.actor.identifier == "config.amazonaws.com"
    assert event.actor.name == "config.amazonaws.com"


def test_parse_root_identity_without_inventing_name() -> None:
    raw_event = _event(
        userIdentity={
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
        }
    )

    event = parse_cloudtrail_event(raw_event)

    assert event.actor is not None
    assert event.actor.actor_type == "Root"
    assert event.actor.identifier == "123456789012"
    assert event.actor.name is None


def test_successful_api_event_outcome() -> None:
    event = parse_cloudtrail_event(_event(responseElements={"accessKey": {}}))

    assert event.outcome is EventOutcome.SUCCESS
    assert event.error_code is None
    assert event.error_message is None


def test_failed_api_event_outcome_and_error_details() -> None:
    event = parse_cloudtrail_event(
        _event(
            errorCode="AccessDenied",
            errorMessage="User is not authorized to perform this action",
        )
    )

    assert event.outcome is EventOutcome.FAILURE
    assert event.error_code == "AccessDenied"
    assert event.error_message == "User is not authorized to perform this action"


def test_extract_event_id() -> None:
    event = parse_cloudtrail_event(_event(eventID="5f1335c1-4de2-4ad7-a759-17b2example"))

    assert event.event_id == "5f1335c1-4de2-4ad7-a759-17b2example"


def test_console_login_extracts_mfa_context() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventSource="signin.amazonaws.com",
            eventName="ConsoleLogin",
            additionalEventData={"MFAUsed": "Yes", "MobileVersion": "No"},
        )
    )

    assert event.attributes == {"mfa_used": True}


def test_console_login_without_mfa_context_does_not_invent_it() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventSource="signin.amazonaws.com",
            eventName="ConsoleLogin",
            additionalEventData={"MobileVersion": "No"},
        )
    )

    assert event.attributes == {}


def test_attach_user_policy_extracts_security_attributes() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventName="AttachUserPolicy",
            requestParameters={
                "userName": "alice",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        )
    )

    assert event.attributes == {
        "target_user": "alice",
        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
    }


def test_attach_role_policy_extracts_security_attributes() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventName="AttachRolePolicy",
            requestParameters={
                "roleName": "DeploymentRole",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        )
    )

    assert event.attributes == {
        "target_role": "DeploymentRole",
        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
    }


def test_create_access_key_extracts_target_user() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventName="CreateAccessKey",
            requestParameters={"userName": "alice"},
        )
    )

    assert event.attributes == {"target_user": "alice"}


@pytest.mark.parametrize("action", ["StopLogging", "DeleteTrail"])
def test_trail_action_extracts_target_name(action: str) -> None:
    event = parse_cloudtrail_event(
        _event(
            eventSource="cloudtrail.amazonaws.com",
            eventName=action,
            requestParameters={"name": "security-audit-trail"},
        )
    )

    assert event.attributes == {"trail_name": "security-audit-trail"}


def test_unrelated_request_parameters_are_not_copied() -> None:
    event = parse_cloudtrail_event(
        _event(
            eventSource="ec2.amazonaws.com",
            eventName="RunInstances",
            requestParameters={
                "imageId": "ami-0123456789abcdef0",
                "instanceType": "t3.micro",
            },
        )
    )

    assert event.attributes == {}
