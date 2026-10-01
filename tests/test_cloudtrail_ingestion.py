import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import trailweaver.cloudtrail_ingestion as ingestion_module
from trailweaver.cloudtrail_ingestion import (
    CloudTrailEnvelopeError,
    CloudTrailIngestionIssueCode,
    CloudTrailInvalidJsonError,
    CloudTrailSourceDecodeError,
    CloudTrailSourceReadError,
    CloudTrailSourceTooLargeError,
    ingest_cloudtrail_document,
    ingest_cloudtrail_file,
    ingest_cloudtrail_json,
)
from trailweaver.models import JsonObject, JsonValue

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"


def _record(**overrides: JsonValue) -> JsonObject:
    record: JsonObject = {
        "eventVersion": "1.11",
        "eventTime": "2026-09-23T10:30:45Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "eventID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    }
    record.update(overrides)
    return record


def test_ingest_valid_standard_cloudtrail_envelope() -> None:
    result = ingest_cloudtrail_document({"Records": [_record()]})

    assert result.total_records == 1
    assert result.accepted_records == 1
    assert result.failed_records == 0
    assert result.duplicate_records == 0
    assert result.issues == ()
    assert result.events[0].service == "iam"
    assert result.events[0].action == "CreateAccessKey"


def test_ingest_valid_json_text() -> None:
    source = json.dumps({"Records": [_record(eventName="AttachUserPolicy")]})

    result = ingest_cloudtrail_json(source)

    assert [event.action for event in result.events] == ["AttachUserPolicy"]


def test_ingest_valid_utf8_bytes() -> None:
    source = json.dumps({"Records": [_record()]}).encode("utf-8")

    result = ingest_cloudtrail_json(source)

    assert result.accepted_records == 1


def test_file_adapter_reads_fixture_without_modifying_source(tmp_path: Path) -> None:
    source_path = tmp_path / "cloudtrail-export.json"
    original = (SAMPLES / "valid-multi-record.json").read_bytes()
    source_path.write_bytes(original)
    original_mtime = source_path.stat().st_mtime_ns

    result = ingest_cloudtrail_file(source_path)

    assert result.accepted_records == 3
    assert result.source_label == "cloudtrail-export.json"
    assert source_path.read_bytes() == original
    assert source_path.stat().st_mtime_ns == original_mtime


def test_empty_records_is_successful() -> None:
    result = ingest_cloudtrail_file(SAMPLES / "empty-records.json")

    assert result.total_records == 0
    assert result.events == ()
    assert result.issues == ()
    assert result.accepted_records == result.failed_records == result.duplicate_records == 0


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({}, "missing 'Records'"),
        ({"Records": {}}, "must be an array"),
        ([], "must be a JSON object"),
    ],
)
def test_invalid_envelopes_are_rejected(document: JsonValue, message: str) -> None:
    with pytest.raises(CloudTrailEnvelopeError, match=message):
        ingest_cloudtrail_document(document)


def test_invalid_json_is_document_failure_without_decoder_details() -> None:
    with pytest.raises(CloudTrailInvalidJsonError) as captured:
        ingest_cloudtrail_json('{"Records": [}')

    assert str(captured.value) == "CloudTrail source is not a valid JSON document"
    assert "line" not in str(captured.value)


def test_invalid_utf8_is_document_failure() -> None:
    with pytest.raises(CloudTrailSourceDecodeError, match="not valid UTF-8"):
        ingest_cloudtrail_json(b'{"Records": []}\xff')


def test_mixed_records_produce_partial_success_and_indexed_issues() -> None:
    result = ingest_cloudtrail_file(SAMPLES / "mixed-records.json")

    assert result.total_records == 4
    assert result.accepted_records == 2
    assert result.failed_records == 2
    assert result.duplicate_records == 0
    assert [issue.record_index for issue in result.issues] == [1, 2]
    assert [issue.code for issue in result.issues] == [
        CloudTrailIngestionIssueCode.INVALID_RECORD_TYPE,
        CloudTrailIngestionIssueCode.PARSER_REJECTED_RECORD,
    ]
    assert result.issues[1].event_id == "55555555-5555-4555-8555-555555555555"


def test_parser_rejection_message_does_not_repeat_raw_field_value() -> None:
    sensitive_value = "do-not-repeat-this-source-value"
    result = ingest_cloudtrail_document(
        {"Records": [_record(eventTime=sensitive_value)]}
    )

    assert result.failed_records == 1
    assert result.issues[0].code is CloudTrailIngestionIssueCode.PARSER_REJECTED_RECORD
    assert sensitive_value not in result.issues[0].message


def test_duplicate_event_id_keeps_first_and_is_not_a_failure() -> None:
    result = ingest_cloudtrail_file(SAMPLES / "duplicate-event-id.json")

    assert result.total_records == 2
    assert result.accepted_records == 1
    assert result.failed_records == 0
    assert result.duplicate_records == 1
    assert result.events[0].action == "CreateAccessKey"
    assert result.issues[0].record_index == 1
    assert result.issues[0].code is CloudTrailIngestionIssueCode.DUPLICATE_EVENT
    assert result.issues[0].event_id == "77777777-7777-4777-8777-777777777777"


def test_events_without_ids_are_not_falsely_deduplicated() -> None:
    first = _record(eventName="CreateAccessKey")
    second = _record(eventName="DeleteAccessKey")
    del first["eventID"]
    del second["eventID"]

    result = ingest_cloudtrail_document({"Records": [first, second]})

    assert result.accepted_records == 2
    assert result.duplicate_records == 0
    assert [event.event_id for event in result.events] == [None, None]


def test_same_timestamp_with_distinct_ids_and_source_order_are_preserved() -> None:
    result = ingest_cloudtrail_file(SAMPLES / "valid-multi-record.json")

    assert [event.event_id for event in result.events] == [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    ]
    assert result.events[0].timestamp > result.events[1].timestamp
    assert result.events[1].timestamp == result.events[2].timestamp


def test_failed_records_do_not_reorder_remaining_events() -> None:
    result = ingest_cloudtrail_file(SAMPLES / "mixed-records.json")

    assert [event.event_id for event in result.events] == [
        "44444444-4444-4444-8444-444444444444",
        "66666666-6666-4666-8666-666666666666",
    ]


def test_source_label_is_result_provenance_not_domain_provenance() -> None:
    result = ingest_cloudtrail_document(
        {"Records": [_record()]}, source_label="upload-42"
    )

    assert result.source_label == "upload-42"
    assert not hasattr(result.events[0], "source_label")


def test_file_adapter_uses_explicit_logical_label() -> None:
    result = ingest_cloudtrail_file(
        SAMPLES / "empty-records.json", source_label="s3-object-123"
    )

    assert result.source_label == "s3-object-123"


def test_parser_raw_event_behavior_is_preserved() -> None:
    raw_record = _record(requestParameters={"userName": "alice"})

    result = ingest_cloudtrail_document({"Records": [raw_record]})

    assert result.events[0].raw_event is raw_record


def test_source_size_limit_accepts_exact_boundary() -> None:
    source = '{"Records":[]}'

    result = ingest_cloudtrail_json(source, max_source_bytes=len(source.encode("utf-8")))

    assert result.total_records == 0


@pytest.mark.parametrize("as_bytes", [False, True])
def test_source_size_limit_rejects_above_boundary(as_bytes: bool) -> None:
    text = '{"Records":[]}'
    source: str | bytes = text.encode("utf-8") if as_bytes else text

    with pytest.raises(CloudTrailSourceTooLargeError, match="byte limit"):
        ingest_cloudtrail_json(source, max_source_bytes=len(text.encode("utf-8")) - 1)


def test_file_size_limit_rejects_without_decoding(tmp_path: Path) -> None:
    source_path = tmp_path / "large.json"
    source_path.write_text('{"Records":[]}', encoding="utf-8")

    with pytest.raises(CloudTrailSourceTooLargeError, match="10-byte limit"):
        ingest_cloudtrail_file(source_path, max_source_bytes=10)


def test_file_read_errors_are_focused_and_do_not_expose_path(tmp_path: Path) -> None:
    missing = tmp_path / "private" / "missing-cloudtrail.json"

    with pytest.raises(CloudTrailSourceReadError) as captured:
        ingest_cloudtrail_file(missing)

    assert str(captured.value) == "Unable to read CloudTrail source file"
    assert str(missing) not in str(captured.value)


def test_unexpected_parser_errors_are_not_silently_converted(monkeypatch) -> None:
    def broken_parser(_record: JsonObject) -> None:
        raise RuntimeError("programming defect")

    monkeypatch.setattr(ingestion_module, "parse_cloudtrail_event", broken_parser)

    with pytest.raises(RuntimeError, match="programming defect"):
        ingest_cloudtrail_document({"Records": [_record()]})


def test_ingestion_result_and_issues_are_immutable() -> None:
    result = ingest_cloudtrail_document({"Records": [None]})

    with pytest.raises(FrozenInstanceError):
        result.total_records = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.issues[0].record_index = 2  # type: ignore[misc]
