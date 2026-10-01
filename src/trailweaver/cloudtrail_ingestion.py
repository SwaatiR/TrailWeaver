"""Ingest standard AWS CloudTrail JSON exports into normalized events."""

import json
from dataclasses import dataclass
from enum import StrEnum
from os import PathLike
from pathlib import Path
from typing import cast

from trailweaver.cloudtrail import CloudTrailParseError, parse_cloudtrail_event
from trailweaver.models import JsonObject, JsonValue, NormalizedEvent

DEFAULT_MAX_SOURCE_BYTES = 10 * 1024 * 1024
_MAX_DIAGNOSTIC_EVENT_ID_LENGTH = 256


class CloudTrailIngestionError(ValueError):
    """Base class for document-level CloudTrail ingestion failures."""


class CloudTrailSourceReadError(CloudTrailIngestionError):
    """Raised when a CloudTrail source file cannot be read."""


class CloudTrailSourceDecodeError(CloudTrailIngestionError):
    """Raised when CloudTrail source bytes are not valid UTF-8."""


class CloudTrailInvalidJsonError(CloudTrailIngestionError):
    """Raised when CloudTrail source text is not a valid JSON document."""


class CloudTrailEnvelopeError(CloudTrailIngestionError):
    """Raised when decoded JSON is not a standard CloudTrail export envelope."""


class CloudTrailSourceTooLargeError(CloudTrailIngestionError):
    """Raised when encoded CloudTrail source exceeds the configured byte limit."""


class CloudTrailIngestionIssueCode(StrEnum):
    """Stable record-level diagnostic codes."""

    INVALID_RECORD_TYPE = "invalid_record_type"
    PARSER_REJECTED_RECORD = "parser_rejected_record"
    DUPLICATE_EVENT = "duplicate_event"


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudTrailIngestionIssue:
    """A safe diagnostic for one record in a CloudTrail export."""

    record_index: int
    code: CloudTrailIngestionIssueCode
    message: str
    event_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudTrailIngestionResult:
    """Immutable normalized events and diagnostics for one ingestion operation."""

    events: tuple[NormalizedEvent, ...]
    total_records: int
    accepted_records: int
    failed_records: int
    duplicate_records: int
    issues: tuple[CloudTrailIngestionIssue, ...]
    source_label: str | None = None


def ingest_cloudtrail_json(
    source: str | bytes,
    *,
    source_label: str | None = None,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> CloudTrailIngestionResult:
    """Decode and ingest UTF-8 JSON text containing a CloudTrail export envelope."""

    limit = _validate_source_limit(max_source_bytes)
    if isinstance(source, bytes):
        _enforce_source_size(len(source), limit)
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CloudTrailSourceDecodeError(
                "CloudTrail source is not valid UTF-8"
            ) from error
    else:
        try:
            encoded_size = len(source.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise CloudTrailSourceDecodeError(
                "CloudTrail source is not valid UTF-8 text"
            ) from error
        _enforce_source_size(encoded_size, limit)
        text = source

    try:
        document = cast(JsonValue, json.loads(text))
    except (json.JSONDecodeError, RecursionError) as error:
        raise CloudTrailInvalidJsonError(
            "CloudTrail source is not a valid JSON document"
        ) from error

    return ingest_cloudtrail_document(document, source_label=source_label)


def ingest_cloudtrail_document(
    document: JsonValue,
    *,
    source_label: str | None = None,
) -> CloudTrailIngestionResult:
    """Validate and ingest an already-decoded standard CloudTrail export."""

    if not isinstance(document, dict):
        raise CloudTrailEnvelopeError("CloudTrail document must be a JSON object")
    if "Records" not in document:
        raise CloudTrailEnvelopeError("CloudTrail document is missing 'Records'")

    records = document["Records"]
    if not isinstance(records, list):
        raise CloudTrailEnvelopeError("CloudTrail document 'Records' must be an array")

    events: list[NormalizedEvent] = []
    issues: list[CloudTrailIngestionIssue] = []
    seen_event_ids: set[str] = set()
    failed_records = 0
    duplicate_records = 0

    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            failed_records += 1
            issues.append(
                CloudTrailIngestionIssue(
                    record_index=record_index,
                    code=CloudTrailIngestionIssueCode.INVALID_RECORD_TYPE,
                    message="CloudTrail record must be a JSON object.",
                )
            )
            continue

        raw_event = cast(JsonObject, record)
        diagnostic_event_id = _safe_diagnostic_event_id(raw_event.get("eventID"))
        try:
            event = parse_cloudtrail_event(raw_event)
        except CloudTrailParseError:
            failed_records += 1
            issues.append(
                CloudTrailIngestionIssue(
                    record_index=record_index,
                    code=CloudTrailIngestionIssueCode.PARSER_REJECTED_RECORD,
                    message=(
                        "CloudTrail record could not be normalized by the event parser."
                    ),
                    event_id=diagnostic_event_id,
                )
            )
            continue

        if event.event_id is not None and event.event_id in seen_event_ids:
            duplicate_records += 1
            issues.append(
                CloudTrailIngestionIssue(
                    record_index=record_index,
                    code=CloudTrailIngestionIssueCode.DUPLICATE_EVENT,
                    message=(
                        "CloudTrail record duplicates an earlier event ID and was not accepted."
                    ),
                    event_id=_safe_diagnostic_event_id(event.event_id),
                )
            )
            continue

        events.append(event)
        if event.event_id is not None:
            seen_event_ids.add(event.event_id)

    return CloudTrailIngestionResult(
        events=tuple(events),
        total_records=len(records),
        accepted_records=len(events),
        failed_records=failed_records,
        duplicate_records=duplicate_records,
        issues=tuple(issues),
        source_label=source_label,
    )


def ingest_cloudtrail_file(
    path: str | PathLike[str],
    *,
    source_label: str | None = None,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> CloudTrailIngestionResult:
    """Read and ingest one file without modifying it or exposing its full path."""

    limit = _validate_source_limit(max_source_bytes)
    source_path = Path(path)
    try:
        with source_path.open("rb") as source_file:
            source = source_file.read(limit + 1)
    except OSError as error:
        raise CloudTrailSourceReadError(
            "Unable to read CloudTrail source file"
        ) from error

    _enforce_source_size(len(source), limit)
    return ingest_cloudtrail_json(
        source,
        source_label=source_path.name if source_label is None else source_label,
        max_source_bytes=limit,
    )


def _validate_source_limit(max_source_bytes: int) -> int:
    if (
        not isinstance(max_source_bytes, int)
        or isinstance(max_source_bytes, bool)
        or max_source_bytes <= 0
    ):
        raise ValueError("max_source_bytes must be a positive integer")
    return max_source_bytes


def _enforce_source_size(source_size: int, max_source_bytes: int) -> None:
    if source_size > max_source_bytes:
        raise CloudTrailSourceTooLargeError(
            f"CloudTrail source exceeds the {max_source_bytes}-byte limit"
        )


def _safe_diagnostic_event_id(value: JsonValue | str | None) -> str | None:
    if (
        isinstance(value, str)
        and value
        and len(value) <= _MAX_DIAGNOSTIC_EVENT_ID_LENGTH
        and value.isprintable()
    ):
        return value
    return None
