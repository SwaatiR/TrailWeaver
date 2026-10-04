"""AWS S3 infrastructure adapter for CloudTrail objects."""

import gzip
import logging
import time
import zlib
from dataclasses import dataclass
from enum import StrEnum
from io import BytesIO
from typing import Any, Protocol, cast

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from trailweaver.analysis_runs import AnalysisSourceType
from trailweaver.api.execution import (
    InvestigationExecutionResult,
    InvestigationRunner,
)
from trailweaver.cloudtrail_ingestion import (
    DEFAULT_MAX_SOURCE_BYTES,
    CloudTrailEnvelopeError,
    CloudTrailIngestionError,
    CloudTrailIngestionResult,
    CloudTrailInvalidJsonError,
    ingest_cloudtrail_json,
)
from trailweaver.observability import log_event, safe_source_label

DEFAULT_MAX_S3_OBJECT_BYTES = 10 * 1024 * 1024
DEFAULT_S3_PREFIX_MAX_OBJECTS = 100
MAX_S3_PREFIX_MAX_OBJECTS = 1000
_LOGGER = logging.getLogger(__name__)


class S3StreamingBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class S3Client(Protocol):
    def get_object(self, **kwargs: object) -> dict[str, Any]: ...

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]: ...


class S3CloudTrailSourceError(RuntimeError):
    """Base class for focused S3 CloudTrail source failures."""


class S3CloudTrailObjectNotFoundError(S3CloudTrailSourceError):
    """Raised when the configured object does not exist."""


class S3CloudTrailAccessDeniedError(S3CloudTrailSourceError):
    """Raised when AWS denies access to the configured source."""


class S3CloudTrailObjectTooLargeError(S3CloudTrailSourceError):
    """Raised when the stored S3 object exceeds its configured byte limit."""


class S3CloudTrailDecompressedTooLargeError(S3CloudTrailSourceError):
    """Raised when gzip content expands beyond the configured byte limit."""


class S3CloudTrailInvalidGzipError(S3CloudTrailSourceError):
    """Raised when an object identified as gzip cannot be decompressed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class S3ObjectProvenance:
    """S3 source metadata that is not used as security-domain identity."""

    bucket: str
    key: str
    etag: str | None = None
    version_id: str | None = None

    @property
    def source_label(self) -> str:
        return f"s3://{self.bucket}/{self.key}"


@dataclass(frozen=True, slots=True, kw_only=True)
class S3CloudTrailObject:
    """Bounded bytes and provenance retrieved from one S3 object."""

    content: bytes
    provenance: S3ObjectProvenance
    content_encoding: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class S3ObjectSummary:
    """One explicitly listed object under a caller-provided prefix."""

    key: str
    size: int
    etag: str | None = None


class S3PrefixObjectStatus(StrEnum):
    """Whether one selected prefix object produced a successful analysis run."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class S3PrefixObjectOutcome:
    """Safe per-object outcome of bounded S3 prefix analysis.

    Successful outcomes carry their ordinary per-object AnalysisRun counts;
    failed outcomes carry a typed failure category and a fixed safe message.
    No object contents, boto metadata, or exception internals are retained.
    """

    key: str
    status: S3PrefixObjectStatus
    analysis_run_id: str | None = None
    records_seen: int = 0
    records_accepted: int = 0
    signals_created: int = 0
    correlations_created: int = 0
    incidents_created: int = 0
    incident_ids: tuple[str, ...] = ()
    error_category: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("prefix object outcome key must be non-empty")
        for count in (
            self.records_seen,
            self.records_accepted,
            self.signals_created,
            self.correlations_created,
            self.incidents_created,
        ):
            if count < 0:
                raise ValueError("prefix object outcome counts must be non-negative")
        if self.status is S3PrefixObjectStatus.SUCCEEDED:
            if self.analysis_run_id is None:
                raise ValueError("successful prefix outcomes require an analysis run")
            if self.error_category is not None or self.error_message is not None:
                raise ValueError("successful prefix outcomes must not carry errors")
        else:
            if self.error_category is None or self.error_message is None:
                raise ValueError("failed prefix outcomes require error details")


@dataclass(frozen=True, slots=True, kw_only=True)
class S3PrefixAnalysis:
    """Ephemeral aggregate of one bounded S3 prefix analysis.

    Every selected object receives exactly one outcome, so attempted always
    equals discovered and succeeded plus failed always equals attempted.
    Per-run counts are summed across successful object runs; incidents
    created by M32 cross-object correlation are counted once, in the run
    that created them. Nothing here is persisted.
    """

    bucket: str
    prefix: str
    max_objects: int
    outcomes: tuple[S3PrefixObjectOutcome, ...] = ()
    analysis_run_ids: tuple[str, ...] = ()
    incident_ids: tuple[str, ...] = ()
    records_seen: int = 0
    records_accepted: int = 0
    signals_created: int = 0
    correlations_created: int = 0
    incidents_created: int = 0

    def __post_init__(self) -> None:
        if len(self.outcomes) > self.max_objects:
            raise ValueError("prefix outcomes must not exceed max_objects")
        succeeded = sum(
            1 for outcome in self.outcomes
            if outcome.status is S3PrefixObjectStatus.SUCCEEDED
        )
        failed = sum(
            1 for outcome in self.outcomes
            if outcome.status is S3PrefixObjectStatus.FAILED
        )
        if succeeded + failed != len(self.outcomes):
            raise ValueError("prefix outcomes must each succeed or fail")

    @property
    def objects_discovered(self) -> int:
        """Number of object summaries selected within the configured bound."""

        return len(self.outcomes)

    @property
    def objects_attempted(self) -> int:
        """Number of selected objects given exactly one outcome each."""

        return len(self.outcomes)

    @property
    def objects_succeeded(self) -> int:
        """Number of selected objects with a successful analysis run."""

        return sum(
            1 for outcome in self.outcomes
            if outcome.status is S3PrefixObjectStatus.SUCCEEDED
        )

    @property
    def objects_failed(self) -> int:
        """Number of selected objects with a recorded object-level failure."""

        return sum(
            1 for outcome in self.outcomes
            if outcome.status is S3PrefixObjectStatus.FAILED
        )


class S3CloudTrailAdapter:
    """Retrieve bounded CloudTrail objects and delegate their semantics to M20/M21."""

    def __init__(self, client: S3Client) -> None:
        self._client = client

    @classmethod
    def from_boto3(cls, *, region_name: str | None = None) -> "S3CloudTrailAdapter":
        """Create an adapter using boto3's normal AWS credential provider chain."""

        client = boto3.client("s3", region_name=region_name)
        return cls(cast(S3Client, client))

    def fetch_object(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        max_object_bytes: int = DEFAULT_MAX_S3_OBJECT_BYTES,
    ) -> S3CloudTrailObject:
        """Retrieve one explicit S3 object without reading beyond the byte limit."""

        _validate_location(bucket=bucket, key=key)
        limit = _validate_limit(max_object_bytes, "max_object_bytes")
        request: dict[str, object] = {"Bucket": bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id

        try:
            response = self._client.get_object(**request)
        except ClientError as error:
            raise _translate_client_error(error) from error
        except BotoCoreError as error:
            raise S3CloudTrailSourceError(
                "Unable to retrieve the configured S3 CloudTrail object"
            ) from error

        content_length = response.get("ContentLength")
        if isinstance(content_length, int) and content_length > limit:
            _close_response_body(response.get("Body"))
            raise S3CloudTrailObjectTooLargeError(
                f"S3 CloudTrail object exceeds the {limit}-byte compressed limit"
            )

        body = response.get("Body")
        if not hasattr(body, "read"):
            raise S3CloudTrailSourceError(
                "S3 returned an unreadable CloudTrail object body"
            )
        try:
            content = body.read(limit + 1)
        except BotoCoreError as error:
            raise S3CloudTrailSourceError(
                "Unable to read the configured S3 CloudTrail object"
            ) from error
        finally:
            _close_response_body(body)

        if not isinstance(content, bytes):
            raise S3CloudTrailSourceError(
                "S3 returned an invalid CloudTrail object body"
            )
        if len(content) > limit:
            raise S3CloudTrailObjectTooLargeError(
                f"S3 CloudTrail object exceeds the {limit}-byte compressed limit"
            )

        return S3CloudTrailObject(
            content=content,
            provenance=S3ObjectProvenance(
                bucket=bucket,
                key=key,
                etag=_optional_string(response.get("ETag")),
                version_id=_optional_string(response.get("VersionId")) or version_id,
            ),
            content_encoding=_optional_string(response.get("ContentEncoding")),
        )

    def ingest_object(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        source_label: str | None = None,
        max_object_bytes: int = DEFAULT_MAX_S3_OBJECT_BYTES,
        max_decompressed_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    ) -> CloudTrailIngestionResult:
        """Retrieve one object and feed its decoded bytes through M20 ingestion."""

        decompressed_limit = _validate_limit(
            max_decompressed_bytes, "max_decompressed_bytes"
        )
        label = safe_source_label(
            f"s3://{bucket}/{key}" if source_label is None else source_label
        )
        log_event(_LOGGER, logging.INFO, "aws_ingestion_started", source=label)
        try:
            source = self.fetch_object(
                bucket=bucket,
                key=key,
                version_id=version_id,
                max_object_bytes=max_object_bytes,
            )
            content = (
                _decompress_gzip(source.content, max_bytes=decompressed_limit)
                if _is_gzip(source)
                else source.content
            )
            result = ingest_cloudtrail_json(
                content,
                source_label=(
                    source.provenance.source_label
                    if source_label is None
                    else source_label
                ),
                max_source_bytes=decompressed_limit,
            )
        except (S3CloudTrailSourceError, CloudTrailIngestionError) as error:
            log_event(
                _LOGGER,
                logging.ERROR,
                "aws_ingestion_failed",
                source=label,
                error_type=type(error).__name__,
            )
            raise
        log_event(
            _LOGGER,
            logging.INFO,
            "aws_ingestion_completed",
            source=label,
            source_records=result.total_records,
            accepted=result.accepted_records,
            failed=result.failed_records,
            duplicates=result.duplicate_records,
        )
        return result

    def run_object(
        self,
        runner: InvestigationRunner,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        source_label: str | None = None,
        max_object_bytes: int = DEFAULT_MAX_S3_OBJECT_BYTES,
        max_decompressed_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    ) -> InvestigationExecutionResult:
        """Retrieve through S3/M20 and run accepted events through the M21 pipeline."""

        ingestion_result = self.ingest_object(
            bucket=bucket,
            key=key,
            version_id=version_id,
            source_label=source_label,
            max_object_bytes=max_object_bytes,
            max_decompressed_bytes=max_decompressed_bytes,
        )
        return runner.run_ingestion_result(
            ingestion_result,
            source_type=AnalysisSourceType.S3_OBJECT,
        )

    def analyze_prefix(
        self,
        runner: InvestigationRunner,
        *,
        bucket: str,
        prefix: str,
        max_objects: int = DEFAULT_S3_PREFIX_MAX_OBJECTS,
        max_object_bytes: int = DEFAULT_MAX_S3_OBJECT_BYTES,
        max_decompressed_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    ) -> S3PrefixAnalysis:
        """Analyze a bounded prefix selection sequentially, one object at a time.

        Every selected object either runs the existing single-object pipeline
        or records one safe object-level failure; only one raw object is
        resident at a time. Internal TrailWeaver persistence failures abort
        the orchestration while already committed object work stays durable.
        """

        _validate_prefix_limit(max_objects)
        started = time.perf_counter()
        summaries = self.list_objects(
            bucket=bucket, prefix=prefix, max_objects=max_objects
        )
        selected = sorted(summaries, key=lambda summary: summary.key)[:max_objects]
        outcomes: list[S3PrefixObjectOutcome] = []
        for summary in selected:
            outcomes.append(
                self._analyze_listed_object(
                    runner,
                    bucket=bucket,
                    summary=summary,
                    max_object_bytes=max_object_bytes,
                    max_decompressed_bytes=max_decompressed_bytes,
                )
            )
        result = S3PrefixAnalysis(
            bucket=bucket,
            prefix=prefix,
            max_objects=max_objects,
            outcomes=tuple(outcomes),
            analysis_run_ids=tuple(
                outcome.analysis_run_id
                for outcome in outcomes
                if outcome.analysis_run_id is not None
            ),
            incident_ids=tuple(
                incident_id
                for outcome in outcomes
                for incident_id in outcome.incident_ids
            ),
            records_seen=sum(outcome.records_seen for outcome in outcomes),
            records_accepted=sum(outcome.records_accepted for outcome in outcomes),
            signals_created=sum(outcome.signals_created for outcome in outcomes),
            correlations_created=sum(
                outcome.correlations_created for outcome in outcomes
            ),
            incidents_created=sum(outcome.incidents_created for outcome in outcomes),
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "aws_prefix_analysis_completed",
            source=safe_source_label(f"s3://{bucket}/{prefix}"),
            objects_discovered=result.objects_discovered,
            objects_attempted=result.objects_attempted,
            objects_succeeded=result.objects_succeeded,
            objects_failed=result.objects_failed,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return result

    def _analyze_listed_object(
        self,
        runner: InvestigationRunner,
        *,
        bucket: str,
        summary: S3ObjectSummary,
        max_object_bytes: int,
        max_decompressed_bytes: int,
    ) -> S3PrefixObjectOutcome:
        """Run one listed object, converting source failures to safe outcomes."""

        if summary.size > max_object_bytes:
            return S3PrefixObjectOutcome(
                key=summary.key,
                status=S3PrefixObjectStatus.FAILED,
                error_category="object_too_large",
                error_message=(
                    "S3 CloudTrail object exceeds the configured compressed size limit"
                ),
            )
        try:
            result = self.run_object(
                runner,
                bucket=bucket,
                key=summary.key,
                max_object_bytes=max_object_bytes,
                max_decompressed_bytes=max_decompressed_bytes,
            )
        except (
            S3CloudTrailSourceError,
            CloudTrailIngestionError,
        ) as error:
            return S3PrefixObjectOutcome(
                key=summary.key,
                status=S3PrefixObjectStatus.FAILED,
                error_category=_object_error_category(error),
                error_message=str(error),
            )
        run = result.analysis_run
        return S3PrefixObjectOutcome(
            key=summary.key,
            status=S3PrefixObjectStatus.SUCCEEDED,
            analysis_run_id=run.analysis_run_id,
            records_seen=run.records_seen,
            records_accepted=run.records_accepted,
            signals_created=run.signals_created,
            correlations_created=run.correlations_created,
            incidents_created=run.incidents_created,
            incident_ids=tuple(
                incident.incident_id for incident in result.persisted_incidents
            ),
        )
    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
        max_objects: int | None = None,
    ) -> tuple[S3ObjectSummary, ...]:
        """List metadata under one explicit non-empty prefix with pagination.

        When ``max_objects`` is provided, pagination stops as soon as enough
        objects are selected instead of walking the rest of the bucket. A
        ``None`` limit preserves the existing walk-all behavior.
        """

        if not bucket.strip():
            raise ValueError("bucket must be non-empty")
        if not prefix.strip():
            raise ValueError("prefix must be non-empty")
        if max_objects is not None:
            _validate_prefix_limit(max_objects)

        objects: list[S3ObjectSummary] = []
        continuation_token: str | None = None
        while True:
            request: dict[str, object] = {"Bucket": bucket, "Prefix": prefix}
            if continuation_token is not None:
                request["ContinuationToken"] = continuation_token
            try:
                response = self._client.list_objects_v2(**request)
            except ClientError as error:
                raise _translate_client_error(error) from error
            except BotoCoreError as error:
                raise S3CloudTrailSourceError(
                    "Unable to list the configured S3 CloudTrail prefix"
                ) from error

            contents = response.get("Contents", ())
            if not isinstance(contents, list):
                raise S3CloudTrailSourceError("S3 returned an invalid object listing")
            for item in contents:
                if not isinstance(item, dict):
                    raise S3CloudTrailSourceError(
                        "S3 returned an invalid object listing"
                    )
                object_key = item.get("Key")
                size = item.get("Size")
                if not isinstance(object_key, str) or not isinstance(size, int):
                    raise S3CloudTrailSourceError(
                        "S3 returned an invalid object listing"
                    )
                objects.append(
                    S3ObjectSummary(
                        key=object_key,
                        size=size,
                        etag=_optional_string(item.get("ETag")),
                    )
                )
                if max_objects is not None and len(objects) >= max_objects:
                    return tuple(objects[:max_objects])

            if response.get("IsTruncated") is not True:
                return tuple(objects)
            continuation_token = _optional_string(response.get("NextContinuationToken"))
            if continuation_token is None:
                raise S3CloudTrailSourceError(
                    "S3 returned a truncated listing without a continuation token"
                )


def _is_gzip(source: S3CloudTrailObject) -> bool:
    encoding = source.content_encoding
    return (
        source.content.startswith(b"\x1f\x8b")
        or source.provenance.key.lower().endswith(".gz")
        or (encoding is not None and "gzip" in encoding.lower())
    )


def _decompress_gzip(source: bytes, *, max_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=BytesIO(source), mode="rb") as archive:
            content = archive.read(max_bytes + 1)
    except (gzip.BadGzipFile, EOFError, zlib.error) as error:
        raise S3CloudTrailInvalidGzipError(
            "S3 CloudTrail object is not valid gzip content"
        ) from error
    if len(content) > max_bytes:
        raise S3CloudTrailDecompressedTooLargeError(
            f"Decompressed CloudTrail object exceeds the {max_bytes}-byte limit"
        )
    return content


def _translate_client_error(error: ClientError) -> S3CloudTrailSourceError:
    error_data = error.response.get("Error", {})
    code = str(error_data.get("Code", "")) if isinstance(error_data, dict) else ""
    if code in {"NoSuchKey", "NotFound", "404"}:
        return S3CloudTrailObjectNotFoundError(
            "The configured S3 CloudTrail object was not found"
        )
    if code in {"AccessDenied", "403"}:
        return S3CloudTrailAccessDeniedError(
            "Access to the configured S3 CloudTrail source was denied"
        )
    return S3CloudTrailSourceError(
        "AWS could not retrieve the configured S3 CloudTrail source"
    )


def _validate_location(*, bucket: str, key: str) -> None:
    if not bucket.strip():
        raise ValueError("bucket must be non-empty")
    if not key.strip():
        raise ValueError("key must be non-empty")


def _validate_limit(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_prefix_limit(max_objects: int) -> int:
    """Validate the bounded M33 prefix selection size."""

    if (
        not isinstance(max_objects, int)
        or isinstance(max_objects, bool)
        or max_objects < 1
        or max_objects > MAX_S3_PREFIX_MAX_OBJECTS
    ):
        raise ValueError(
            "max_objects must be an integer between 1 and "
            f"{MAX_S3_PREFIX_MAX_OBJECTS}"
        )
    return max_objects


def _object_error_category(error: Exception) -> str:
    """Map one object-level failure to a stable safe error category."""

    if isinstance(error, S3CloudTrailObjectNotFoundError):
        return "not_found"
    if isinstance(error, S3CloudTrailAccessDeniedError):
        return "access_denied"
    if isinstance(error, S3CloudTrailObjectTooLargeError):
        return "object_too_large"
    if isinstance(error, S3CloudTrailDecompressedTooLargeError):
        return "decompressed_too_large"
    if isinstance(error, S3CloudTrailInvalidGzipError):
        return "invalid_gzip"
    if isinstance(error, CloudTrailInvalidJsonError):
        return "invalid_json"
    if isinstance(error, CloudTrailEnvelopeError):
        return "invalid_envelope"
    return "source_error"


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _close_response_body(body: object) -> None:
    close = getattr(body, "close", None)
    if callable(close):
        close()
