"""AWS S3 infrastructure adapter for CloudTrail objects."""

import gzip
import logging
import zlib
from dataclasses import dataclass
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
    CloudTrailIngestionError,
    CloudTrailIngestionResult,
    ingest_cloudtrail_json,
)
from trailweaver.observability import log_event, safe_source_label

DEFAULT_MAX_S3_OBJECT_BYTES = 10 * 1024 * 1024
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

    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
    ) -> tuple[S3ObjectSummary, ...]:
        """List metadata under one explicit non-empty prefix with pagination."""

        if not bucket.strip():
            raise ValueError("bucket must be non-empty")
        if not prefix.strip():
            raise ValueError("prefix must be non-empty")

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


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _close_response_body(body: object) -> None:
    close = getattr(body, "close", None)
    if callable(close):
        close()
