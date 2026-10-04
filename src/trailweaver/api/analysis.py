"""Thin web-analysis adapter over the existing M20/M21 pipeline.

Browser-submitted CloudTrail evidence is decoded here and then handed to the
unchanged ingestion (M20) and investigation-runner (M21) services. This module
contains no CloudTrail parsing, no detection logic, no correlation logic, and
no persistence of its own; it only bounds and frames transport bytes.
"""

import gzip
import logging
import zlib
from collections.abc import Callable
from io import BytesIO

from trailweaver.analysis_runs import AnalysisSourceType
from trailweaver.api.execution import (
    InvestigationExecutionResult,
    InvestigationRunner,
)
from trailweaver.aws_s3 import S3CloudTrailAdapter
from trailweaver.cloudtrail_ingestion import DEFAULT_MAX_SOURCE_BYTES
from trailweaver.observability import log_event, safe_source_label

_LOGGER = logging.getLogger(__name__)

MAX_WEB_SOURCE_BYTES = DEFAULT_MAX_SOURCE_BYTES
_GZIP_MAGIC = b"\x1f\x8b"


class UploadedContentError(ValueError):
    """Raised when uploaded bytes are not usable CloudTrail evidence framing."""

ALLOWED_UPLOAD_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/gzip",
        "application/octet-stream",
    }
)


def is_gzip_bytes(payload: bytes) -> bool:
    """Return whether payload starts with the gzip magic header."""

    return payload.startswith(_GZIP_MAGIC)


def decompress_limited_gzip(payload: bytes, *, max_bytes: int) -> bytes:
    """Decompress gzip transport framing with a bounded output size.

    This mirrors the S3 adapter's decompression bound so gzipped web uploads
    and gzipped S3 objects share the same expansion limit.
    """

    if max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    try:
        with gzip.GzipFile(fileobj=BytesIO(payload), mode="rb") as archive:
            content = archive.read(max_bytes + 1)
    except (gzip.BadGzipFile, EOFError, zlib.error) as error:
        raise UploadedContentError(
            "Uploaded CloudTrail content is not valid gzip"
        ) from error
    if len(content) > max_bytes:
        raise UploadedContentError(
            "Decompressed CloudTrail content exceeds the size limit"
        )
    return content


def analyze_uploaded_bytes(
    payload: bytes,
    runner: InvestigationRunner,
    *,
    source_label: str | None = None,
    max_source_bytes: int = MAX_WEB_SOURCE_BYTES,
) -> InvestigationExecutionResult:
    """Run uploaded bytes through M20 ingestion and the M21 pipeline."""

    label = safe_source_label(
        "browser-upload" if source_label is None else source_label
    )
    content = (
        decompress_limited_gzip(payload, max_bytes=max_source_bytes)
        if is_gzip_bytes(payload)
        else payload
    )
    return runner.run_cloudtrail_json(
        content,
        source_label=label,
        max_source_bytes=max_source_bytes,
        source_type=AnalysisSourceType.WEB_UPLOAD,
    )


def analyze_s3_object(
    adapter: S3CloudTrailAdapter,
    runner: InvestigationRunner,
    *,
    bucket: str,
    key: str,
    version_id: str | None = None,
    source_label: str | None = None,
) -> InvestigationExecutionResult:
    """Run one explicit S3 object through the S3 adapter, M20, and M21."""

    return adapter.run_object(
        runner,
        bucket=bucket,
        key=key,
        version_id=version_id,
        source_label=safe_source_label(
            f"s3://{bucket}/{key}" if source_label is None else source_label
        ),
    )


S3AdapterFactory = Callable[[str | None], S3CloudTrailAdapter]


def default_s3_adapter_factory(region_name: str | None) -> S3CloudTrailAdapter:
    """Create an S3 adapter from the backend's boto3 provider chain.

    No AWS credentials are accepted or stored; authentication always uses the
    runtime provider chain locally and the workload IAM role in AWS.
    """

    log_event(_LOGGER, logging.DEBUG, "s3_adapter_created")
    return S3CloudTrailAdapter.from_boto3(region_name=region_name)
