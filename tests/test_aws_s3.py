import gzip
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

import trailweaver.aws_s3 as aws_s3_module
from trailweaver.api.execution import create_default_investigation_runner
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.aws_s3 import (
    S3CloudTrailAccessDeniedError,
    S3CloudTrailAdapter,
    S3CloudTrailDecompressedTooLargeError,
    S3CloudTrailInvalidGzipError,
    S3CloudTrailObjectNotFoundError,
    S3CloudTrailObjectTooLargeError,
    S3CloudTrailSourceError,
)
from trailweaver.cloudtrail_ingestion import CloudTrailInvalidJsonError

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
BUCKET = "fictional-cloudtrail-bucket"
KEY = "AWSLogs/111122223333/CloudTrail/us-east-1/export.json"


class _FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.get_error: ClientError | None = None
        self.list_pages: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, object]] = []
        self.list_calls: list[dict[str, object]] = []

    def get_object(self, **kwargs: object) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        if self.get_error is not None:
            raise self.get_error
        return self.objects[kwargs["Key"]]

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
        self.list_calls.append(kwargs)
        return self.list_pages[len(self.list_calls) - 1]


def _response(content: bytes, **metadata: object) -> dict[str, Any]:
    return {
        "Body": BytesIO(content),
        "ContentLength": len(content),
        **metadata,
    }


def _client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "sensitive AWS response details"}},
        "GetObject",
    )


def test_plain_s3_object_delegates_to_m20() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response(
        (SAMPLES / "valid-multi-record.json").read_bytes(),
        ETag='"fictional-etag"',
        VersionId="fictional-version",
    )

    result = S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=KEY)

    assert result.accepted_records == 3
    assert result.source_label == f"s3://{BUCKET}/{KEY}"
    assert client.get_calls == [{"Bucket": BUCKET, "Key": KEY}]


def test_gzip_s3_object_is_bounded_and_delegates_to_m20() -> None:
    client = _FakeS3Client()
    gzip_key = f"{KEY}.gz"
    client.objects[gzip_key] = _response(
        gzip.compress((SAMPLES / "valid-multi-record.json").read_bytes())
    )

    result = S3CloudTrailAdapter(client).ingest_object(
        bucket=BUCKET,
        key=gzip_key,
    )

    assert result.accepted_records == 3


def test_gzip_magic_bytes_are_detected_without_filename_suffix() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response(
        gzip.compress((SAMPLES / "empty-records.json").read_bytes())
    )

    result = S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=KEY)

    assert result.total_records == 0


def test_version_id_is_requested_and_preserved_in_provenance() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response(
        (SAMPLES / "empty-records.json").read_bytes(),
        ETag='"etag-1"',
        VersionId="version-1",
    )

    source = S3CloudTrailAdapter(client).fetch_object(
        bucket=BUCKET,
        key=KEY,
        version_id="version-1",
    )

    assert source.provenance.etag == '"etag-1"'
    assert source.provenance.version_id == "version-1"
    assert client.get_calls == [
        {"Bucket": BUCKET, "Key": KEY, "VersionId": "version-1"}
    ]


def test_explicit_source_label_avoids_exposing_s3_location() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response((SAMPLES / "empty-records.json").read_bytes())

    result = S3CloudTrailAdapter(client).ingest_object(
        bucket=BUCKET,
        key=KEY,
        source_label="cloudtrail-object-42",
    )

    assert result.source_label == "cloudtrail-object-42"


def test_partial_success_diagnostics_are_preserved_from_m20() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response((SAMPLES / "mixed-records.json").read_bytes())

    result = S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=KEY)

    assert result.total_records == 4
    assert result.accepted_records == 2
    assert result.failed_records == 2
    assert [issue.record_index for issue in result.issues] == [1, 2]


def test_s3_attack_object_runs_through_existing_m21_pipeline() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response(
        gzip.compress((SAMPLES / "account-compromise-sequence.json").read_bytes()),
        ContentEncoding="gzip",
    )
    repository = InMemoryIncidentRepository()

    result = S3CloudTrailAdapter(client).run_object(
        create_default_investigation_runner(repository),
        bucket=BUCKET,
        key=KEY,
    )

    assert result.ingestion_result.accepted_records == 3
    assert result.signal_count == 3
    assert result.correlation_count == 1
    assert result.incident_count == 1
    assert repository.list_incidents() == result.incidents
    assert all(event.raw_event for event in result.analyzed_events)


@pytest.mark.parametrize(
    ("code", "expected_error"),
    [
        ("NoSuchKey", S3CloudTrailObjectNotFoundError),
        ("AccessDenied", S3CloudTrailAccessDeniedError),
        ("SlowDown", S3CloudTrailSourceError),
    ],
)
def test_aws_errors_are_sanitized(
    code: str, expected_error: type[S3CloudTrailSourceError]
) -> None:
    client = _FakeS3Client()
    client.get_error = _client_error(code)

    with pytest.raises(expected_error) as captured:
        S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=KEY)

    message = str(captured.value)
    assert "sensitive AWS response details" not in message
    assert BUCKET not in message
    assert KEY not in message


def test_invalid_gzip_is_reported_before_json_decoding() -> None:
    client = _FakeS3Client()
    gzip_key = f"{KEY}.gz"
    client.objects[gzip_key] = _response(b"not-gzip")

    with pytest.raises(S3CloudTrailInvalidGzipError, match="not valid gzip"):
        S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=gzip_key)


def test_decompressed_size_limit_stops_gzip_expansion() -> None:
    client = _FakeS3Client()
    gzip_key = f"{KEY}.gz"
    client.objects[gzip_key] = _response(gzip.compress(b"A" * 1000))

    with pytest.raises(S3CloudTrailDecompressedTooLargeError, match="100-byte limit"):
        S3CloudTrailAdapter(client).ingest_object(
            bucket=BUCKET,
            key=gzip_key,
            max_decompressed_bytes=100,
        )


def test_stored_object_size_limit_is_checked_before_full_read() -> None:
    client = _FakeS3Client()
    body = BytesIO(b"{}")
    client.objects[KEY] = {"Body": body, "ContentLength": 1000}

    with pytest.raises(S3CloudTrailObjectTooLargeError, match="100-byte"):
        S3CloudTrailAdapter(client).ingest_object(
            bucket=BUCKET,
            key=KEY,
            max_object_bytes=100,
        )

    assert body.closed


def test_malformed_plain_json_remains_an_m20_document_error() -> None:
    client = _FakeS3Client()
    client.objects[KEY] = _response(b'{"Records": [}')

    with pytest.raises(CloudTrailInvalidJsonError):
        S3CloudTrailAdapter(client).ingest_object(bucket=BUCKET, key=KEY)


def test_listing_requires_explicit_prefix_and_paginates() -> None:
    client = _FakeS3Client()
    client.list_pages = [
        {
            "Contents": [
                {"Key": "AWSLogs/a.json.gz", "Size": 10, "ETag": '"one"'}
            ],
            "IsTruncated": True,
            "NextContinuationToken": "next-token",
        },
        {
            "Contents": [
                {"Key": "AWSLogs/b.json.gz", "Size": 20, "ETag": '"two"'}
            ],
            "IsTruncated": False,
        },
    ]
    adapter = S3CloudTrailAdapter(client)

    objects = adapter.list_objects(bucket=BUCKET, prefix="AWSLogs/111122223333/")

    assert [item.key for item in objects] == [
        "AWSLogs/a.json.gz",
        "AWSLogs/b.json.gz",
    ]
    assert client.list_calls == [
        {"Bucket": BUCKET, "Prefix": "AWSLogs/111122223333/"},
        {
            "Bucket": BUCKET,
            "Prefix": "AWSLogs/111122223333/",
            "ContinuationToken": "next-token",
        },
    ]
    with pytest.raises(ValueError, match="prefix must be non-empty"):
        adapter.list_objects(bucket=BUCKET, prefix="")


def test_boto3_factory_uses_provider_chain_without_static_credentials(monkeypatch) -> None:
    client = _FakeS3Client()
    calls: list[tuple[str, dict[str, object]]] = []

    def fake_client(service: str, **kwargs: object) -> _FakeS3Client:
        calls.append((service, kwargs))
        return client

    monkeypatch.setattr(aws_s3_module.boto3, "client", fake_client)

    adapter = S3CloudTrailAdapter.from_boto3(region_name="us-east-1")

    assert isinstance(adapter, S3CloudTrailAdapter)
    assert calls == [("s3", {"region_name": "us-east-1"})]
