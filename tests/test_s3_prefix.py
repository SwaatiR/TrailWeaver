"""Focused tests for bounded S3 prefix analysis (M33).

A prefix selection is discovered, lexically ordered, and processed
sequentially with one ordinary per-object AnalysisRun each. The aggregate
is ephemeral; durable provenance consists of the individual runs.
"""

import gzip
import json
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.service import InMemoryIncidentRepository
from trailweaver.api.sqlite_repository import (
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)
from trailweaver.aws_s3 import (
    DEFAULT_S3_PREFIX_MAX_OBJECTS,
    MAX_S3_PREFIX_MAX_OBJECTS,
    S3CloudTrailAdapter,
    S3PrefixObjectStatus,
)
from trailweaver.cli import EXIT_RUNTIME_ERROR, EXIT_SOURCE_ERROR, EXIT_SUCCESS, main
from trailweaver.runtime import RuntimeConfig, RuntimeConfigurationError

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
BUCKET = "fictional-cloudtrail-bucket"
PREFIX = "AWSLogs/111122223333/CloudTrail/us-east-1/2026/09/23/"


class _FakeS3Client:
    """In-memory boto stand-in with paged listing and per-key objects/errors."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.object_errors: dict[str, ClientError] = {}
        self.list_pages: list[dict[str, Any]] = []
        self.list_error: ClientError | None = None
        self.get_calls: list[dict[str, object]] = []
        self.list_calls: list[dict[str, object]] = []

    def get_object(self, **kwargs: object) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        key = kwargs["Key"]
        assert isinstance(key, str)
        if key in self.object_errors:
            raise self.object_errors[key]
        return self.objects[key]

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
        self.list_calls.append(kwargs)
        if self.list_error is not None:
            raise self.list_error
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


def _attack_bytes() -> bytes:
    return (SAMPLES / "account-compromise-sequence.json").read_bytes()


def _attack_document() -> dict[str, Any]:
    return json.loads(_attack_bytes().decode("utf-8"))


def _single_event_document(event_name: str) -> bytes:
    records = [
        record
        for record in _attack_document()["Records"]
        if record["eventName"] == event_name
    ]
    assert records, "fixture must contain the requested record"
    return json.dumps({"Records": records}).encode("utf-8")


def _page(*entries: tuple[str, bytes]) -> dict[str, Any]:
    return {
        "Contents": [
            {
                "Key": key,
                "Size": len(content),
                "ETag": '"fictional-etag"',
                "StorageClass": "STANDARD",
                "Owner": {"ID": "fictional-owner"},
            }
            for key, content in entries
        ],
        "IsTruncated": False,
    }


def _adapter(client: _FakeS3Client) -> S3CloudTrailAdapter:
    return S3CloudTrailAdapter(client)  # type: ignore[arg-type]


def test_prefix_and_bound_validation() -> None:
    client = _FakeS3Client()
    adapter = _adapter(client)

    with pytest.raises(ValueError, match="prefix must be non-empty"):
        adapter.list_objects(bucket=BUCKET, prefix="   ")
    for bad in (0, -3, 1001, 10**9):
        with pytest.raises(ValueError):
            adapter.list_objects(bucket=BUCKET, prefix=PREFIX, max_objects=bad)
        with pytest.raises(ValueError):
            adapter.analyze_prefix(
                create_default_investigation_runner(InMemoryIncidentRepository()),
                bucket=BUCKET,
                prefix=PREFIX,
                max_objects=bad,
            )


def test_zero_matching_objects_produces_empty_successful_aggregate(
    tmp_path: Path,
) -> None:
    client = _FakeS3Client()
    client.list_pages.append({"Contents": [], "IsTruncated": False})
    _, runner = _sqlite_runner(tmp_path / "empty.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_discovered == 0
    assert result.objects_attempted == 0
    assert result.objects_succeeded == 0
    assert result.objects_failed == 0
    assert result.outcomes == ()
    assert result.analysis_run_ids == ()
    assert result.incident_ids == ()
    assert result.records_seen == 0
    assert result.incidents_created == 0
    assert len(client.get_calls) == 0


def test_pagination_collects_all_pages_and_stops_early_on_bound() -> None:
    client = _FakeS3Client()
    first = [(f"key-{position:03d}.json", b'{"Records": []}') for position in range(60)]
    second = [(f"key-{position:03d}.json", b'{"Records": []}') for position in range(60, 120)]
    third = [(f"key-{position:03d}.json", b'{"Records": []}') for position in range(120, 180)]
    client.list_pages.extend(
        [
            {**_page(*first), "IsTruncated": True, "NextContinuationToken": "t1"},
            {**_page(*second), "IsTruncated": True, "NextContinuationToken": "t2"},
            {**_page(*third), "IsTruncated": False},
        ]
    )

    summaries = _adapter(client).list_objects(
        bucket=BUCKET, prefix=PREFIX, max_objects=100
    )

    assert len(summaries) == 100
    assert len(client.list_calls) == 2
    assert client.list_calls[1]["ContinuationToken"] == "t1"
    import dataclasses

    assert [field.name for field in dataclasses.fields(summaries[0])] == [
        "key",
        "size",
        "etag",
    ]


def test_truncated_listing_without_token_fails_safely() -> None:
    from trailweaver.aws_s3 import S3CloudTrailSourceError

    client = _FakeS3Client()
    client.list_pages.append({"Contents": [], "IsTruncated": True})

    with pytest.raises(S3CloudTrailSourceError, match="continuation token"):
        _adapter(client).list_objects(bucket=BUCKET, prefix=PREFIX)


def test_single_valid_object_uses_ordinary_run_semantics(tmp_path: Path) -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())
    client.list_pages.append(_page((key, _attack_bytes())))
    repository, runner = _sqlite_runner(tmp_path / "single.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_discovered == 1
    assert result.objects_succeeded == 1
    assert result.objects_failed == 0
    assert result.incidents_created == 1
    assert len(result.analysis_run_ids) == 1
    assert len(result.incident_ids) == 1
    assert result.records_seen == 3
    outcome = result.outcomes[0]
    assert outcome.key == key
    assert outcome.status is S3PrefixObjectStatus.SUCCEEDED
    assert outcome.analysis_run_id == result.analysis_run_ids[0]
    assert outcome.error_category is None
    assert len(repository.list_incidents()) == 1


def test_multiple_objects_process_in_lexical_key_order(tmp_path: Path) -> None:
    client = _FakeS3Client()
    keys = [f"{PREFIX}c-admin.json", f"{PREFIX}a-login.json", f"{PREFIX}b-key.json"]
    payloads = {
        keys[0]: _single_event_document("AttachUserPolicy"),
        keys[1]: _single_event_document("ConsoleLogin"),
        keys[2]: _single_event_document("CreateAccessKey"),
    }
    for key, content in payloads.items():
        client.objects[key] = _response(content)
    client.list_pages.append(_page(*[(key, payloads[key]) for key in keys]))
    _, runner = _sqlite_runner(tmp_path / "lexical.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert [outcome.key for outcome in result.outcomes] == sorted(keys)
    assert [call["Key"] for call in client.get_calls] == sorted(keys)
    # Event times run admin/key/login while lexical order differs; the
    # cross-object correlation still forms through M32 event-time handling.
    assert result.incidents_created == 1
    assert result.signals_created == 3


def test_gzip_object_analyzed_through_existing_path(tmp_path: Path) -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}export.json.gz"
    client.objects[key] = _response(gzip.compress(_attack_bytes()))
    client.list_pages.append(_page((key, gzip.compress(_attack_bytes()))))
    _, runner = _sqlite_runner(tmp_path / "gzip.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_succeeded == 1
    assert result.incidents_created == 1


def test_partial_failure_continues_with_later_objects(tmp_path: Path) -> None:
    client = _FakeS3Client()
    good_a = f"{PREFIX}a-valid.json"
    bad = f"{PREFIX}b-broken.json.gz"
    good_c = f"{PREFIX}c-valid.json"
    client.objects[good_a] = _response(_attack_bytes())
    client.objects[bad] = _response(b"\x1f\x8bnot actually gzip content")
    client.objects[good_c] = _response(_attack_bytes())
    client.list_pages.append(
        _page(
            (good_a, _attack_bytes()),
            (bad, b"\x1f\x8bnot actually gzip content"),
            (good_c, _attack_bytes()),
        )
    )
    repository, runner = _sqlite_runner(tmp_path / "partial.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_discovered == 3
    assert result.objects_attempted == 3
    assert result.objects_succeeded == 2
    assert result.objects_failed == 1
    failed = next(
        outcome for outcome in result.outcomes if outcome.status is S3PrefixObjectStatus.FAILED
    )
    assert failed.key == bad
    assert failed.error_category == "invalid_gzip"
    assert failed.analysis_run_id is None
    assert "sensitive AWS response details" not in (failed.error_message or "")
    # Second valid object still executed; its events were already known, so
    # no second incident was created.
    assert result.incidents_created == 1
    assert len(repository.list_incidents()) == 1


def test_object_failure_taxonomy(tmp_path: Path) -> None:
    cases = [
        ("missing.json", "not_found", {"deleted": True}),
        ("denied.json", "access_denied", {"denied": True}),
        ("bad.json", "invalid_json", {"content": b"not json at all"}),
        ("envelope.json", "invalid_envelope", {"content": b'{"unexpected": 1}'}),
    ]
    for key, category, setup in cases:
        client = _FakeS3Client()
        full_key = f"{PREFIX}{key}"
        if setup.get("deleted"):
            client.object_errors[full_key] = _client_error("NoSuchKey")
        elif setup.get("denied"):
            client.object_errors[full_key] = _client_error("AccessDenied")
        else:
            content = setup["content"]
            assert isinstance(content, bytes)
            client.objects[full_key] = _response(content)
        client.list_pages.append(_page((full_key, b"")))
        _, runner = _sqlite_runner(tmp_path / f"{key}.sqlite3")

        result = _adapter(client).analyze_prefix(
            runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
        )

        assert result.objects_failed == 1, key
        assert result.outcomes[0].error_category == category, key
        assert result.incidents_created == 0


def test_listed_oversize_object_skipped_without_get(tmp_path: Path) -> None:
    client = _FakeS3Client()
    big_key = f"{PREFIX}big.json"
    client.objects[big_key] = _response(_attack_bytes())
    oversized = {
        "Contents": [
            {"Key": big_key, "Size": 100 * 1024 * 1024, "ETag": '"x"'},
        ],
        "IsTruncated": False,
    }
    client.list_pages.append(oversized)
    _, runner = _sqlite_runner(tmp_path / "big.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_failed == 1
    assert result.outcomes[0].error_category == "object_too_large"
    assert client.get_calls == []


def test_decompressed_too_large_is_object_failure(tmp_path: Path) -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}bomb.json.gz"
    client.objects[key] = _response(gzip.compress(_attack_bytes()))
    client.list_pages.append(_page((key, gzip.compress(_attack_bytes()))))
    _, runner = _sqlite_runner(tmp_path / "bomb.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner,
        bucket=BUCKET,
        prefix=PREFIX,
        max_objects=10,
        max_decompressed_bytes=16,
    )

    assert result.objects_failed == 1
    assert result.outcomes[0].error_category == "decompressed_too_large"


def test_record_level_issues_keep_object_successful(tmp_path: Path) -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}mixed.json"
    content = (SAMPLES / "mixed-records.json").read_bytes()
    client.objects[key] = _response(content)
    client.list_pages.append(_page((key, content)))
    _, runner = _sqlite_runner(tmp_path / "mixed.sqlite3")

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_succeeded == 1
    assert result.records_seen == 4
    assert result.records_accepted == 2


def test_listing_failure_aborts_with_zero_runs(tmp_path: Path) -> None:
    from trailweaver.aws_s3 import S3CloudTrailSourceError

    client = _FakeS3Client()
    client.list_error = _client_error("AccessDenied")
    repository, runner = _sqlite_runner(tmp_path / "listfail.sqlite3")

    with pytest.raises(S3CloudTrailSourceError):
        _adapter(client).analyze_prefix(
            runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
        )

    assert repository.list_runs() == ()
    assert repository.list_incidents() == ()
    assert client.get_calls == []


def test_internal_persistence_failure_aborts_later_objects(tmp_path: Path) -> None:
    class _AlwaysFailingRepository(InMemoryIncidentRepository):
        def save_incident(self, incident):  # type: ignore[no-untyped-def]
            raise IncidentRepositoryError("storage unavailable for this test")

        def save_incident_if_correlation_new(  # type: ignore[no-untyped-def]
            self, incident, correlation_key
        ):
            raise IncidentRepositoryError("storage unavailable for this test")

    client = _FakeS3Client()
    first = f"{PREFIX}a.json"
    second = f"{PREFIX}b.json"
    client.objects[first] = _response(_attack_bytes())
    client.objects[second] = _response(_attack_bytes())
    client.list_pages.append(_page((first, _attack_bytes()), (second, _attack_bytes())))
    runner = create_default_investigation_runner(_AlwaysFailingRepository())

    with pytest.raises(IncidentRepositoryError):
        _adapter(client).analyze_prefix(
            runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
        )

    assert [call["Key"] for call in client.get_calls] == [first]


def test_same_event_across_objects_processed_once(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "cross.sqlite3")
    client = _FakeS3Client()
    key_a = f"{PREFIX}a.json"
    key_b = f"{PREFIX}b.json"
    client.objects[key_a] = _response(_attack_bytes())
    client.objects[key_b] = _response(_attack_bytes())
    client.list_pages.append(_page((key_a, _attack_bytes()), (key_b, _attack_bytes())))

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_succeeded == 2
    assert len(result.analysis_run_ids) == 2
    assert result.analysis_run_ids[0] != result.analysis_run_ids[1]
    assert result.signals_created == 3
    assert result.incidents_created == 1
    assert len(repository.list_incidents()) == 1


def test_cross_object_m32_incident_forms_naturally(tmp_path: Path) -> None:
    repository, runner = _sqlite_runner(tmp_path / "m32.sqlite3")
    client = _FakeS3Client()
    login_key = f"{PREFIX}a-login.json"
    key_key = f"{PREFIX}b-key.json"
    admin_key = f"{PREFIX}c-admin.json"
    payloads = {
        login_key: _single_event_document("ConsoleLogin"),
        key_key: _single_event_document("CreateAccessKey"),
        admin_key: _single_event_document("AttachUserPolicy"),
    }
    for key, content in payloads.items():
        client.objects[key] = _response(content)
    client.list_pages.append(_page(*[(key, payloads[key]) for key in sorted(payloads)]))

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_succeeded == 3
    assert result.signals_created == 3
    assert result.incidents_created == 1
    assert len(repository.list_incidents()) == 1
    assert [
        entry.rule_id for entry in repository.list_incidents()[0].timeline
    ] == [
        "aws.auth.console_login_without_mfa",
        "aws.iam.access_key_created",
        "aws.iam.admin_policy_attached_to_user",
    ]


def _sqlite_runner(
    database: Path,
) -> tuple[SQLiteIncidentRepository, InvestigationRunner]:
    repository = SQLiteIncidentRepository(database)
    return repository, create_default_investigation_runner(
        repository,
        analysis_run_repository=repository,
        event_ledger_repository=repository,
        signal_history_repository=repository,
    )


def test_prefix_replay_creates_runs_but_no_duplicate_incidents(
    tmp_path: Path,
) -> None:
    repository, runner = _sqlite_runner(tmp_path / "replay.sqlite3")
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())

    def _run() -> None:
        client.objects[key] = _response(_attack_bytes())
        client.list_pages.clear()
        client.list_pages.append(_page((key, _attack_bytes())))
        client.get_calls.clear()
        client.list_calls.clear()

    _run()
    first = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )
    _run()
    second = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert first.incidents_created == 1
    assert second.incidents_created == 0
    assert len(first.analysis_run_ids) == 1
    assert len(second.analysis_run_ids) == 1
    assert first.analysis_run_ids != second.analysis_run_ids
    assert len(repository.list_incidents()) == 1


def test_aggregate_counts_and_invariants(tmp_path: Path) -> None:
    _, runner = _sqlite_runner(tmp_path / "counts.sqlite3")
    client = _FakeS3Client()
    good = f"{PREFIX}good.json"
    bad = f"{PREFIX}bad.json"
    client.objects[good] = _response(_attack_bytes())
    client.objects[bad] = _response(b"not json")
    client.list_pages.append(_page((good, _attack_bytes()), (bad, b"not json")))

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )

    assert result.objects_discovered == 2
    assert result.objects_attempted == 2
    assert result.objects_succeeded == 1
    assert result.objects_failed == 1
    assert result.objects_discovered <= 10
    assert result.records_seen == 3
    assert result.records_accepted == 3
    assert result.signals_created == 3
    assert result.correlations_created == 1
    assert result.incidents_created == 1
    assert len(result.incident_ids) == 1


def test_aggregate_contains_no_object_contents_or_boto_metadata(
    tmp_path: Path,
) -> None:
    import json as json_module

    _, runner = _sqlite_runner(tmp_path / "safe.sqlite3")
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(
        _attack_bytes(), ETag='"secret-etag"', VersionId="secret-version"
    )
    denied_key = f"{PREFIX}denied.json"
    client.object_errors[denied_key] = _client_error("AccessDenied")
    client.list_pages.append(
        _page(
            (key, _attack_bytes()),
            (denied_key, b""),
        )
    )

    result = _adapter(client).analyze_prefix(
        runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
    )
    serialized = json_module.dumps(
        {
            "outcomes": [
                {
                    "key": outcome.key,
                    "status": outcome.status.value,
                    "error_category": outcome.error_category,
                    "error_message": outcome.error_message,
                    "incident_ids": list(outcome.incident_ids),
                }
                for outcome in result.outcomes
            ],
            "incident_ids": list(result.incident_ids),
        }
    )

    assert "secret-etag" not in serialized
    assert "secret-version" not in serialized
    assert "sensitive AWS response details" not in serialized
    assert "fictional-owner" not in serialized
    assert "StorageClass" not in serialized


def test_max_objects_bounds_and_defaults() -> None:
    assert DEFAULT_S3_PREFIX_MAX_OBJECTS == 100
    assert MAX_S3_PREFIX_MAX_OBJECTS == 1000

    assert RuntimeConfig.from_environment({}).s3_max_objects == 100
    assert (
        RuntimeConfig.from_environment({"TRAILWEAVER_S3_MAX_OBJECTS": "25"}).s3_max_objects
        == 25
    )
    for bad in ("0", "1001", "-5", "many", ""):
        with pytest.raises(RuntimeConfigurationError):
            RuntimeConfig.from_environment({"TRAILWEAVER_S3_MAX_OBJECTS": bad})


def test_earlier_committed_object_work_survives_abort(tmp_path: Path) -> None:
    from trailweaver.api.service import SaveIncidentOutcome
    from trailweaver.incidents import Incident

    class _FailOnSecondAtomicSave(InMemoryIncidentRepository):
        def __init__(self) -> None:
            super().__init__()
            self.atomic_attempts = 0

        def save_incident_if_correlation_new(
            self, incident: Incident, correlation_key: str
        ) -> SaveIncidentOutcome:
            self.atomic_attempts += 1
            if self.atomic_attempts == 2:
                raise IncidentRepositoryError("storage unavailable for this test")
            return super().save_incident_if_correlation_new(incident, correlation_key)

    other = _attack_bytes().replace(b"aaaaaaaa-1111", b"dddddddd-4444")
    other = other.replace(b"bbbbbbbb-2222", b"eeeeeeee-5555")
    other = other.replace(b"cccccccc-3333", b"ffffffff-6666")
    first = f"{PREFIX}a.json"
    second = f"{PREFIX}b.json"
    client = _FakeS3Client()
    client.objects[first] = _response(_attack_bytes())
    client.objects[second] = _response(other)
    client.list_pages.append(_page((first, _attack_bytes()), (second, other)))
    repository = _FailOnSecondAtomicSave()
    runner = create_default_investigation_runner(repository)

    with pytest.raises(IncidentRepositoryError):
        _adapter(client).analyze_prefix(
            runner, bucket=BUCKET, prefix=PREFIX, max_objects=10
        )

    assert len(repository.list_incidents()) == 1


def _api_client(app):  # type: ignore[no-untyped-def]
    import asyncio

    import httpx

    class _Client:
        def __init__(self, application) -> None:  # type: ignore[no-untyped-def]
            self._application = application

        def get(self, path: str):  # type: ignore[no-untyped-def]
            async def request():  # type: ignore[no-untyped-def]
                transport = httpx.ASGITransport(app=self._application)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://testserver"
                ) as api_client:
                    return await api_client.get(path)

            return asyncio.run(request())

        def post(self, path: str, *, json_body=None):  # type: ignore[no-untyped-def]
            async def request():  # type: ignore[no-untyped-def]
                transport = httpx.ASGITransport(app=self._application)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://testserver"
                ) as api_client:
                    return await api_client.post(path, json=json_body)

            return asyncio.run(request())

    return _Client(app)


def _api_app_with_fake(client: _FakeS3Client):
    from trailweaver.api.app import create_app

    application = create_app()
    application.state.s3_adapter_factory = lambda region: S3CloudTrailAdapter(client)
    return application


def test_prefix_api_returns_bounded_aggregate() -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())
    client.list_pages.append(_page((key, _attack_bytes())))
    api = _api_client(_api_app_with_fake(client))

    response = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["bucket"] == BUCKET
    assert body["prefix"] == PREFIX
    assert body["max_objects"] == 100
    assert body["objects_discovered"] == 1
    assert body["objects_attempted"] == 1
    assert body["objects_succeeded"] == 1
    assert body["objects_failed"] == 0
    assert len(body["analysis_run_ids"]) == 1
    assert len(body["incident_ids"]) == 1
    assert body["records_seen"] == 3
    assert body["signals_created"] == 3
    assert body["incidents_created"] == 1
    assert body["outcomes"][0]["key"] == key
    assert body["outcomes"][0]["status"] == "succeeded"
    assert set(body) == {
        "bucket",
        "prefix",
        "max_objects",
        "objects_discovered",
        "objects_attempted",
        "objects_succeeded",
        "objects_failed",
        "analysis_run_ids",
        "incident_ids",
        "records_seen",
        "records_accepted",
        "signals_created",
        "correlations_created",
        "incidents_created",
        "outcomes",
    }
    assert set(body["outcomes"][0]) == {
        "key",
        "status",
        "analysis_run_id",
        "records_seen",
        "records_accepted",
        "signals_created",
        "correlations_created",
        "incidents_created",
        "incident_ids",
        "error_category",
        "error_message",
    }
    for forbidden in ("raw_event", "etag", "version_id", "Body", "StorageClass"):
        assert forbidden not in response.text


def test_prefix_api_validation() -> None:
    api = _api_client(_api_app_with_fake(_FakeS3Client()))

    blank = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": "   "},
    )
    assert blank.status_code == 422

    for bad_max in (0, 1001):
        rejected = api.post(
            "/api/v1/analyses/s3-prefix",
            json_body={"bucket": BUCKET, "prefix": PREFIX, "max_objects": bad_max},
        )
        assert rejected.status_code == 422

    with_credentials = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={
            "bucket": BUCKET,
            "prefix": PREFIX,
            "aws_access_key_id": "AKIAEXAMPLE",
        },
    )
    assert with_credentials.status_code == 422

    with_extra = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX, "unknown_field": 1},
    )
    assert with_extra.status_code == 422


def test_prefix_api_partial_failure_returns_200_aggregate() -> None:
    client = _FakeS3Client()
    good = f"{PREFIX}good.json"
    bad = f"{PREFIX}bad.json"
    client.objects[good] = _response(_attack_bytes())
    client.objects[bad] = _response(b"not json")
    client.list_pages.append(_page((good, _attack_bytes()), (bad, b"not json")))
    api = _api_client(_api_app_with_fake(client))

    response = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["objects_succeeded"] == 1
    assert body["objects_failed"] == 1
    failed = next(
        outcome for outcome in body["outcomes"] if outcome["status"] == "failed"
    )
    assert failed["key"] == bad
    assert failed["error_category"] == "invalid_json"
    assert "sensitive AWS response details" not in response.text


def test_prefix_api_zero_objects_returns_empty_200() -> None:
    client = _FakeS3Client()
    client.list_pages.append({"Contents": [], "IsTruncated": False})
    api = _api_client(_api_app_with_fake(client))

    response = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX},
    )

    assert response.status_code == 200
    assert response.json()["objects_discovered"] == 0
    assert response.json()["outcomes"] == []


def test_prefix_api_listing_failure_maps_to_502() -> None:
    client = _FakeS3Client()
    client.list_error = _client_error("AccessDenied")
    api = _api_client(_api_app_with_fake(client))

    response = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX},
    )

    assert response.status_code == 502
    assert "sensitive AWS response details" not in response.text


def test_prefix_api_storage_failure_maps_to_503(tmp_path: Path) -> None:
    from trailweaver.api.app import create_app
    from trailweaver.api.sqlite_repository import IncidentRepositoryError

    class _FailingRepository(InMemoryIncidentRepository):
        def save_incident_if_correlation_new(  # type: ignore[no-untyped-def]
            self, incident, correlation_key
        ):
            raise IncidentRepositoryError("storage unavailable for this test")

    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())
    client.list_pages.append(_page((key, _attack_bytes())))
    application = create_app(repository=_FailingRepository())
    application.state.s3_adapter_factory = lambda region: S3CloudTrailAdapter(client)
    api = _api_client(application)

    response = api.post(
        "/api/v1/analyses/s3-prefix",
        json_body={"bucket": BUCKET, "prefix": PREFIX},
    )

    assert response.status_code == 503


def test_single_object_api_response_keys_unchanged() -> None:
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())
    api = _api_client(_api_app_with_fake(client))

    body = api.post(
        "/api/v1/analyses/s3",
        json_body={"bucket": BUCKET, "key": key},
    ).json()

    assert set(body) == {
        "analysis_run_id",
        "source_type",
        "started_at",
        "completed_at",
        "source_label",
        "total_records",
        "accepted_records",
        "failed_records",
        "duplicate_records",
        "events_analyzed",
        "signals",
        "correlations",
        "incidents_created",
        "persisted_incidents",
        "incident_ids",
        "issues",
    }


def test_cli_prefix_success_and_partial_and_empty(tmp_path: Path) -> None:
    client = _FakeS3Client()
    good_a = f"{PREFIX}a.json"
    bad = f"{PREFIX}b.json"
    good_c = f"{PREFIX}c.json"
    client.objects[good_a] = _response(_attack_bytes())
    client.objects[bad] = _response(b"not json")
    client.objects[good_c] = _response(_attack_bytes())
    client.list_pages.append(
        _page(
            (good_a, _attack_bytes()),
            (bad, b"not json"),
            (good_c, _attack_bytes()),
        )
    )
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "prefix.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == EXIT_SOURCE_ERROR
    text = output.getvalue()
    assert f"{good_a}: ok" in text
    assert f"{bad}: failed (invalid_json:" in text
    assert "objects succeeded: 2" in text
    assert "objects failed: 1" in text
    assert "incidents: 1" in text
    assert "sensitive AWS response details" not in text


def test_cli_prefix_zero_objects_exits_success(tmp_path: Path) -> None:
    client = _FakeS3Client()
    client.list_pages.append({"Contents": [], "IsTruncated": False})
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "zero.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == EXIT_SUCCESS
    assert "objects discovered: 0" in output.getvalue()


def test_cli_prefix_all_fail_exits_source_error(tmp_path: Path) -> None:
    client = _FakeS3Client()
    bad = f"{PREFIX}bad.json"
    client.objects[bad] = _response(b"not json")
    client.list_pages.append(_page((bad, b"not json")))
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "allfail.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == EXIT_SOURCE_ERROR


def test_cli_prefix_listing_failure_exits_runtime_error(tmp_path: Path) -> None:
    client = _FakeS3Client()
    client.list_error = _client_error("AccessDenied")
    output = StringIO()
    errors = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "listfail.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
        ],
        environment={},
        stdout=output,
        stderr=errors,
        s3_client=client,
    )

    assert exit_code == EXIT_RUNTIME_ERROR
    assert "sensitive AWS response details" not in output.getvalue()
    assert "sensitive AWS response details" not in errors.getvalue()


def test_cli_prefix_persistence_failure_exits_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trailweaver.api.sqlite_repository import (
        IncidentRepositoryError,
        SQLiteIncidentRepository,
    )

    def _unavailable(
        self, incident: object, correlation_key: str
    ) -> object:
        raise IncidentRepositoryError("storage unavailable for this test")

    monkeypatch.setattr(
        SQLiteIncidentRepository,
        "save_incident_if_correlation_new",
        _unavailable,
    )
    client = _FakeS3Client()
    key = f"{PREFIX}export.json"
    client.objects[key] = _response(_attack_bytes())
    client.list_pages.append(_page((key, _attack_bytes())))
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "persistfail.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == EXIT_RUNTIME_ERROR


def test_cli_prefix_argument_validation(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as blank:
        main(
            [
                "--database",
                str(tmp_path / "arg.sqlite3"),
                "analyze-s3-prefix",
                "--bucket",
                BUCKET,
                "--prefix",
                "   ",
            ],
            environment={},
            stdout=StringIO(),
            s3_client=_FakeS3Client(),
        )
    assert blank.value.code == 2

    with pytest.raises(SystemExit) as too_many:
        main(
            [
                "--database",
                str(tmp_path / "arg.sqlite3"),
                "analyze-s3-prefix",
                "--bucket",
                BUCKET,
                "--prefix",
                PREFIX,
                "--max-objects",
                "1001",
            ],
            environment={},
            stdout=StringIO(),
            s3_client=_FakeS3Client(),
        )
    assert too_many.value.code == 2


def test_cli_prefix_respects_explicit_bound(tmp_path: Path) -> None:
    client = _FakeS3Client()
    keys = [f"{PREFIX}obj-{position}.json" for position in range(5)]
    for key in keys:
        client.objects[key] = _response(b'{"Records": []}')
    client.list_pages.append(_page(*[(key, b'{"Records": []}') for key in keys]))
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "bound.sqlite3"),
            "analyze-s3-prefix",
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
            "--max-objects",
            "2",
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == EXIT_SUCCESS
    assert "objects discovered: 2" in output.getvalue()
