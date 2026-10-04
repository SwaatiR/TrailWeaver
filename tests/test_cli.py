import json
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from trailweaver.api.sqlite_repository import SQLiteIncidentRepository
from trailweaver.cli import EXIT_RUNTIME_ERROR, EXIT_SOURCE_ERROR, main
from trailweaver.runtime import RuntimeConfig, RuntimeConfigurationError

SAMPLES = Path(__file__).parents[1] / "samples" / "cloudtrail"
ATTACK_FIXTURE = SAMPLES / "account-compromise-sequence.json"


class _FakeS3Client:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.calls: list[dict[str, object]] = []

    def get_object(self, **kwargs: object) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "Body": BytesIO(self.content),
            "ContentLength": len(self.content),
        }

    def list_objects_v2(self, **kwargs: object) -> dict[str, Any]:
        del kwargs
        return {"IsTruncated": False}


def test_help_lists_runtime_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["--help"], environment={})

    assert captured.value.code == 0
    output = capsys.readouterr().out
    assert "analyze-file" in output
    assert "analyze-s3" in output
    assert "serve" in output


def test_local_attack_analysis_persists_incident_and_prints_safe_summary(
    tmp_path: Path,
) -> None:
    database = tmp_path / "incidents.sqlite3"
    output = StringIO()
    errors = StringIO()

    exit_code = main(
        ["--database", str(database), "analyze-file", str(ATTACK_FIXTURE)],
        environment={},
        stdout=output,
        stderr=errors,
    )

    assert exit_code == 0
    log_records = [json.loads(line) for line in errors.getvalue().splitlines()]
    assert [record["event"] for record in log_records] == [
        "investigation_started",
        "investigation_analyzed",
        "investigation_completed",
    ]
    assert "source records: 3" in output.getvalue()
    run_line = next(
        line for line in output.getvalue().splitlines() if line.startswith("analysis run: ")
    )
    assert UUID(run_line.removeprefix("analysis run: ")).version == 4
    assert "signals: 3" in output.getvalue()
    assert "incidents: 1" in output.getvalue()
    assert "persisted incidents: 1" in output.getvalue()
    assert "raw_event" not in output.getvalue()
    assert len(SQLiteIncidentRepository(database).list_incidents()) == 1


def test_benign_file_is_successful_with_zero_incidents(tmp_path: Path) -> None:
    database = tmp_path / "benign.sqlite3"
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(database),
            "analyze-file",
            str(SAMPLES / "empty-records.json"),
        ],
        environment={},
        stdout=output,
    )

    assert exit_code == 0
    assert "incidents: 0" in output.getvalue()


def test_partial_ingestion_summary_preserves_failure_count(tmp_path: Path) -> None:
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "partial.sqlite3"),
            "analyze-file",
            str(SAMPLES / "mixed-records.json"),
        ],
        environment={},
        stdout=output,
    )

    assert exit_code == 0
    assert "source records: 4" in output.getvalue()
    assert "accepted: 2" in output.getvalue()
    assert "failed: 2" in output.getvalue()


def test_s3_command_uses_injected_client_and_existing_pipeline(tmp_path: Path) -> None:
    client = _FakeS3Client(ATTACK_FIXTURE.read_bytes())
    output = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "s3.sqlite3"),
            "analyze-s3",
            "--bucket",
            "fictional-bucket",
            "--key",
            "AWSLogs/export.json",
            "--region",
            "us-east-1",
        ],
        environment={},
        stdout=output,
        s3_client=client,
    )

    assert exit_code == 0
    assert "signals: 3" in output.getvalue()
    run_line = next(
        line for line in output.getvalue().splitlines() if line.startswith("analysis run: ")
    )
    assert UUID(run_line.removeprefix("analysis run: ")).version == 4
    assert client.calls == [
        {"Bucket": "fictional-bucket", "Key": "AWSLogs/export.json"}
    ]


def test_cli_database_flag_overrides_environment(tmp_path: Path) -> None:
    environment_database = tmp_path / "environment.sqlite3"
    flag_database = tmp_path / "flag.sqlite3"

    exit_code = main(
        [
            "--database",
            str(flag_database),
            "analyze-file",
            str(SAMPLES / "empty-records.json"),
        ],
        environment={"TRAILWEAVER_DATABASE_PATH": str(environment_database)},
        stdout=StringIO(),
    )

    assert exit_code == 0
    assert flag_database.exists()
    assert not environment_database.exists()


def test_default_database_is_user_scoped_not_repository_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(Path(__file__).parents[1])
    environment = {"HOME": str(tmp_path)}

    exit_code = main(
        ["analyze-file", str(SAMPLES / "empty-records.json")],
        environment=environment,
        stdout=StringIO(),
    )

    assert exit_code == 0
    assert (tmp_path / ".local/share/trailweaver/incidents.sqlite3").exists()
    assert not (Path.cwd() / "incidents.sqlite3").exists()


def test_serve_uses_validated_environment_and_cli_precedence(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def server_runner(_application: object, **kwargs: object) -> None:
        calls.append(kwargs)

    exit_code = main(
        [
            "--database",
            str(tmp_path / "serve.sqlite3"),
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--cors-origin",
            "https://dashboard.example",
            "--log-level",
            "warning",
        ],
        environment={
            "TRAILWEAVER_API_HOST": "127.0.0.1",
            "TRAILWEAVER_API_PORT": "8000",
        },
        server_runner=server_runner,
    )

    assert exit_code == 0
    assert calls == [
        {
            "host": "0.0.0.0",
            "port": 9000,
            "log_level": "warning",
            "access_log": False,
        }
    ]


def test_missing_file_returns_source_error_without_traceback(tmp_path: Path) -> None:
    errors = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "missing.sqlite3"),
            "analyze-file",
            str(tmp_path / "not-found.json"),
        ],
        environment={},
        stdout=StringIO(),
        stderr=errors,
    )

    assert exit_code == EXIT_SOURCE_ERROR
    assert errors.getvalue().endswith(
        "Source error: Unable to read CloudTrail source file\n"
    )
    assert "source_failed" in errors.getvalue()
    assert "Traceback" not in errors.getvalue()
    assert str(tmp_path) not in errors.getvalue()


def test_invalid_runtime_configuration_has_distinct_exit_code() -> None:
    errors = StringIO()

    exit_code = main(
        ["analyze-file", str(SAMPLES / "empty-records.json")],
        environment={"TRAILWEAVER_API_PORT": "not-a-port"},
        stdout=StringIO(),
        stderr=errors,
    )

    assert exit_code == EXIT_RUNTIME_ERROR
    assert "Configuration error" in errors.getvalue()


def test_runtime_config_parses_prefixed_environment(tmp_path: Path) -> None:
    config = RuntimeConfig.from_environment(
        {
            "TRAILWEAVER_DATABASE_PATH": str(tmp_path / "configured.sqlite3"),
            "TRAILWEAVER_AWS_REGION": "us-west-2",
            "TRAILWEAVER_API_HOST": "0.0.0.0",
            "TRAILWEAVER_API_PORT": "8080",
            "TRAILWEAVER_CORS_ORIGINS": (
                "https://one.example,https://two.example,https://one.example"
            ),
            "TRAILWEAVER_LOG_LEVEL": "DEBUG",
        }
    )

    assert config.database_path == tmp_path / "configured.sqlite3"
    assert config.aws_region == "us-west-2"
    assert config.api_host == "0.0.0.0"
    assert config.api_port == 8080
    assert config.cors_origins == (
        "https://one.example",
        "https://two.example",
    )
    assert config.log_level == "debug"


@pytest.mark.parametrize(
    "origin",
    (
        "dashboard.example",
        "ftp://dashboard.example",
        "https://user:password@dashboard.example",
        "https://dashboard.example/path",
        "https://dashboard.example?token=secret",
    ),
)
def test_runtime_config_rejects_malformed_cors_origins(origin: str) -> None:
    with pytest.raises(RuntimeConfigurationError, match="HTTP\\(S\\) origins"):
        RuntimeConfig.from_environment({"TRAILWEAVER_CORS_ORIGINS": origin})


def test_cli_output_never_contains_raw_evidence_marker(tmp_path: Path) -> None:
    source = tmp_path / "sensitive.json"
    marker = "must-not-appear-in-terminal"
    document = json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))
    document["Records"][0]["requestParameters"]["sensitive"] = marker
    source.write_text(json.dumps(document), encoding="utf-8")
    output = StringIO()
    errors = StringIO()

    exit_code = main(
        [
            "--database",
            str(tmp_path / "safe.sqlite3"),
            "analyze-file",
            str(source),
        ],
        environment={},
        stdout=output,
        stderr=errors,
    )

    assert exit_code == 0
    assert marker not in output.getvalue()
    assert marker not in errors.getvalue()
