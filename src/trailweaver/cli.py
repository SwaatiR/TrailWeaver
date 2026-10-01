"""Thin command-line adapter for TrailWeaver application services."""

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

import uvicorn

from trailweaver.api.app import create_persistent_app
from trailweaver.api.execution import (
    InvestigationExecutionResult,
    create_default_investigation_runner,
)
from trailweaver.api.sqlite_repository import (
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)
from trailweaver.aws_s3 import (
    DEFAULT_MAX_S3_OBJECT_BYTES,
    S3Client,
    S3CloudTrailAdapter,
    S3CloudTrailSourceError,
)
from trailweaver.cloudtrail_ingestion import (
    DEFAULT_MAX_SOURCE_BYTES,
    CloudTrailIngestionError,
)
from trailweaver.runtime import RuntimeConfig, RuntimeConfigurationError

EXIT_SUCCESS = 0
EXIT_SOURCE_ERROR = 3
EXIT_RUNTIME_ERROR = 4

ServerRunner = Callable[..., None]


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    s3_client: S3Client | None = None,
    server_runner: ServerRunner | None = None,
) -> int:
    """Run one CLI command and return a process exit code."""

    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    try:
        config = RuntimeConfig.from_environment(environment)
    except RuntimeConfigurationError as error:
        print(f"Configuration error: {error}", file=errors)
        return EXIT_RUNTIME_ERROR

    parser = _build_parser(config)
    arguments = parser.parse_args(argv)
    database_path = Path(arguments.database).expanduser()

    try:
        if arguments.command == "analyze-file":
            repository = SQLiteIncidentRepository(database_path)
            result = create_default_investigation_runner(repository).run_cloudtrail_file(
                arguments.path,
                source_label=arguments.source_label,
                max_source_bytes=arguments.max_source_bytes,
            )
            _print_summary(result, output)
            return EXIT_SUCCESS

        if arguments.command == "analyze-s3":
            repository = SQLiteIncidentRepository(database_path)
            runner = create_default_investigation_runner(repository)
            adapter = (
                S3CloudTrailAdapter(s3_client)
                if s3_client is not None
                else S3CloudTrailAdapter.from_boto3(region_name=arguments.region)
            )
            result = adapter.run_object(
                runner,
                bucket=arguments.bucket,
                key=arguments.key,
                version_id=arguments.version_id,
                source_label=arguments.source_label,
                max_object_bytes=arguments.max_object_bytes,
                max_decompressed_bytes=arguments.max_decompressed_bytes,
            )
            _print_summary(result, output)
            return EXIT_SUCCESS

        application = create_persistent_app(
            database_path,
            cors_origins=_validated_origins(
                tuple(arguments.cors_origin)
                if arguments.cors_origin is not None
                else config.cors_origins
            ),
        )
        serve = uvicorn.run if server_runner is None else server_runner
        serve(
            application,
            host=arguments.host,
            port=arguments.port,
            log_level=arguments.log_level,
        )
        return EXIT_SUCCESS
    except (CloudTrailIngestionError, S3CloudTrailSourceError) as error:
        print(f"Source error: {error}", file=errors)
        return EXIT_SOURCE_ERROR
    except (IncidentRepositoryError, OSError) as error:
        del error
        print("Runtime error: incident storage is unavailable", file=errors)
        return EXIT_RUNTIME_ERROR
    except RuntimeConfigurationError as error:
        print(f"Configuration error: {error}", file=errors)
        return EXIT_RUNTIME_ERROR


def entrypoint() -> int:
    """Console-script entry point."""

    return main()


def _build_parser(config: RuntimeConfig) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trailweaver",
        description="Analyze AWS CloudTrail evidence with TrailWeaver.",
    )
    parser.add_argument(
        "--database",
        default=str(config.database_path),
        help=(
            "SQLite incident database path "
            "(default: TRAILWEAVER_DATABASE_PATH or the user data directory)"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    file_parser = subparsers.add_parser(
        "analyze-file", help="Analyze one local CloudTrail JSON export"
    )
    file_parser.add_argument("path", type=Path)
    file_parser.add_argument("--source-label")
    file_parser.add_argument(
        "--max-source-bytes", type=_positive_integer, default=DEFAULT_MAX_SOURCE_BYTES
    )

    s3_parser = subparsers.add_parser(
        "analyze-s3", help="Analyze one explicitly named S3 CloudTrail object"
    )
    s3_parser.add_argument("--bucket", required=True, type=_non_empty)
    s3_parser.add_argument("--key", required=True, type=_non_empty)
    s3_parser.add_argument("--version-id")
    s3_parser.add_argument("--region", default=config.aws_region)
    s3_parser.add_argument("--source-label")
    s3_parser.add_argument(
        "--max-object-bytes", type=_positive_integer, default=DEFAULT_MAX_S3_OBJECT_BYTES
    )
    s3_parser.add_argument(
        "--max-decompressed-bytes", type=_positive_integer, default=DEFAULT_MAX_SOURCE_BYTES
    )

    serve_parser = subparsers.add_parser(
        "serve", help="Serve the existing read-only investigation API"
    )
    serve_parser.add_argument("--host", type=_non_empty, default=config.api_host)
    serve_parser.add_argument("--port", type=_port, default=config.api_port)
    serve_parser.add_argument(
        "--cors-origin",
        action="append",
        help="Allowed frontend origin; repeat for multiple explicit origins",
    )
    serve_parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info", "debug"),
        default=config.log_level,
    )
    return parser


def _print_summary(result: InvestigationExecutionResult, output: TextIO) -> None:
    ingestion = result.ingestion_result
    lines = (
        ("source records", ingestion.total_records),
        ("accepted", ingestion.accepted_records),
        ("failed", ingestion.failed_records),
        ("duplicates", ingestion.duplicate_records),
        ("events analyzed", result.analyzed_event_count),
        ("signals", result.signal_count),
        ("correlations", result.correlation_count),
        ("incidents", result.incident_count),
        ("persisted incidents", result.persisted_incident_count),
    )
    for label, value in lines:
        print(f"{label}: {value}", file=output)


def _positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _port(value: str) -> int:
    port = _positive_integer(value)
    if port > 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def _non_empty(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must be non-empty")
    return value


def _validated_origins(origins: tuple[str, ...]) -> tuple[str, ...]:
    if "*" in origins:
        raise RuntimeConfigurationError("CORS origins must be explicit, not '*'")
    return origins
