"""Validated operational configuration for TrailWeaver entry points."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_LOG_LEVELS = frozenset({"critical", "error", "warning", "info", "debug"})


class RuntimeConfigurationError(ValueError):
    """Raised when operational configuration is invalid."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    database_path: Path
    aws_region: str | None = None
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    log_level: str = "info"

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "RuntimeConfig":
        values = os.environ if environment is None else environment
        database = values.get("TRAILWEAVER_DATABASE_PATH")
        database_path = (
            Path(database).expanduser()
            if database
            else _default_database_path(values)
        )
        region = _optional_value(values.get("TRAILWEAVER_AWS_REGION"))
        host = values.get("TRAILWEAVER_API_HOST", "127.0.0.1").strip()
        port = _parse_port(values.get("TRAILWEAVER_API_PORT", "8000"))
        origins = _parse_origins(
            values.get("TRAILWEAVER_CORS_ORIGINS", "http://localhost:5173")
        )
        log_level = values.get("TRAILWEAVER_LOG_LEVEL", "info").strip().lower()

        if not host:
            raise RuntimeConfigurationError("TRAILWEAVER_API_HOST must be non-empty")
        if log_level not in _LOG_LEVELS:
            raise RuntimeConfigurationError(
                "TRAILWEAVER_LOG_LEVEL must be critical, error, warning, info, or debug"
            )
        return cls(
            database_path=database_path,
            aws_region=region,
            api_host=host,
            api_port=port,
            cors_origins=origins,
            log_level=log_level,
        )


def _default_database_path(environment: Mapping[str, str]) -> Path:
    data_home = environment.get("XDG_DATA_HOME")
    home = Path(environment.get("HOME", str(Path.home()))).expanduser()
    root = Path(data_home).expanduser() if data_home else home / ".local" / "share"
    return root / "trailweaver" / "incidents.sqlite3"


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise RuntimeConfigurationError(
            "TRAILWEAVER_API_PORT must be an integer"
        ) from error
    if not 1 <= port <= 65535:
        raise RuntimeConfigurationError(
            "TRAILWEAVER_API_PORT must be between 1 and 65535"
        )
    return port


def _parse_origins(value: str) -> tuple[str, ...]:
    origins = tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    return validate_cors_origins(origins)


def validate_cors_origins(origins: tuple[str, ...]) -> tuple[str, ...]:
    """Require explicit HTTP(S) origins without credentials, paths, or queries."""

    for origin in origins:
        if origin == "*":
            raise RuntimeConfigurationError(
                "TRAILWEAVER_CORS_ORIGINS must list explicit origins, not '*'"
            )
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeConfigurationError(
                "TRAILWEAVER_CORS_ORIGINS must contain only HTTP(S) origins"
            )
    return origins


def _optional_value(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
