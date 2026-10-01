"""Small, evidence-safe structured logging helpers."""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import IO, TypeAlias

LogValue: TypeAlias = str | int | float | bool | None


class JsonLogFormatter(logging.Formatter):
    """Format TrailWeaver records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, LogValue] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "trailweaver_fields", {})
        if isinstance(fields, dict):
            for key, value in sorted(fields.items()):
                if key not in payload and isinstance(key, str) and (
                    value is None or isinstance(value, (str, int, float, bool))
                ):
                    payload[key] = value
        if record.exc_info is not None and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging(level: str, *, stream: IO[str] | None = None) -> None:
    """Configure only TrailWeaver's logger hierarchy with structured output."""

    logger = logging.getLogger("trailweaver")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLogFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: LogValue,
) -> None:
    """Emit a named event with a deliberately limited set of scalar fields."""

    logger.log(level, event, extra={"trailweaver_fields": fields})


def safe_source_label(label: str | None) -> str | None:
    """Return bounded provenance without exposing an absolute local path."""

    if label is None:
        return None
    cleaned = "".join(character for character in label if character.isprintable())[:256]
    if not cleaned:
        return None
    local_path = Path(cleaned)
    if local_path.is_absolute():
        return local_path.name
    windows_path = PureWindowsPath(cleaned)
    if windows_path.is_absolute():
        return windows_path.name
    return cleaned
