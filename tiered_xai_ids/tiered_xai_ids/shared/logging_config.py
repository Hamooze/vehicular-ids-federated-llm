import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from tiered_xai_ids.shared.correlation import get_correlation_id

try:
    import orjson
except ImportError:  # pragma: no cover
    orjson = None

# Matches JSON-encoded raw_log values longer than 40 chars and redacts them.
_RAW_LOG_RE = re.compile(r'("raw_log"\s*:\s*")(.{40,}?)(")', re.DOTALL)
# Matches smtp_password appearing in any formatted log line.
_SMTP_PASS_RE = re.compile(r'(smtp_password\s*[=:]\s*)\S+')


def _redact(message: str) -> str:
    message = _RAW_LOG_RE.sub(r'\1[REDACTED]\3', message)
    message = _SMTP_PASS_RE.sub(r'\1[REDACTED]', message)
    return message


class ContextFilter(logging.Filter):
    def __init__(self, service_name: str) -> None:
        super().__init__()
        self._service_name = service_name

    def filter(self, record: logging.LogRecord) -> bool:
        record.service_name = self._service_name
        record.correlation_id = get_correlation_id()
        if isinstance(record.msg, str):
            record.msg = _redact(record.msg)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service_name", "unknown"),
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", "-"),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if orjson is not None:
            return orjson.dumps(payload).decode("utf-8")
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(service_name: str, level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(ContextFilter(service_name=service_name))
    root.addHandler(handler)
