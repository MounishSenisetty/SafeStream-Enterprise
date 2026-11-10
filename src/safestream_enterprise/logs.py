"""Logging setup shared by the ``safestream-kafka`` and ``safestream-batch`` entry points.

``LOG_LEVEL``   standard level name (default ``INFO``); an unknown name falls
                back to ``INFO`` with a warning instead of a traceback.
``LOG_FORMAT``  ``text`` (default) or ``json``: one JSON object per line, for
                log pipelines that parse rather than grep.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TextIO


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out)


def configure_logging(stream: TextIO | None = None) -> None:
    """Configure the root logger from ``LOG_LEVEL`` and ``LOG_FORMAT`` (stderr by default)."""
    name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = logging.getLevelName(name)  # the int for a known name, else a string
    fmt = os.environ.get("LOG_FORMAT", "text").lower()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        JsonFormatter()
        if fmt == "json"
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    logging.basicConfig(level=level if isinstance(level, int) else logging.INFO, handlers=[handler])
    if not isinstance(level, int):
        logging.getLogger(__name__).warning("unknown LOG_LEVEL %r; using INFO", name)
    if fmt not in ("text", "json"):
        logging.getLogger(__name__).warning("unknown LOG_FORMAT %r; using text", fmt)
