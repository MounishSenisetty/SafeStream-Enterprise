"""LOG_LEVEL / LOG_FORMAT handling."""

from __future__ import annotations

import io
import json
import logging

import pytest

from safestream_enterprise.logs import configure_logging


def configure(out: io.StringIO, monkeypatch: pytest.MonkeyPatch) -> None:
    # basicConfig only acts on a root logger without handlers (pytest adds its own).
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setattr(logging.getLogger(), "level", logging.WARNING)
    configure_logging(out)


def test_json_format_emits_one_object_per_line(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_FORMAT", "json")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    out = io.StringIO()
    configure(out, monkeypatch)
    logging.getLogger("x").debug("hello %s", "world")
    event = json.loads(out.getvalue())
    assert (event["level"], event["logger"], event["message"]) == ("DEBUG", "x", "hello world")


def test_unknown_level_falls_back_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "LOUD")
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    out = io.StringIO()
    configure(out, monkeypatch)
    assert logging.getLogger().level == logging.INFO
    assert "unknown LOG_LEVEL 'LOUD'" in out.getvalue()
