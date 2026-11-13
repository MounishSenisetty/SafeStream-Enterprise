"""The scan-result cache must never change what is redacted or what is counted."""

from __future__ import annotations

import json
import pickle

from hypothesis import given, settings
from hypothesis import strategies as st
from safestream_redactor import RedactionMode, RedactionStats

from safestream_enterprise.parsers.json_ast import StructuredRedactor
from safestream_enterprise.rules import make_redactor

# A small pool, so values repeat across records and the cache is exercised,
# mixing benign values with ones the content detectors catch.
VALUES = (
    st.sampled_from(
        [
            "info",
            "GET /api/orders",
            "checkout",
            "mail bob@corp.example now",
            "card 4111 1111 1111 1111",
            "key AKIAIOSFODNN7EXAMPLE",
            "10.1.2.3",
            "",
            "x" * 300,  # too long to cache
            "AKIAIOSFODNN7EXAMPLE " * 20,  # too long to cache, and sensitive
        ]
    )
    | st.integers(-(10**17), 10**17)
    | st.just(4111111111111111)
)
RECORDS = st.lists(
    st.dictionaries(st.sampled_from(["msg", "level", "path", "n", "note"]), VALUES, max_size=5),
    min_size=1,
    max_size=30,
)


def run(redactor: StructuredRedactor, records: list[dict[str, object]]) -> tuple[list[str], dict]:
    stats = RedactionStats()
    out = [redactor.redact_line(json.dumps(r), stats).text for r in records]
    return out, dict(stats.counts)


@settings(max_examples=150, deadline=None)
@given(
    RECORDS,
    st.sampled_from([RedactionMode.REPLACE, RedactionMode.MASK, RedactionMode.PSEUDONYMIZE]),
)
def test_cache_changes_nothing(records: list[dict[str, object]], mode: RedactionMode) -> None:
    key = b"k" * 32 if mode is RedactionMode.PSEUDONYMIZE else None
    cached = make_redactor(mode, key)
    plain = make_redactor(mode, key)
    plain._value_cache_size = 0
    # Twice over the same records: the second pass is served mostly from the cache.
    assert run(cached, records) == run(plain, records)
    assert run(cached, records) == run(plain, records)


def test_repeated_values_are_served_from_the_cache_without_keeping_them() -> None:
    redactor = StructuredRedactor()
    record = '{"level":"info","msg":"mail bob@corp.example now"}'
    for _ in range(3):
        assert redactor.redact_line(record).text == '{"level":"info","msg":"mail [REDACTED] now"}'
    assert redactor.value_cache_hits == 4  # two values, second and third time
    # Neither the raw value nor anything derived from it but the redacted text.
    stored = pickle.dumps(redactor._value_cache)
    assert b"bob@corp.example" not in stored and b"info" not in stored


def test_a_full_cache_starts_over() -> None:
    redactor = StructuredRedactor(value_cache_size=2)
    for word in ("alpha", "bravo", "charlie"):
        redactor.redact_line(json.dumps({"msg": word}))
    assert len(redactor._value_cache) == 1
