"""Property tests on the security boundary: whatever the record looks like,
a value under a sensitive field never survives, and the output stays well-formed.
"""

from __future__ import annotations

import contextlib
import json
import xml.etree.ElementTree as ET
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_enterprise import StructuredParseError, StructuredRedactor

REDACTOR = StructuredRedactor()
#: Never produced by the other strategies (they draw from lowercase letters and digits).
CANARY = "ZQ-CANARY-VALUE-QZ"

SENSITIVE_KEYS = st.sampled_from(
    ["password", "Password", "user_password", "LastName", "last-name", "SSN", "cardNumber"]
)
PLAIN_KEYS = st.sampled_from(["id", "level", "service", "count", "region", "items", "meta"])
PLAIN_TEXT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=12)
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-1000, 1000), PLAIN_TEXT)


def json_trees(leaves: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    return st.recursive(
        leaves,
        lambda inner: st.one_of(
            st.lists(inner, max_size=4), st.dictionaries(PLAIN_KEYS, inner, max_size=4)
        ),
        max_leaves=12,
    )


#: Anything a sensitive field can hold: the canary itself, or containers of it.
SECRETS = json_trees(st.just(CANARY))


@st.composite
def records_with_a_secret(draw: st.DrawFn) -> dict[str, Any]:
    """A JSON object with CANARY under a sensitive key, somewhere at any depth."""
    node: dict[str, Any] = {draw(SENSITIVE_KEYS): draw(SECRETS)}
    node.update(draw(st.dictionaries(PLAIN_KEYS, json_trees(SCALARS), max_size=3)))
    for _ in range(draw(st.integers(0, 4))):  # bury it under objects and arrays
        wrapped: Any = [node] if draw(st.booleans()) else node
        node = {draw(PLAIN_KEYS): wrapped}
    return node


def shape(value: Any) -> Any:
    """The record with every leaf blanked: keys and nesting only."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(v) for v in value]
    return None


@settings(max_examples=300, deadline=None)
@given(records_with_a_secret())
def test_json_value_under_a_sensitive_key_never_survives(record: dict[str, Any]) -> None:
    out = REDACTOR.redact_line(json.dumps(record), strict=True)
    assert out.structured
    assert CANARY not in out.text
    # Still JSON, with the same keys and nesting: only leaves change.
    assert shape(json.loads(out.text)) == shape(record)


@settings(max_examples=200, deadline=None)
@given(records_with_a_secret())
def test_json_redaction_is_idempotent(record: dict[str, Any]) -> None:
    once = REDACTOR.redact_line(json.dumps(record)).text
    assert REDACTOR.redact_line(once).text == once


XML_SENSITIVE = st.sampled_from(["Password", "LastName", "ssn", "CardNumber"])
XML_PLAIN = st.sampled_from(["event", "item", "meta", "level"])


@st.composite
def xml_with_a_secret(draw: st.DrawFn) -> str:
    """An XML document carrying CANARY as sensitive element text, attribute or named field."""
    form = draw(st.sampled_from(["element", "attribute", "named"]))
    name = draw(XML_SENSITIVE)
    if form == "element":
        inner = f"<{name}>{CANARY}</{name}>"
    elif form == "attribute":
        inner = f'<{draw(XML_PLAIN)} {name}="{CANARY}"/>'
    else:  # Windows Event Log style
        inner = f'<Data Name="{name}">{CANARY}</Data>'
    for _ in range(draw(st.integers(0, 4))):
        tag = draw(XML_PLAIN)
        sibling = f"<note>{draw(PLAIN_TEXT)}</note>" if draw(st.booleans()) else ""
        inner = f"<{tag}>{sibling}{inner}</{tag}>"
    return f"<root>{inner}</root>"


@settings(max_examples=200, deadline=None)
@given(xml_with_a_secret())
def test_xml_value_under_a_sensitive_name_never_survives(doc: str) -> None:
    out = REDACTOR.redact_line(doc, strict=True)
    assert out.structured
    assert CANARY not in out.text
    ET.fromstring(out.text)  # still well-formed


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.binary(max_size=200), st.text(max_size=200)))
def test_arbitrary_input_is_redacted_or_refused_never_a_crash(data: bytes | str) -> None:
    # Non-strict: everything gets at least the text scan.
    REDACTOR.redact_line(data)
    # Strict: structured, or a clean refusal the connector turns into a DLQ record.
    with contextlib.suppress(StructuredParseError):
        assert REDACTOR.redact_line(data, strict=True).structured
