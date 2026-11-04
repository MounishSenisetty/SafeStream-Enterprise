"""Structure-aware (AST) redaction for XML log records.

The XML counterpart of :mod:`safestream_enterprise.parsers.json_ast`, and it
uses the same field rules. :meth:`StructuredRedactor.redact_line` sends any
record whose first non-blank character is ``<`` here, so callers never pick a
format themselves.

What counts as a "key" in XML
-----------------------------
* **Element names.** ``<Phone>555 0100</Phone>`` and ``<LastName>Smith</LastName>``
  are matched like JSON keys. A sensitive element has *all* text inside it
  redacted, nested elements and their attributes included.
* **Attribute names.** ``<user email="bob@corp.example"/>`` has that attribute
  value redacted.
* **Name/key attributes.** Many log schemas (Windows Event Log, SOAP fault
  details, config dumps) put the field name in an attribute::

      <Data Name="TargetUserName">bob</Data>      <param key="password" value="x"/>

  An element with a ``name`` or ``key`` attribute whose *value* matches a rule
  is redacted as that field (its content and other attributes), and the name
  attribute itself is kept so the record stays readable.

Everything else (text, tails, other attribute values) is scanned by the OSS
detectors, exactly as JSON string values are.

Hostile input
-------------
Records come from untrusted producers, so parsing is locked down. These
limits are enforced by the parser itself, not by inspecting the raw text, so
they hold in every encoding:

* **Any DTD is refused.** Log records never need one, and refusing it closes
  every entity attack class at once: billion laughs, quadratic blowup, and
  external entities (XXE, local file disclosure, SSRF).
* **Nesting is capped** at :data:`MAX_DEPTH`, the same bound as JSON records.

Output fidelity
---------------
The stdlib serialiser renames every namespace prefix (``<ns0:Event ...>``) and
cannot keep a default namespace on documents with unprefixed attributes,
which covers every Windows event. This module therefore re-emits each
namespace declaration exactly where the original document made it, so
namespaced records keep their prefixes. Comments, processing instructions and
the XML declaration are dropped (comments can carry PII too). CDATA becomes
escaped text. Output is UTF-8.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape, quoteattr

from safestream_redactor import EntityType, RedactionStats

if TYPE_CHECKING:  # runtime import would be circular (json_ast dispatches here)
    from safestream_enterprise.parsers.json_ast import StructuredRedactor

#: Deepest element nesting accepted; matches orjson's round-trip bound for JSON.
MAX_DEPTH = 254

#: Attribute names that carry the *field name* of their element (case-insensitive).
NAME_ATTRIBUTES = frozenset({"name", "key"})

_XML_NS = "http://www.w3.org/XML/1998/namespace"


class XMLRejected(ValueError):
    """The record cannot be processed as XML. The message never quotes content."""


class _SafeTreeBuilder(ET.TreeBuilder):
    """Tree builder that refuses DTDs, bounds depth, and records ``xmlns`` declarations."""

    def __init__(self) -> None:
        super().__init__()
        #: Element -> the (prefix, uri) declarations it carried, in source order.
        self.ns_decls: dict[ET.Element, list[tuple[str, str]]] = {}
        self._pending: list[tuple[str, str]] = []
        self._depth = 0

    def doctype(self, name: str, pubid: str, system: str) -> None:
        # Called by the parser on <!DOCTYPE ...>, before any entity is declared,
        # so no entity expansion or external fetch can ever happen.
        raise XMLRejected("XML with a document type declaration (not allowed)")

    def start_ns(self, prefix: str, uri: str) -> None:
        self._pending.append((prefix, uri))

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self._depth += 1
        if self._depth > MAX_DEPTH:
            raise XMLRejected(f"XML nested deeper than {MAX_DEPTH} levels")
        element = super().start(tag, attrs)
        if self._pending:
            self.ns_decls[element] = self._pending
            self._pending = []
        return element

    def end(self, tag: str) -> ET.Element:
        self._depth -= 1
        return super().end(tag)


def looks_like_xml(data: str | bytes) -> bool:
    """True when the first non-blank character is ``<`` (JSON can never start so).

    A UTF-8 BOM is skipped. ponytail: UTF-16 with a BOM is not detected here;
    such records go down the JSON path, fail to parse, and fail closed (text
    redaction or DLQ). Detect the UTF-16 BOMs too if a producer sends them.
    """
    if isinstance(data, bytes):
        return data.removeprefix(b"\xef\xbb\xbf").lstrip(b" \t\r\n").startswith(b"<")
    return data.lstrip(" \t\r\n﻿").startswith("<")


def _parse(data: str | bytes) -> tuple[ET.Element, dict[ET.Element, list[tuple[str, str]]]]:
    builder = _SafeTreeBuilder()
    parser = ET.XMLParser(target=builder)
    try:
        # The XML declaration must be the very first thing; tolerate framing whitespace.
        parser.feed(data.strip())
        root = parser.close()
    except ET.ParseError as exc:
        # expat's message is a position ("line 1, column 7"), never content.
        raise XMLRejected(f"not well-formed XML ({exc})") from None
    return root, builder.ns_decls


def _local(name: str) -> str:
    """``{uri}Phone`` -> ``Phone``: rules match local names, whatever the namespace."""
    return name.rsplit("}", 1)[-1]


def _named_field(
    redactor: StructuredRedactor, el: ET.Element
) -> tuple[str | None, EntityType | None]:
    """``(attribute key, entity type)`` when a name/key attribute names a sensitive field."""
    for key, value in el.attrib.items():
        if _local(key).lower() in NAME_ATTRIBUTES:
            entity_type = redactor.classify_key(value)
            if entity_type is not None:
                return key, entity_type
    return None, None


def _redact_text(
    redactor: StructuredRedactor,
    text: str,
    forced: EntityType | None,
    stats: RedactionStats | None,
) -> str:
    return str(redactor.redact_scalar(text, forced, stats))


def redact_tree(
    redactor: StructuredRedactor, root: ET.Element, stats: RedactionStats | None
) -> None:
    """Redact a parsed XML tree in place.

    Same traversal as the JSON walk: depth-first with an explicit stack, each
    item carrying the entity type inherited from a sensitive ancestor.
    Whitespace-only text (pretty-printing between elements) is left alone so
    the layout survives.
    """
    stack: list[tuple[ET.Element, EntityType | None]] = [(root, None)]
    while stack:
        el, inherited = stack.pop()
        name_key, by_name = (None, None) if inherited else _named_field(redactor, el)
        forced = inherited or redactor.classify_key(_local(el.tag)) or by_name

        for key, value in el.attrib.items():
            if key == name_key:
                continue  # keep the field label ("TargetUserName") readable
            attr_forced = forced or redactor.classify_key(_local(key))
            # Replacing values of existing keys while iterating is safe.
            el.attrib[key] = _redact_text(redactor, value, attr_forced, stats)

        if el.text and el.text.strip():
            el.text = _redact_text(redactor, el.text, forced, stats)
        for child in el:
            stack.append((child, forced))
            # A child's tail is text of *this* element, so it takes this
            # element's sensitivity, not the child's.
            if child.tail and child.tail.strip():
                child.tail = _redact_text(redactor, child.tail, forced, stats)


def _qname(name: str, prefixes: dict[str, str]) -> str:
    """``{uri}local`` -> ``prefix:local`` using the prefixes in scope."""
    if not name.startswith("{"):
        return name
    uri, local = name[1:].split("}", 1)
    prefix = prefixes.get(uri)
    if prefix is None:  # impossible for a parsed document; never emit wrong XML
        raise XMLRejected("XML namespace with no prefix in scope")
    return f"{prefix}:{local}" if prefix else local


def _escape_text(text: str) -> str:
    # \r survives only as a character reference (parsers normalise a raw one away).
    return escape(text, {"\r": "&#13;"})


def _write(
    el: ET.Element,
    bindings: dict[str, str],
    ns_decls: dict[ET.Element, list[tuple[str, str]]],
    out: list[str],
) -> None:
    """Serialise ``el`` with its original namespace declarations and prefixes.

    Recursive: depth is bounded by :data:`MAX_DEPTH` at parse time.
    ``bindings`` maps prefix -> uri for the scope of ``el``'s parent.
    """
    decls = ns_decls.get(el, [])
    if decls:
        bindings = {**bindings, **dict(decls)}
    # Elements may use the default namespace (prefix ""); attributes may not.
    element_prefixes = {uri: prefix for prefix, uri in bindings.items()}
    attr_prefixes = {uri: prefix for prefix, uri in bindings.items() if prefix}

    tag = _qname(el.tag, element_prefixes)
    out.append(f"<{tag}")
    for prefix, uri in decls:
        out.append(f" xmlns:{prefix}={quoteattr(uri)}" if prefix else f" xmlns={quoteattr(uri)}")
    for key, value in el.attrib.items():
        out.append(f" {_qname(key, attr_prefixes)}={quoteattr(value)}")
    if not el.text and len(el) == 0:
        out.append("/>")
        return
    out.append(">")
    if el.text:
        out.append(_escape_text(el.text))
    for child in el:
        _write(child, bindings, ns_decls, out)
        if child.tail:
            out.append(_escape_text(child.tail))
    out.append(f"</{tag}>")


def redact_xml(
    redactor: StructuredRedactor, data: str | bytes, stats: RedactionStats | None = None
) -> bytes:
    """Parse, redact and re-serialise one XML record. Returns UTF-8 bytes.

    Raises :class:`XMLRejected` when the record cannot be handled as XML;
    :meth:`StructuredRedactor.redact_line` turns that into its fail-closed
    text fallback (or ``StructuredParseError`` in strict mode).
    """
    root, ns_decls = _parse(data)
    redact_tree(redactor, root, stats)
    out: list[str] = []
    _write(root, {"xml": _XML_NS}, ns_decls, out)
    return "".join(out).encode("utf-8")
