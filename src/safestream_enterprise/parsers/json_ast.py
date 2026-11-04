"""Structure-aware (AST) redaction for JSON / NDJSON and XML log records.

:class:`StructuredRedactor` is the single entry point for structured records:
:meth:`~StructuredRedactor.redact_line` sends a record whose first non-blank
character is ``<`` to the XML module (:mod:`.xml_ast`), and everything else
to the JSON path below. Both use the same field rules.

Why this exists
---------------
The open-source engine scans *text*: regexes, validators and entropy over an
overlapping window. That is ideal for free-form logs, but structured records
carry their most sensitive values in a form no text detector can recognise::

    {"LastName": "Smith", "password": "hunter2", "Phone": "555 0100"}

``Smith`` is not a pattern; ``hunter2`` has too little entropy; the phone number
is in a local format. The *key* is the signal. This module parses each record
into its tree, decides per key whether the value is sensitive, and rewrites
values in place before serialising the record back to JSON.

Two passes over every value, both fail-closed
----------------------------------------------
1. **Field rules** (structural). A key whose normalised name matches a rule
   (``*password*``, ``*lastname*``, ...) has its *whole* value redacted, whatever
   it contains. Containers under a sensitive key are redacted leaf by leaf, so
   ``{"credentials": {"user": "a", "pin": 1234}}`` leaks nothing.
2. **Free-text scan** (the OSS ``Redactor``). Every other string value is still
   scanned by the core engine, so ``{"msg": "login by bob@corp.example"}`` is
   caught exactly as the OSS CLI would catch it.

A line that is neither valid JSON nor valid XML is never passed through: by default it falls back
to the OSS free-text path, so mixed-format streams are always covered; with
``strict=True`` it raises :class:`StructuredParseError` so the caller can route
it elsewhere (the Kafka connector sends it to its DLQ).

Replacement text comes from the engine's own :class:`RedactionPolicy`, so
``replace`` / ``mask`` / ``pseudonymize`` behave identically for structural and
textual hits, and pseudonyms stay joinable across both paths.

Parsing and serialisation use ``orjson`` (Rust): several times faster than the
stdlib ``json`` module, it emits compact UTF-8 ``bytes`` directly (what Kafka
wants) and bounds nesting depth (254 levels round-trip), which caps the cost of
hostile input. Deeper records are treated as malformed.

Memory: one record at a time. :meth:`StructuredRedactor.redact_lines` is a
generator, so an NDJSON stream of any size runs in O(largest record) memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from fnmatch import translate
from functools import lru_cache
from typing import NamedTuple, TypeAlias

import orjson
from safestream_redactor import Detection, EntityType, RedactionStats, Redactor

from safestream_enterprise.parsers.xml_ast import XMLRejected, looks_like_xml, redact_xml

#: Any value ``orjson.loads`` can produce.
JSONValue: TypeAlias = "dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None"

#: ``Detection.source`` stamped on structural hits, so reports can tell them apart.
STRUCTURAL_SOURCE = "structural"

#: Prefix marking a field rule as a regular expression instead of a glob.
REGEX_PREFIX = "re:"

# Key normalisation strips everything but letters/digits, so one rule matches
# every spelling: ``LastName``, ``last_name``, ``last-name``, ``LAST NAME``.
# Rule patterns keep the glob wildcards ``*`` and ``?``.
_KEY_STRIP = re.compile(r"[^0-9a-z]+")
_RULE_STRIP = re.compile(r"[^0-9a-z*?]+")

#: Default field rules, evaluated in order, first match wins. Patterns are globs
#: over the *normalised* key (see above). They are deliberately specific: a bare
#: ``*name*`` would also redact ``hostname``/``filename``/``service_name`` and
#: destroy the operational value of every log line.
#:
#: Entity types are limited to the published ``safestream-redactor`` 0.4.x API:
#: usernames, IBANs and street addresses move to dedicated types once the OSS
#: release carrying ``USERNAME``/``IBAN``/``ADDRESS`` ships.
DEFAULT_FIELD_RULES: Mapping[str, EntityType] = {
    # --- credentials (PCI-DSS 8, SOC 2 CC6) ---------------------------------
    "*password*": EntityType.SECRET,
    "*passwd*": EntityType.SECRET,
    "*passphrase*": EntityType.SECRET,
    "pwd": EntityType.SECRET,
    "*secret*": EntityType.SECRET,
    "*token*": EntityType.SECRET,
    "*apikey*": EntityType.API_KEY,
    "*accesskey*": EntityType.SECRET,
    "*privatekey*": EntityType.PRIVATE_KEY,
    "*credential*": EntityType.SECRET,
    "*authorization*": EntityType.SECRET,
    "*cookie*": EntityType.SECRET,
    "*sessionid*": EntityType.SECRET,
    # --- payment data (PCI-DSS 3) -------------------------------------------
    "*creditcard*": EntityType.CREDIT_CARD,
    "*cardnumber*": EntityType.CREDIT_CARD,
    "*ccnumber*": EntityType.CREDIT_CARD,
    "pan": EntityType.CREDIT_CARD,
    "*cvv*": EntityType.CREDIT_CARD,
    "*cvc*": EntityType.CREDIT_CARD,
    "*iban*": EntityType.ID_NUMBER,
    "*accountnumber*": EntityType.ID_NUMBER,
    "*routingnumber*": EntityType.ID_NUMBER,
    # --- contact data (GDPR Art. 4, HIPAA identifiers) ----------------------
    "*email*": EntityType.EMAIL,
    "*phone*": EntityType.PHONE,
    "*mobile*": EntityType.PHONE,
    "*msisdn*": EntityType.PHONE,
    "*fax*": EntityType.PHONE,
    # --- identity ------------------------------------------------------------
    "*username*": EntityType.ID_NUMBER,
    "*login*": EntityType.ID_NUMBER,
    "*firstname*": EntityType.PERSON,
    "*lastname*": EntityType.PERSON,
    "*fullname*": EntityType.PERSON,
    "*middlename*": EntityType.PERSON,
    "*surname*": EntityType.PERSON,
    "*givenname*": EntityType.PERSON,
    "*maidenname*": EntityType.PERSON,
    "*displayname*": EntityType.PERSON,
    # ``ssn`` anchored at an edge: ``*ssn*`` would hit ``classname``.
    "ssn": EntityType.SSN,
    "ssn*": EntityType.SSN,
    "*ssn": EntityType.SSN,
    "*socialsecurity*": EntityType.SSN,
    "*taxid*": EntityType.ID_NUMBER,
    "*nationalid*": EntityType.ID_NUMBER,
    "*passport*": EntityType.ID_NUMBER,
    "*driverslicense*": EntityType.ID_NUMBER,
    # ``dob`` exact: ``*dob*`` would hit ``adobe``.
    "dob": EntityType.DOB,
    "*dateofbirth*": EntityType.DOB,
    "*birthdate*": EntityType.DOB,
    "*birthday*": EntityType.DOB,
    # --- location ------------------------------------------------------------
    # No bare ``*address*``: that would swallow ``mac_address``/``server_address``.
    "address": EntityType.LOC,
    "*streetaddress*": EntityType.LOC,
    "*homeaddress*": EntityType.LOC,
    "*mailingaddress*": EntityType.LOC,
    "*billingaddress*": EntityType.LOC,
    "*shippingaddress*": EntityType.LOC,
    "*street*": EntityType.LOC,
    "*postalcode*": EntityType.LOC,
    "*zipcode*": EntityType.LOC,
    "*ipaddress*": EntityType.IPV4,
    "*clientip*": EntityType.IPV4,
    "*remoteaddr*": EntityType.IPV4,
    # --- health (HIPAA Safe Harbor identifiers) ------------------------------
    "mrn": EntityType.ID_NUMBER,
    "*medicalrecord*": EntityType.ID_NUMBER,
    "*healthplan*": EntityType.ID_NUMBER,
    "*insuranceid*": EntityType.ID_NUMBER,
    "*diagnosis*": EntityType.CUSTOM,
}


class StructuredParseError(ValueError):
    """A record is neither valid JSON nor valid XML, and the caller asked for strict parsing."""


class _NotJSON(ValueError):
    """Internal: the JSON path cannot process this record (the message says why)."""


class RedactedRecord(NamedTuple):
    """One redacted record.

    ``data`` is the redacted record as UTF-8 bytes (compact JSON, or XML, when
    ``structured``). ``structured`` is ``False`` when the input was neither
    valid JSON nor valid XML and the OSS free-text path redacted it instead; connectors surface this
    as a header so consumers know whether the record's shape was preserved.
    """

    data: bytes
    structured: bool

    @property
    def text(self) -> str:
        """``data`` decoded, for callers working in ``str``."""
        return self.data.decode("utf-8")


def _normalise_key(key: str) -> str:
    return _KEY_STRIP.sub("", key.lower())


class StructuredRedactor:
    """Redact JSON records by field name *and* by content.

    Parameters
    ----------
    redactor:
        The OSS engine. Its detectors scan free-text values and its ``policy``
        renders every replacement. Defaults to ``Redactor()``.
    field_rules:
        Ordered ``pattern -> entity type`` map; first match wins. A plain
        pattern is a glob matched against the *normalised* key (lower-case,
        letters and digits only), so ``*last_name*`` matches ``LastName``. A
        pattern starting with ``re:`` is a regular expression searched in the
        *raw* key, case-insensitively (``re:^x-.*-token$``). Entity types may
        be given by name (``"email"``).
    scan_free_text:
        Also run the OSS detectors over values whose key matched no rule.
        Disable only for records whose schema is fully covered by rules.
    key_cache_size:
        Distinct keys whose classification is memoised. Log schemas reuse a
        small key set, so after warm-up each key costs one dict lookup.
    """

    def __init__(
        self,
        redactor: Redactor | None = None,
        field_rules: Mapping[str, EntityType | str] = DEFAULT_FIELD_RULES,
        *,
        scan_free_text: bool = True,
        key_cache_size: int = 4096,
    ) -> None:
        self.redactor = redactor if redactor is not None else Redactor()
        self.scan_free_text = scan_free_text
        # Compile every rule once. Each entry: (regex, matches_raw_key, type).
        # Globs are normalised exactly like keys, so ``*Last_Name*`` works.
        rules: list[tuple[re.Pattern[str], bool, EntityType]] = []
        for pattern, et in field_rules.items():
            entity_type = et if isinstance(et, EntityType) else EntityType.from_name(et)
            if pattern.startswith(REGEX_PREFIX):
                try:
                    regex = re.compile(pattern[len(REGEX_PREFIX) :], re.IGNORECASE)
                except re.error as exc:
                    # Fail at startup, not on the first matching record mid-stream.
                    raise ValueError(f"invalid field rule {pattern!r}: {exc}") from None
                rules.append((regex, True, entity_type))
            else:
                glob = _RULE_STRIP.sub("", pattern.lower())
                rules.append((re.compile(translate(glob)), False, entity_type))
        self._rules: tuple[tuple[re.Pattern[str], bool, EntityType], ...] = tuple(rules)
        # Per-instance cache (a module-level one would leak rules across
        # instances). lru_cache is thread-safe for concurrent readers.
        self.classify_key = lru_cache(maxsize=key_cache_size)(self._classify_key)

    # ------------------------------------------------------------------
    # key classification
    # ------------------------------------------------------------------

    def _classify_key(self, key: str) -> EntityType | None:
        """The entity type a key's value is redacted as, or ``None``."""
        norm = _normalise_key(key)
        for regex, raw, entity_type in self._rules:
            if regex.search(key) if raw else regex.match(norm):
                return entity_type
        return None

    # ------------------------------------------------------------------
    # value rewriting
    # ------------------------------------------------------------------

    def redact_scalar(
        self,
        value: JSONValue,
        forced: EntityType | None,
        stats: RedactionStats | None,
    ) -> JSONValue:
        """Return the redacted replacement for one leaf value.

        ``forced`` is the entity type from a matching field rule (the whole
        value is redacted) or ``None`` (the value is scanned by the OSS
        detectors). Shared by the JSON and XML walks.
        """
        # bool before int: bool is an int subclass, and true/false/null carry
        # no payload worth hiding — keeping them preserves the record's shape.
        if value is None or isinstance(value, bool):
            return value

        if forced is not None:
            # Structural hit: the whole value is sensitive. Numbers are
            # stringified (a numeric phone/SSN is still a phone/SSN).
            text = value if isinstance(value, str) else str(value)
            if not text:
                return value
            det = Detection(0, len(text), text, forced, 1.0, STRUCTURAL_SOURCE)
            if stats is not None:
                stats.counts[forced.value] += 1
            return self.redactor.policy.render(det)

        if not self.scan_free_text or isinstance(value, float):
            return value
        # Strings, and integers (a card number logged as a JSON number).
        text = value if isinstance(value, str) else str(value)
        detections = self.redactor.detect(text)
        if not detections:
            return value
        if stats is not None:
            stats.counts.update(d.entity_type.value for d in detections)
        return self.redactor.policy.apply(text, detections)

    def redact_tree(self, root: JSONValue, stats: RedactionStats | None = None) -> JSONValue:
        """Redact a parsed JSON tree **in place** and return it.

        The traversal is depth-first like a recursive walk, but uses an explicit
        stack: orjson parses up to 1024 levels of nesting, more than Python's
        default recursion limit, so a recursive walk could crash on input the
        parser accepted. Each work item is a container plus the entity type
        inherited from a sensitive ancestor key (``None`` if there is none).
        ``stats`` receives per-entity-type counts only.
        """
        if not isinstance(root, (dict, list)):
            return self.redact_scalar(root, None, stats)

        stack: list[tuple[dict[str, JSONValue] | list[JSONValue], EntityType | None]] = [
            (root, None)
        ]
        while stack:
            container, inherited = stack.pop()
            if isinstance(container, dict):
                # Assigning to existing keys while iterating is safe: the dict's
                # size never changes, only values are replaced.
                for key, child in container.items():
                    forced = inherited or self.classify_key(key)
                    if isinstance(child, (dict, list)):
                        stack.append((child, forced))
                    else:
                        container[key] = self.redact_scalar(child, forced, stats)
            else:
                for i, child in enumerate(container):
                    if isinstance(child, (dict, list)):
                        stack.append((child, inherited))
                    else:
                        container[i] = self.redact_scalar(child, inherited, stats)
        # ponytail: keys are classified, never rewritten. A PII-valued key
        # ({"bob@corp.example": {...}}) is left as-is; rewriting keys can merge
        # distinct keys under REPLACE mode. Add key redaction with a collision
        # policy if a customer schema keys maps by personal data.
        return root

    # ------------------------------------------------------------------
    # line / stream API
    # ------------------------------------------------------------------

    def redact_line(
        self,
        line: str | bytes,
        stats: RedactionStats | None = None,
        *,
        strict: bool = False,
    ) -> RedactedRecord:
        """Redact one log record: a JSON document, an XML document, or free text.

        A record whose first non-blank character is ``<`` is handled as XML
        (see :mod:`.xml_ast`); anything else as JSON. ``bytes`` are parsed
        directly, so Kafka payloads skip a decode/encode round trip on the hot
        path. JSON output is compact UTF-8 with key order preserved.

        A record that cannot be processed structurally (bad syntax, invalid
        UTF-8, a DTD in XML, nesting deeper than 254 levels) is redacted as
        free text by the OSS engine, so it still never passes through
        unredacted. With ``strict=True`` it raises
        :class:`StructuredParseError` instead, for pipelines that route
        malformed records elsewhere (the Kafka DLQ).
        """
        # Count into a scratch object and merge only on success, so a record
        # that falls back to the text path is never counted twice.
        local = RedactionStats() if stats is not None else None
        try:
            if looks_like_xml(line):
                out = redact_xml(self, line, local)
            else:
                out = self._redact_json(line, local)
        except (_NotJSON, XMLRejected) as exc:
            return self._unstructured(line, stats, strict, str(exc))
        if stats is not None and local is not None:
            stats.merge(local)  # per-type counts from the walk
            stats.chars_in += len(line)  # sizes are per record
            stats.chars_out += len(out)
        return RedactedRecord(out, structured=True)

    def _redact_json(self, line: str | bytes, stats: RedactionStats | None) -> bytes:
        """Parse, redact and re-serialise one JSON record (raises :class:`_NotJSON`)."""
        try:
            tree: JSONValue = orjson.loads(line)
        except orjson.JSONDecodeError as exc:
            # Position only: the message must never quote the record.
            raise _NotJSON(f"not valid JSON (byte {exc.pos})") from None
        self.redact_tree(tree, stats)
        try:
            # ponytail: orjson reads integers wider than 64 bits as floats, so a
            # 30-digit numeric ID loses precision on the way through. Producers
            # should send such IDs as strings (they are then scanned as text).
            return orjson.dumps(tree)
        except orjson.JSONEncodeError:
            # orjson serialises at most 254 levels of nesting (it parses 1024).
            raise _NotJSON("JSON nested deeper than 254 levels") from None

    def _unstructured(
        self, line: str | bytes, stats: RedactionStats | None, strict: bool, reason: str
    ) -> RedactedRecord:
        """Fail closed for a record that can't be handled as JSON."""
        if strict:
            raise StructuredParseError(f"record is {reason}")
        text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
        detections = self.redactor.detect(text)
        redacted = self.redactor.policy.apply(text, detections)
        if stats is not None:
            stats.add_segment(text, redacted, detections)
        return RedactedRecord(redacted.encode("utf-8"), structured=False)

    def redact_lines(
        self, lines: Iterable[str | bytes], stats: RedactionStats | None = None
    ) -> Iterator[str]:
        """Redact an NDJSON stream lazily, one record in memory at a time.

        Line terminators are stripped on input and not re-added; join the
        output with ``"\\n"``. Blank lines are passed through unchanged.
        """
        for line in lines:
            stripped = line.strip()
            if not stripped:
                yield ""
                continue
            yield self.redact_line(stripped, stats).text
