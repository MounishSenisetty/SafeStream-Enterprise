"""Structure-aware (AST) redaction for JSON / NDJSON log records.

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

A line that is not valid JSON is never passed through: it falls back to the
OSS text path (``Redactor.redact``), so mixed-format streams are always covered.

Replacement text comes from the engine's own :class:`RedactionPolicy`, so
``replace`` / ``mask`` / ``pseudonymize`` / ``hash`` / ``encrypt`` behave
identically for structural and textual hits, and pseudonyms stay joinable
across both paths.

Memory: one record at a time. :meth:`StructuredRedactor.redact_lines` is a
generator, so an NDJSON stream of any size runs in O(largest record) memory.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import NamedTuple, TypeAlias

from safestream_redactor import Detection, EntityType, RedactionStats, Redactor

#: Any value ``json.loads`` can produce.
JSONValue: TypeAlias = "dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None"

#: ``Detection.source`` stamped on structural hits, so reports can tell them apart.
STRUCTURAL_SOURCE = "structural"

# Key normalisation strips everything but letters/digits, so one rule matches
# every spelling: ``LastName``, ``last_name``, ``last-name``, ``LAST NAME``.
# Rule patterns keep the glob wildcards ``*`` and ``?``.
_KEY_STRIP = re.compile(r"[^0-9a-z]+")
_RULE_STRIP = re.compile(r"[^0-9a-z*?]+")

#: Default field rules, evaluated in order, first match wins. Entity types are
#: limited to those in the published ``safestream-redactor`` 0.4.x API; usernames,
#: IBANs and street addresses move to their dedicated types once the OSS release
#: carrying ``USERNAME``/``IBAN``/``ADDRESS`` ships. Patterns are
#: globs over the *normalised* key (see above). They are deliberately specific:
#: a bare ``*name*`` would also redact ``hostname``/``filename``/``service_name``
#: and destroy the operational value of every log line.
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


class RedactedRecord(NamedTuple):
    """One redacted record.

    ``structured`` is ``False`` when the input was not valid JSON and the OSS
    free-text path redacted it instead; connectors surface this as a header so
    downstream consumers know whether the record's shape was preserved.
    """

    text: str
    structured: bool


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
        Ordered ``glob -> entity type`` map applied to normalised keys; first
        match wins. Entity types may be given by name (``"email"``).
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
        # Normalise each pattern exactly like keys, so ``*Last_Name*`` works.
        self._rules: tuple[tuple[str, EntityType], ...] = tuple(
            (
                _RULE_STRIP.sub("", pattern.lower()),
                et if isinstance(et, EntityType) else EntityType.from_name(et),
            )
            for pattern, et in field_rules.items()
        )
        # Per-instance cache (a module-level one would leak rules across
        # instances). lru_cache is thread-safe for concurrent readers.
        self.classify_key = lru_cache(maxsize=key_cache_size)(self._classify_key)

    # ------------------------------------------------------------------
    # key classification
    # ------------------------------------------------------------------

    def _classify_key(self, key: str) -> EntityType | None:
        """The entity type a key's value is redacted as, or ``None``."""
        norm = _normalise_key(key)
        for pattern, entity_type in self._rules:
            if fnmatchcase(norm, pattern):
                return entity_type
        return None

    # ------------------------------------------------------------------
    # value rewriting
    # ------------------------------------------------------------------

    def _redact_scalar(
        self,
        value: JSONValue,
        forced: EntityType | None,
        stats: RedactionStats | None,
    ) -> JSONValue:
        """Return the redacted replacement for one leaf value."""
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

        Iterative (explicit stack), so record depth never touches Python's
        recursion limit. Each work item is a container plus the entity type
        inherited from a sensitive ancestor key (``None`` if there is none).
        ``stats`` receives per-entity-type counts only.
        """
        if not isinstance(root, (dict, list)):
            return self._redact_scalar(root, None, stats)

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
                        container[key] = self._redact_scalar(child, forced, stats)
            else:
                for i, child in enumerate(container):
                    if isinstance(child, (dict, list)):
                        stack.append((child, inherited))
                    else:
                        container[i] = self._redact_scalar(child, inherited, stats)
        # ponytail: keys are classified, never rewritten. A PII-valued key
        # ({"bob@corp.example": {...}}) is left as-is; rewriting keys can merge
        # distinct keys under REPLACE mode. Add key redaction with a collision
        # policy if a customer schema keys maps by personal data.
        return root

    # ------------------------------------------------------------------
    # line / stream API
    # ------------------------------------------------------------------

    def redact_line(self, line: str | bytes, stats: RedactionStats | None = None) -> RedactedRecord:
        """Redact one log record (a JSON document or arbitrary text).

        ``bytes`` are accepted directly (``json.loads`` sniffs UTF-8/16/32), so
        Kafka payloads skip a decode/encode round trip on the hot path.
        Output is compact JSON with key order preserved and non-ASCII kept.
        """
        try:
            tree: JSONValue = json.loads(line)
        except (ValueError, RecursionError):
            # ValueError covers JSONDecodeError and UnicodeDecodeError.
            # RecursionError: hostile nesting deeper than the C parser allows.
            # Either way, fail closed through the OSS free-text engine.
            text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
            detections = self.redactor.detect(text)
            redacted = self.redactor.policy.apply(text, detections)
            if stats is not None:
                stats.add_segment(text, redacted, detections)
            return RedactedRecord(redacted, structured=False)

        self.redact_tree(tree, stats)
        out = json.dumps(tree, ensure_ascii=False, separators=(",", ":"))
        if stats is not None:
            # per-type counts were added during the walk; sizes are per record
            stats.chars_in += len(line)
            stats.chars_out += len(out)
        return RedactedRecord(out, structured=True)

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
