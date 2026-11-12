"""Leak canaries: continuous proof that the policy in force still redacts.

A signed policy proves *which* rules are in force, not that they work. Every
``SAFESTREAM_CANARY_INTERVAL_S`` the connector builds synthetic records, in
JSON and in XML, carrying freshly generated fake PII (an email address, a
Luhn-valid card number, a social security number) both under field names the
built-in rules cover and inside free text, and redacts them with the live
redactor on the same code path as a real record. If any seeded value, or the
random part of it, survives into the output, that is a **leak**:
``safestream_canary_leaks_total`` goes up, the audit event of the window says
so, and a staged policy rollout halts.

The values are random on every run, so no rule can special-case them, and
they are fake by construction (``example.com`` addresses, a card number from
a test range, an SSN area no one is issued): nothing real is ever handled.
Canary records are never published; only the counts leave the process.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from xml.sax.saxutils import escape

import orjson
from safestream_redactor import RedactionStats

from safestream_enterprise.parsers.json_ast import StructuredRedactor


def _luhn_card() -> str:
    """A random 16-digit, Luhn-valid number in the Visa test range (4…)."""
    digits = [4] + [secrets.randbelow(10) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        doubled = d * 2 if i % 2 == 0 else d
        total += doubled - 9 if doubled > 9 else doubled
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)


def _ssn() -> str:
    # Area 100-599, group and serial never zero: valid format, synthetic values.
    area = 100 + secrets.randbelow(500)
    return f"{area:03d}-{1 + secrets.randbelow(99):02d}-{1 + secrets.randbelow(9999):04d}"


@dataclass(frozen=True)
class Seed:
    """One canary's fake values, and the substrings that must not survive."""

    tag: str
    email: str
    card: str
    ssn: str

    @classmethod
    def new(cls) -> Seed:
        tag = secrets.token_hex(5)
        return cls(tag, f"canary.{tag}@example.com", _luhn_card(), _ssn())

    def forbidden(self) -> tuple[bytes, ...]:
        # The random tag catches a partially redacted address ("canary.<tag>@…").
        return tuple(v.encode() for v in (f"canary.{self.tag}", self.card, self.ssn))

    def records(self) -> dict[str, bytes]:
        note = f"contact {self.email}, card {self.card}, ssn {self.ssn}"
        json_record = orjson.dumps(
            {
                "event": "safestream-canary",
                "email": self.email,
                "card_number": self.card,
                "ssn": self.ssn,
                "note": note,
            }
        )
        xml_record = (
            "<event><kind>safestream-canary</kind>"
            f"<email>{escape(self.email)}</email>"
            f"<card_number>{self.card}</card_number>"
            f"<ssn>{self.ssn}</ssn>"
            f"<note>{escape(note)}</note></event>"
        ).encode()
        return {"json": json_record, "xml": xml_record}


@dataclass
class Result:
    checks: int = 0
    #: Formats in which a seeded value survived (``"json"``, ``"xml"``).
    leaked: tuple[str, ...] = ()


class Canary:
    """Runs canaries against a redactor. :meth:`check` never raises."""

    def __init__(self, strict: bool = True) -> None:
        self.strict = strict

    def check(self, redactor: StructuredRedactor) -> Result:
        seed = Seed.new()
        leaked: list[str] = []
        records = seed.records()
        for fmt, record in records.items():
            try:
                out = redactor.redact_line(record, RedactionStats(), strict=self.strict).data
            except Exception:
                # A redactor that cannot process the canary would dead-letter
                # a real record (fail closed): not a leak.
                continue
            out_bytes = out if isinstance(out, bytes) else out.encode()
            if any(value in out_bytes for value in seed.forbidden()):
                leaked.append(fmt)
        return Result(checks=len(records), leaked=tuple(leaked))
