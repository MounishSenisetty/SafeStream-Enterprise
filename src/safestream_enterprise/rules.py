"""Customer field rules, loaded from a JSON file (e.g. a mounted Kubernetes ConfigMap).

The built-in rules (:data:`~safestream_enterprise.parsers.json_ast.DEFAULT_FIELD_RULES`)
cover common PCI/HIPAA/GDPR field names. Real schemas add their own
(``loyalty_number``, ``member_ssn_last4``, a vendor's ``x-acme-signature``
header). This module lets operators add them without a code change or rebuild::

    {
      "mode": "extend",
      "rules": {
        "*loyalty_number*": "id_number",
        "re:^x-acme-.*-signature$": "secret"
      },
      "disable": ["*login*"]
    }

* ``mode: "extend"`` (default): ``rules`` are evaluated *before* the built-in
  rules, so a custom rule wins where both match. ``disable`` removes built-in
  rules by their exact pattern string (for a field that is not sensitive in
  this schema).
* ``mode: "replace"``: only ``rules`` apply; the built-in rules are not used.

Patterns use the same syntax as :class:`StructuredRedactor`: a glob over the
normalised key, or ``re:`` plus a case-insensitive regex over the raw key.

Everything is validated when the file is loaded, so a typo fails the pod at
startup instead of silently leaving a field unredacted: unknown keys, unknown
entity types, a ``disable`` entry that matches no built-in rule, and (when the
redactor is built) an invalid regex.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from safestream_redactor import EntityType, RedactionMode, RedactionPolicy, Redactor

from safestream_enterprise.parsers.json_ast import DEFAULT_FIELD_RULES, StructuredRedactor


class FieldRulesError(ValueError):
    """The field-rules file is missing, unreadable, or invalid. The message says why."""


class FieldRulesFile(BaseModel):
    """Schema of the field-rules file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["extend", "replace"] = "extend"
    #: Ordered pattern -> entity type name; first match wins.
    rules: dict[str, str] = Field(default_factory=dict)
    #: Built-in patterns to drop (extend mode only).
    disable: list[str] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _known_entity_types(cls, rules: dict[str, str]) -> dict[str, str]:
        for pattern, name in rules.items():
            if not pattern.strip():
                raise ValueError("a rule pattern must not be empty")
            EntityType.from_name(name)  # raises ValueError listing the valid types
        return rules

    @model_validator(mode="after")
    def _consistent(self) -> FieldRulesFile:
        if self.mode == "replace":
            if not self.rules:
                raise ValueError("mode 'replace' needs at least one rule")
            if self.disable:
                raise ValueError("'disable' only applies to mode 'extend'")
        unknown = [p for p in self.disable if p not in DEFAULT_FIELD_RULES]
        if unknown:
            raise ValueError(f"'disable' names no built-in rule: {unknown}")
        return self

    def effective_rules(self) -> dict[str, EntityType]:
        """The ordered rule table to give :class:`StructuredRedactor`."""
        custom = {p: EntityType.from_name(n) for p, n in self.rules.items()}
        if self.mode == "replace":
            return custom
        dropped = set(self.disable)
        builtin = {p: t for p, t in DEFAULT_FIELD_RULES.items() if p not in dropped}
        # Custom first, so it wins; a pattern in both keeps the custom type.
        return {**custom, **{p: t for p, t in builtin.items() if p not in custom}}


def parse_field_rules(data: Mapping[str, object]) -> dict[str, EntityType]:
    """Validate an already-parsed rules document and return the effective rules."""
    try:
        return FieldRulesFile.model_validate(data).effective_rules()
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'file'}: {err['msg']}"
            for err in exc.errors(include_url=False)
        )
        raise FieldRulesError(f"invalid field rules: {problems}") from None


def load_field_rules(path: str | Path) -> dict[str, EntityType]:
    """Load, validate and merge a field-rules JSON file.

    Raises :class:`FieldRulesError` with a message naming the problem.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise FieldRulesError(f"cannot read field rules file {path}: {exc.strerror}") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise FieldRulesError(f"field rules file {path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise FieldRulesError(f"field rules file {path} must contain a JSON object")
    return parse_field_rules(data)


def make_redactor(
    mode: RedactionMode,
    hmac_key: bytes | None = None,
    field_rules_file: str | Path | None = None,
) -> StructuredRedactor:
    """The redactor every SafeStream Enterprise entry point uses.

    The Kafka connector and the batch job both build through here, so the same
    ``hmac_key`` and rules give byte-identical output: a record backfilled
    from the lake and the same record streamed through Kafka get the same
    pseudonyms, and stay joinable. Raises ``ValueError`` on a bad rules file
    or an invalid mode/key combination.
    """
    rules = load_field_rules(field_rules_file) if field_rules_file else DEFAULT_FIELD_RULES
    return StructuredRedactor(
        Redactor(
            policy=RedactionPolicy(mode=mode, hmac_key=hmac_key),
            # Compiled Rust core when installed, pure Python otherwise;
            # output is byte-identical either way.
            backend="auto",
            # Third-party detector plugins run with full process privileges
            # inside a process that sees every record: opt-in only.
            load_plugins=False,
        ),
        rules,
    )
