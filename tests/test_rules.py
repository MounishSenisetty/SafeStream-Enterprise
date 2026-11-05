import json
import os
from pathlib import Path

import pytest
from safestream_redactor import EntityType

from safestream_enterprise import DEFAULT_FIELD_RULES, StructuredRedactor
from safestream_enterprise.connectors.kafka import ConnectorConfig, build_redactor, main
from safestream_enterprise.rules import FieldRulesError, load_field_rules, parse_field_rules


def write(tmp_path: Path, doc: object) -> Path:
    path = tmp_path / "field-rules.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def redact(rules: dict[str, EntityType], record: dict[str, object]) -> dict[str, object]:
    out: dict[str, object] = json.loads(
        StructuredRedactor(field_rules=rules).redact_line(json.dumps(record)).text
    )
    return out


def test_extend_adds_custom_rules_first_and_keeps_builtins(tmp_path: Path) -> None:
    rules = load_field_rules(
        write(tmp_path, {"rules": {"*loyalty_number*": "id_number", "*email*": "custom"}})
    )
    assert list(rules)[:2] == ["*loyalty_number*", "*email*"]  # custom first: they win
    assert rules["*email*"] is EntityType.CUSTOM  # custom type overrides the built-in one
    assert rules["*password*"] is EntityType.SECRET  # built-ins still apply
    assert len(rules) == len(DEFAULT_FIELD_RULES) + 1
    assert redact(rules, {"LoyaltyNumber": "L-1", "password": "p", "plan": "gold"}) == {
        "LoyaltyNumber": "[REDACTED]",
        "password": "[REDACTED]",
        "plan": "gold",
    }


def test_disable_drops_a_builtin_rule() -> None:
    rules = parse_field_rules({"disable": ["*login*"]})
    assert "*login*" not in rules
    assert redact(rules, {"login_count": 3})["login_count"] == 3  # no longer redacted
    assert redact(DEFAULT_FIELD_RULES, {"login_count": 3})["login_count"] == "[REDACTED]"


def test_replace_uses_only_custom_rules() -> None:
    rules = parse_field_rules({"mode": "replace", "rules": {"re:^x-acme-.*-sig$": "secret"}})
    assert list(rules) == ["re:^x-acme-.*-sig$"]
    assert redact(rules, {"X-Acme-Api-Sig": "s", "password": "plain"}) == {
        "X-Acme-Api-Sig": "[REDACTED]",
        "password": "plain",  # built-ins are off in replace mode
    }


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ({"rules": {"*x*": "not_a_type"}}, "unknown entity type"),
        ({"rules": {"  ": "secret"}}, "must not be empty"),
        ({"rulez": {}}, "Extra inputs are not permitted"),
        ({"mode": "merge"}, "mode"),
        ({"mode": "replace"}, "at least one rule"),
        ({"mode": "replace", "rules": {"*a*": "secret"}, "disable": ["*login*"]}, "only applies"),
        ({"disable": ["*not-a-builtin*"]}, "names no built-in rule"),
    ],
)
def test_invalid_documents_fail_with_a_clear_message(doc: dict[str, object], message: str) -> None:
    with pytest.raises(FieldRulesError, match=message):
        parse_field_rules(doc)


def test_file_errors(tmp_path: Path) -> None:
    with pytest.raises(FieldRulesError, match="cannot read"):
        load_field_rules(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(FieldRulesError, match="not valid JSON"):
        load_field_rules(bad)
    with pytest.raises(FieldRulesError, match="JSON object"):
        load_field_rules(write(tmp_path, ["*a*"]))


def test_connector_uses_the_rules_file(tmp_path: Path) -> None:
    path = write(tmp_path, {"rules": {"*loyalty_number*": "id_number"}})
    config = ConnectorConfig.from_env(
        {"KAFKA_BOOTSTRAP_SERVERS": "b:9092", "SAFESTREAM_FIELD_RULES_FILE": str(path)}
    )
    out = build_redactor(config).redact_line('{"loyaltyNumber": "L-1"}').text
    assert json.loads(out) == {"loyaltyNumber": "[REDACTED]"}
    # without the file, the field is not a built-in rule
    plain = build_redactor(ConnectorConfig(bootstrap_servers="b:9092"))
    assert json.loads(plain.redact_line('{"loyaltyNumber": "L-1"}').text) == {
        "loyaltyNumber": "L-1"
    }


@pytest.mark.parametrize("doc", [{"rules": {"*x*": "nope"}}, {"rules": {"re:(": "secret"}}])
def test_main_refuses_to_start_on_a_bad_rules_file(
    tmp_path: Path,
    doc: object,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # a bad entity type fails in the loader; a bad regex when the redactor compiles it
    path = write(tmp_path, doc)
    monkeypatch.setattr(
        os,
        "environ",
        {"KAFKA_BOOTSTRAP_SERVERS": "b:9092", "SAFESTREAM_FIELD_RULES_FILE": str(path)},
    )
    assert main() == 2
    assert "invalid configuration" in caplog.text
