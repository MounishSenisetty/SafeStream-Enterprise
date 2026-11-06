import json
from collections import Counter

import pytest
from safestream_redactor import RedactionMode, RedactionPolicy, RedactionStats, Redactor

from safestream_enterprise import StructuredParseError, StructuredRedactor

R = StructuredRedactor()


def redact(obj: object) -> object:
    out = R.redact_line(json.dumps(obj))
    assert out.structured
    return json.loads(out.text)


def test_catches_what_the_text_engine_misses() -> None:
    line = '{"patient_mrn": "MR-4821", "password": "hunter2", "Phone": "555 0100", "host": "web-1"}'
    assert "MR-4821" in Redactor().redact(line)  # the OSS gap this module closes
    assert redact(json.loads(line)) == {
        "patient_mrn": "[REDACTED]",
        "password": "[REDACTED]",
        "Phone": "[REDACTED]",
        "host": "web-1",
    }


def test_key_spellings_normalise() -> None:
    out = redact({"last_name": "a", "LAST-NAME": "b", "userEmail": "c", "Last Name": "d"})
    assert set(out.values()) == {"[REDACTED]"}  # type: ignore[union-attr]


def test_specific_rules_do_not_hit_operational_keys() -> None:
    keep = {"hostname": "h", "filename": "f", "classname": "C", "mac_address": "m", "adobe": "x"}
    assert redact(keep) == keep


def test_sensitive_container_redacts_every_leaf_and_keeps_shape() -> None:
    out = redact({"credentials": {"user": "u", "pin": 1234, "ok": True, "n": None, "l": ["x"]}})
    assert out == {
        "credentials": {
            "user": "[REDACTED]",
            "pin": "[REDACTED]",
            "ok": True,
            "n": None,
            "l": ["[REDACTED]"],
        }
    }


def test_free_text_values_still_scanned_including_ints() -> None:
    out = redact({"msg": "login by bob@corp.example", "ref": 4111111111111111, "n": 42})
    assert out == {"msg": "login by [REDACTED]", "ref": "[REDACTED]", "n": 42}


def test_deep_nesting_and_root_array() -> None:
    deep: object = {"password": "p"}
    for _ in range(250):
        deep = [deep]
    out = R.redact_line(json.dumps(deep))
    assert out.structured and '"p"' not in out.text
    assert redact([{"email": "x"}, "ok"]) == [{"email": "[REDACTED]"}, "ok"]


def test_too_deep_or_invalid_json_falls_back_or_raises_in_strict_mode() -> None:
    too_deep = "[" * 1000 + '{"password": "hunter2"}' + "]" * 1000  # parses, can't serialise
    hostile = "[" * 2000 + "]" * 2000  # doesn't parse
    stats = RedactionStats()
    assert not R.redact_line(too_deep, stats).structured
    assert not R.redact_line(hostile).structured
    # Only the text fallback is counted, not the failed structured walk too.
    assert stats.counts == Counter(d.entity_type.value for d in R.redactor.detect(too_deep))
    for bad in (too_deep, hostile, b"\xff not json", '{"password": "hunter2"'):
        with pytest.raises(StructuredParseError) as info:
            R.redact_line(bad, strict=True)
        assert "hunter2" not in str(info.value)  # error never quotes the record


def test_regex_rules_match_raw_key() -> None:
    r = StructuredRedactor(field_rules={"re:^x-.*-sig$": "secret"})
    out = json.loads(r.redact_line('{"X-Amz-Sig": "abc", "x-amz-date": "d"}').text)
    assert out == {"X-Amz-Sig": "[REDACTED]", "x-amz-date": "d"}
    with pytest.raises(ValueError, match="invalid field rule"):
        StructuredRedactor(field_rules={"re:(": "secret"})


def test_non_json_falls_back_to_text_engine() -> None:
    out = R.redact_line(b"<Phone>x</Phone> mail bob@corp.example \xff")
    assert not out.structured and "bob@corp.example" not in out.text


def test_policy_and_custom_rules_and_stats() -> None:
    policy = RedactionPolicy(mode=RedactionMode.PSEUDONYMIZE, hmac_key=b"k" * 32)
    r = StructuredRedactor(Redactor(policy=policy), {"*Member_ID*": "id_number"})
    stats = RedactionStats()
    a = json.loads(r.redact_line('{"memberId": "M1", "x": "a@b.example"}', stats).text)
    b = json.loads(r.redact_line('{"MEMBER_ID": "M1"}', stats).text)
    assert a["memberId"] == b["MEMBER_ID"] and a["memberId"].startswith("<ID_NUMBER_")
    assert a["x"].startswith("<EMAIL_")
    assert dict(stats.counts) == {"id_number": 2, "email": 1}


def test_iban_fields_use_the_iban_type() -> None:
    policy = RedactionPolicy(mode=RedactionMode.PSEUDONYMIZE, hmac_key=b"k" * 32)
    r = StructuredRedactor(Redactor(policy=policy))
    stats = RedactionStats()
    out = json.loads(r.redact_line('{"payee_IBAN": "GB82WEST12345698765432"}', stats).text)
    assert out["payee_IBAN"].startswith("<IBAN_")
    assert dict(stats.counts) == {"iban": 1}


def test_ndjson_stream() -> None:
    lines = ['{"email": "a"}\n', "\n", "plain bob@corp.example\n"]
    assert list(R.redact_lines(lines)) == ['{"email":"[REDACTED]"}', "", "plain [REDACTED]"]


def test_long_keys_are_classified_but_never_cached() -> None:
    # hostile records must not be able to fill the key cache with huge keys
    r = StructuredRedactor()
    long_key = "x" * 10_000 + "password"
    assert r.classify_key(long_key) is not None  # still redacted as a password field
    assert r._classify_cached.cache_info().currsize == 0
    out = json.loads(r.redact_line(json.dumps({long_key: "hunter2", "email": "e"})).text)
    assert out[long_key] == "[REDACTED]" and out["email"] == "[REDACTED]"
    assert r._classify_cached.cache_info().currsize == 1  # only the short key
