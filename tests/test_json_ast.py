import json

from safestream_redactor import RedactionMode, RedactionPolicy, RedactionStats, Redactor

from safestream_enterprise import StructuredRedactor

R = StructuredRedactor()


def redact(obj: object) -> object:
    out = R.redact_line(json.dumps(obj))
    assert out.structured
    return json.loads(out.text)


def test_catches_what_the_text_engine_misses() -> None:
    line = '{"LastName": "Smith", "password": "hunter2", "Phone": "555 0100", "host": "web-1"}'
    assert "Smith" in Redactor().redact(line)  # the OSS gap this module closes
    assert redact(json.loads(line)) == {
        "LastName": "[REDACTED]",
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
    for _ in range(2000):
        deep = [deep]
    assert '"p"' not in R.redact_line(json.dumps(deep)).text
    assert redact([{"email": "x"}, "ok"]) == [{"email": "[REDACTED]"}, "ok"]


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


def test_ndjson_stream() -> None:
    lines = ['{"email": "a"}\n', "\n", "plain bob@corp.example\n"]
    assert list(R.redact_lines(lines)) == ['{"email":"[REDACTED]"}', "", "plain [REDACTED]"]
