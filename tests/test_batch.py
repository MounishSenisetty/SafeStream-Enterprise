import gzip
import io
import json
import os
import stat
import subprocess
import sys
import tracemalloc
from pathlib import Path

import pytest
from safestream_redactor import RedactionMode

from safestream_enterprise.batch import BatchReport, main, redact_stream
from safestream_enterprise.connectors.kafka import ConnectorConfig, build_redactor
from safestream_enterprise.rules import make_redactor

R = make_redactor(RedactionMode.REPLACE)
MIXED = (
    b'{"LastName":"Smith","msg":"mail bob@corp.example"}\n'
    b"<user><Phone>555 0100</Phone></user>\n"
    b"\n"
    b"plain text alice@corp.example\r\n"
    b'{"ok":1}'  # last line without a newline
)


def redact_bytes(data: bytes) -> tuple[bytes, BatchReport]:
    out, report = io.BytesIO(), BatchReport()
    redact_stream(R, io.BytesIO(data), out, report)
    return out.getvalue(), report


def test_stream_preserves_layout_and_fails_closed() -> None:
    out, report = redact_bytes(MIXED)
    assert out == (
        b'{"LastName":"[REDACTED]","msg":"mail [REDACTED]"}\n'
        b"<user><Phone>[REDACTED]</Phone></user>\n"
        b"\n"
        b"plain text [REDACTED]\r\n"
        b'{"ok":1}'
    )
    assert (report.lines, report.structured, report.text_fallback) == (5, 3, 1)
    assert dict(report.stats.counts) == {"person": 1, "email": 2, "phone": 1}


def test_same_output_as_the_kafka_connector() -> None:
    # backfill and stream must pseudonymize identically, or they won't join
    os_key = "k" * 32
    config = ConnectorConfig(bootstrap_servers="x", redaction_mode="pseudonymize", hmac_key=os_key)
    record = b'{"email":"a@b.example","note":"call 555-0100"}'
    batch = make_redactor(RedactionMode.PSEUDONYMIZE, os_key.encode()).redact_line(record).data
    assert batch == build_redactor(config).redact_line(record).data
    assert b"<EMAIL_" in batch


def test_tree_gzip_atomic_private_and_report(tmp_path: Path) -> None:
    raw = tmp_path / "raw" / "2026" / "11"
    raw.mkdir(parents=True)
    (raw / "app.ndjson").write_bytes(MIXED)
    (raw / "web.ndjson.gz").write_bytes(gzip.compress(MIXED))
    (raw / "image.png").write_bytes(b"\x89PNG not a log")
    report_path = tmp_path / "report.json"
    out = tmp_path / "clean"
    assert main([str(tmp_path / "raw"), "-o", str(out), "--report", str(report_path)]) == 0

    expected, _ = redact_bytes(MIXED)
    assert (out / "2026/11/app.ndjson").read_bytes() == expected
    assert gzip.decompress((out / "2026/11/web.ndjson.gz").read_bytes()) == expected
    assert not (out / "2026/11/image.png").exists()  # not a matching log file
    assert sorted(p.name for p in (out / "2026/11").iterdir()) == ["app.ndjson", "web.ndjson.gz"]
    assert stat.S_IMODE((out / "2026/11/app.ndjson").stat().st_mode) == 0o600

    report = json.loads(report_path.read_text())
    assert (report["files"], report["lines"], report["text_fallback_lines"]) == (2, 10, 2)
    assert report["redactions"] == {"email": 4, "person": 2, "phone": 2}
    assert report["field_rules"]["fingerprint"] == R.rules_fingerprint
    assert "Smith" not in report_path.read_text()  # content-free


def test_single_file_and_rules_file(tmp_path: Path) -> None:
    src = tmp_path / "in.jsonl"
    src.write_bytes(b'{"loyaltyNumber":"L-1","plan":"gold"}\n')
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": {"*loyalty_number*": "id_number"}}))
    dst = tmp_path / "out.jsonl"
    assert main([str(src), "-o", str(dst), "--rules", str(rules)]) == 0
    assert dst.read_bytes() == b'{"loyaltyNumber":"[REDACTED]","plan":"gold"}\n'


def test_stdin_to_stdout_pipe() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "safestream_enterprise.batch", "-"],
        input=b'{"password":"hunter2"}\nsecret bob@corp.example\n',
        capture_output=True,
        check=True,
        env={**os.environ, "LOG_LEVEL": "WARNING"},
    )
    assert proc.stdout == b'{"password":"[REDACTED]"}\nsecret [REDACTED]\n'
    assert b"hunter2" not in proc.stderr


def test_guards_and_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.ndjson").write_bytes(b"{}\n")
    assert main([str(raw), "-o", str(raw / "clean")]) == 2  # output inside input
    assert main([str(raw / "a.ndjson"), "-o", str(raw / "a.ndjson")]) == 2  # overwrite input
    assert main([str(tmp_path / "missing"), "-o", str(tmp_path / "x")]) == 2
    assert main([str(raw), "-o", "-"]) == 2  # files to stdout
    bad_rules = tmp_path / "bad.json"
    bad_rules.write_text('{"rules": {"*x*": "nope"}}')
    assert main([str(raw), "-o", str(tmp_path / "o"), "--rules", str(bad_rules)]) == 2
    # pseudonymize without SAFESTREAM_HMAC_KEY is a configuration error
    monkeypatch.delenv("SAFESTREAM_HMAC_KEY", raising=False)
    assert main([str(raw), "-o", str(tmp_path / "o"), "--mode", "pseudonymize"]) == 2


def test_partial_output_never_replaces_a_file(tmp_path: Path) -> None:
    class Boom(Exception):
        pass

    src = tmp_path / "in.ndjson"
    src.write_bytes(b'{"a":1}\n' * 10)
    dst = tmp_path / "out.ndjson"
    dst.write_bytes(b"previous good output\n")

    class Exploding:
        rule_count = 0
        rules_fingerprint = ""

        def redact_line(self, *_a: object, **_k: object) -> object:
            raise Boom

    from safestream_enterprise import batch

    with pytest.raises(Boom):
        batch.run(Exploding(), [str(src)], str(dst), batch.DEFAULT_INCLUDE)  # type: ignore[arg-type]
    assert dst.read_bytes() == b"previous good output\n"  # untouched
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".partial")] == []


def _peak_bytes(lines: int) -> int:
    data = b'{"email":"user@corp.example","msg":"login from 10.1.2.3","n":1}\n' * lines
    tracemalloc.start()
    redact_stream(R, io.BytesIO(data), _Sink(), BatchReport())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


class _Sink(io.RawIOBase):
    """Discards output, so only the redaction pipeline's own memory is measured."""

    def writable(self) -> bool:
        return True

    def write(self, b: object) -> int:
        return len(b)  # type: ignore[arg-type]


def test_memory_does_not_grow_with_input_size() -> None:
    _peak_bytes(200)  # warm caches (regex compilation, key classification)
    small, large = _peak_bytes(1_000), _peak_bytes(10_000)
    # 10x the records, same peak: memory is bounded by the longest line
    assert large < small * 1.5 + 64 * 1024, (small, large)


# --- pre-release review regressions ------------------------------------------


def test_multiline_json_is_not_picked_up_by_default_and_warns_if_forced(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    pretty = b'{\n  "user": {\n    "password": "hunter2"\n  }\n}\n'
    (raw / "users.json").write_bytes(pretty)
    (raw / "page.xml").write_bytes(b"<user>\n  <password>hunter2</password>\n</user>\n")
    out = tmp_path / "clean"
    assert main([str(raw), "-o", str(out)]) == 0
    assert not out.exists() or list(out.rglob("*")) == []  # neither default-included
    # explicitly included: still runs, but says loudly that field rules didn't apply
    assert main([str(raw), "-o", str(out), "--include", "*.json"]) == 0
    assert "text redaction only" in caplog.text and "field rules did not apply" in caplog.text


def test_colliding_destinations_are_refused(tmp_path: Path) -> None:
    for day in ("day1", "day2"):
        (tmp_path / day).mkdir()
        (tmp_path / day / "app.ndjson").write_bytes(b'{"day":"' + day.encode() + b'"}\n')
    out = tmp_path / "clean"
    assert (
        main(
            [str(tmp_path / "day1/app.ndjson"), str(tmp_path / "day2/app.ndjson"), "-o", f"{out}/"]
        )
        == 2
    )
    assert main([str(tmp_path / "day1"), str(tmp_path / "day2"), "-o", str(out)]) == 2
    assert not out.exists()  # refused before anything was written
