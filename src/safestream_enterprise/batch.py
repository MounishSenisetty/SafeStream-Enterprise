"""Batch redaction for data already in the lake: files, directory trees, or stdin.

The Kafka connector protects new data in flight; this backfills what landed
before it. It uses the same redactor (:func:`~safestream_enterprise.rules.make_redactor`):
the same field rules, rules file, redaction mode and HMAC key. A backfilled
record therefore gets exactly the pseudonyms the stream would have given it.

::

    safestream-batch app.ndjson.gz -o clean/app.ndjson.gz
    safestream-batch lake/raw/ -o lake/clean/ --rules field-rules.json --report report.json
    aws s3 cp s3://lake/raw/x.ndjson.gz - | gunzip | safestream-batch - | aws s3 cp - s3://lake/clean/x.ndjson

* **Constant memory.** Input is read one line at a time (one JSON or XML
  record per line), so a file of any size runs in memory proportional to its
  longest line.
* **Object storage via pipes.** ``-`` reads stdin and writes stdout, so any
  CLI that streams objects (``aws s3 cp``, ``gsutil cat``, ``azcopy``) works
  with no SDK dependency.
* **gzip** in and out, chosen by the ``.gz`` suffix.
* **Atomic and private.** Each output is written to a temporary file in the
  destination directory, fsynced, then renamed into place, so a crash never
  leaves a half-redacted file. Outputs are created mode 0600.
* **Fail closed.** A line that is not JSON or XML is text-redacted by the OSS
  engine. Line endings and blank lines are preserved.
* **Content-free report.** ``--report`` writes counts (files, lines, redactions
  by entity type) plus the mode and rule fingerprint, never content.

Secrets are read from the environment, never from arguments, which other
users can see in the process list: ``SAFESTREAM_HMAC_KEY`` for pseudonymize
mode, as for the connector.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import json
import logging
import os
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from safestream_redactor import RedactionMode, RedactionStats

from safestream_enterprise import __version__
from safestream_enterprise.logs import configure_logging
from safestream_enterprise.parsers.json_ast import StructuredRedactor
from safestream_enterprise.rules import make_redactor

logger = logging.getLogger("safestream_enterprise.batch")

#: Files picked up when an input is a directory (plain or gzipped). Only
#: one-record-per-line formats: a pretty-printed ``.json`` or ``.xml`` document
#: spans many lines, and redacting it line by line would bypass the field rules.
DEFAULT_INCLUDE = ("*.ndjson", "*.jsonl", "*.log")


class BatchError(Exception):
    """A usage or I/O problem; the message names it and never quotes content."""


@dataclass
class BatchReport:
    """Content-free totals for a run."""

    files: int = 0
    lines: int = 0
    structured: int = 0
    text_fallback: int = 0
    stats: RedactionStats = field(default_factory=RedactionStats)

    def to_json(self, redactor: StructuredRedactor, mode: RedactionMode, seconds: float) -> str:
        return json.dumps(
            {
                "tool": "safestream-enterprise-batch",
                "version": __version__,
                "redaction_mode": mode.value,
                "field_rules": {
                    "count": redactor.rule_count,
                    "fingerprint": redactor.rules_fingerprint,
                },
                "files": self.files,
                "lines": self.lines,
                "structured_lines": self.structured,
                "text_fallback_lines": self.text_fallback,
                "redactions": dict(sorted(self.stats.counts.items())),
                "duration_seconds": round(seconds, 3),
            },
            indent=2,
        )


def redact_stream(
    redactor: StructuredRedactor, src: BinaryIO, dst: BinaryIO, report: BatchReport
) -> None:
    """Redact ``src`` to ``dst`` line by line, preserving line endings."""
    for line in src:
        body = line.rstrip(b"\r\n")
        ending = line[len(body) :]
        report.lines += 1
        if not body.strip():
            dst.write(line)  # blank line: nothing to redact
            continue
        record = redactor.redact_line(body, report.stats)
        if record.structured:
            report.structured += 1
        else:
            report.text_fallback += 1
        dst.write(record.data + ending)


def _open_input(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore[return-value]
    return path.open("rb")


@contextmanager
def _atomic_output(path: Path) -> Iterator[BinaryIO]:
    """Write ``path`` via a fsynced temp file and an atomic rename (gzip if ``.gz``)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".partial")
    try:
        with os.fdopen(fd, "wb") as raw:
            if path.suffix == ".gz":
                with gzip.GzipFile(filename=path.stem, mode="wb", fileobj=raw) as gz:
                    yield gz  # type: ignore[misc]
            else:
                yield raw
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _matches(path: Path, include: Sequence[str]) -> bool:
    name = path.name.removesuffix(".gz")
    return any(fnmatch.fnmatch(name, pattern) for pattern in include)


def plan(inputs: Sequence[str], output: str, include: Sequence[str]) -> list[tuple[Path, Path]]:
    """``(source, destination)`` pairs for file inputs. Raises :class:`BatchError`."""
    out = Path(output)
    sources = [Path(i) for i in inputs]
    for src in sources:
        if not src.exists():
            raise BatchError(f"input not found: {src}")
    single_file = len(sources) == 1 and sources[0].is_file()
    if single_file and not output.endswith(os.sep) and not out.is_dir():
        pairs = [(sources[0], out)]
    else:
        pairs = []
        for src in sources:
            if src.is_dir():
                pairs += [
                    (f, out / f.relative_to(src))
                    for f in sorted(src.rglob("*"))
                    if f.is_file() and _matches(f, include)
                ]
            else:
                pairs.append((src, out / src.name))
    seen: dict[Path, Path] = {}
    for src, dst in pairs:
        if dst.resolve() == src.resolve():
            raise BatchError(f"output would overwrite its input: {src}")
        first = seen.setdefault(dst.resolve(), src)
        if first is not src:
            raise BatchError(f"{first} and {src} would both be written to {dst}")
    out_resolved = out.resolve()
    for src in sources:
        if src.is_dir() and out_resolved.is_relative_to(src.resolve()):
            raise BatchError(f"output {out} is inside input directory {src}")
    return pairs


def run(
    redactor: StructuredRedactor, inputs: Sequence[str], output: str, include: Sequence[str]
) -> BatchReport:
    """Redact every input. ``["-"]`` with output ``"-"`` streams stdin to stdout."""
    report = BatchReport()
    if list(inputs) == ["-"]:
        if output == "-":
            redact_stream(redactor, sys.stdin.buffer, sys.stdout.buffer, report)
            sys.stdout.buffer.flush()
        else:
            with _atomic_output(Path(output)) as dst:
                redact_stream(redactor, sys.stdin.buffer, dst, report)
        report.files = 1
        return report
    if "-" in inputs:
        raise BatchError("'-' (stdin) cannot be combined with other inputs")
    if output == "-":
        raise BatchError("stdout output needs stdin input; use -o PATH for files")
    for src_path, dst_path in plan(inputs, output, include):
        before = report.lines
        with _open_input(src_path) as fin, _atomic_output(dst_path) as fout:
            redact_stream(redactor, fin, fout, report)
        report.files += 1
        logger.info("redacted %s -> %s (%d lines)", src_path, dst_path, report.lines - before)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``safestream-batch``): 0 ok, 1 I/O error, 2 usage/config error."""
    parser = argparse.ArgumentParser(
        prog="safestream-batch",
        description="Redact NDJSON / XML-per-line files, directory trees or stdin.",
    )
    parser.add_argument("inputs", nargs="+", help="files, directories, or - for stdin")
    parser.add_argument(
        "-o", "--output", default="-", help="output file or directory, or - for stdout"
    )
    parser.add_argument("--rules", help="field rules JSON file (same format as the connector)")
    parser.add_argument(
        "--mode",
        choices=[m.value for m in RedactionMode],
        default=os.environ.get("SAFESTREAM_MODE", "replace"),
        help="redaction mode (default: $SAFESTREAM_MODE or replace); "
        "pseudonymize reads its key from $SAFESTREAM_HMAC_KEY",
    )
    parser.add_argument(
        "--include",
        action="append",
        help="glob for files in input directories (repeatable; default "
        f"{' '.join(DEFAULT_INCLUDE)}, each also matched with .gz)",
    )
    parser.add_argument("--report", help="write a content-free JSON report to this path")
    args = parser.parse_args(argv)
    configure_logging()  # stderr: stdout may be the redacted data stream

    mode = RedactionMode(args.mode)
    hmac_key = os.environ.get("SAFESTREAM_HMAC_KEY")
    try:
        redactor = make_redactor(mode, hmac_key.encode() if hmac_key else None, args.rules)
    except ValueError as exc:
        logger.error("invalid configuration: %s", exc)
        return 2

    started = time.monotonic()
    try:
        report = run(redactor, args.inputs, args.output, args.include or DEFAULT_INCLUDE)
    except BatchError as exc:
        logger.error("%s", exc)
        return 2
    except OSError as exc:
        # strerror and filename only: never anything read from the data
        logger.error("I/O error: %s: %s", exc.strerror, exc.filename)
        return 1
    summary = report.to_json(redactor, mode, time.monotonic() - started)
    if args.report:
        Path(args.report).write_text(summary + "\n", encoding="utf-8")
    logger.info(
        "done: %d file(s), %d line(s), %d redaction(s)",
        report.files,
        report.lines,
        report.stats.total,
    )
    if report.text_fallback:
        # Often the sign of multi-line (pretty-printed) JSON or XML, where no
        # single line parses and field rules never apply.
        logger.warning(
            "%d line(s) were not one-line JSON or XML and got text redaction only; "
            "field rules did not apply to them. This tool expects one record per line.",
            report.text_fallback,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
