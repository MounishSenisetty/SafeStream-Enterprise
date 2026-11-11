"""Tamper-evident audit events, and ``safestream-audit verify``.

Since ``safestream.audit/v2`` every audit event a connector publishes names its
place in a hash chain::

    "chain": {"id": "<instance>-<start time>", "seq": 4, "prev": "sha256:…"}

``prev`` is the SHA-256 of the previous event of the same chain, byte for byte
as it was published (``null`` for ``seq`` 0). One chain covers one run of one
connector process; a restart starts a new chain. So, given the events of a
period::

    kafka-console-consumer --topic safestream-audit --from-beginning … > audit.ndjson
    safestream-audit verify audit.ndjson

reports, per chain, whether any event was **altered**, **removed** or
**reordered**, and whether the chain was closed by a clean shutdown.

What a hash chain cannot show on its own: that the *last* events of a chain,
or a whole chain, were removed, or that someone able to rewrite every stored
copy rebuilt the chain from scratch. For that, record each chain's ``head``
(printed by ``verify``) somewhere the audit store's administrators cannot
write, and check later that the chain still contains it:
``--head <chain id>=<hash>``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

SCHEMA = "safestream.audit/v2"


def event_hash(data: bytes) -> str:
    """The value the next event's ``chain.prev`` must carry."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Chain:
    """What verification found for one chain."""

    id: str
    instance: str = ""
    events: int = 0
    start: str = ""
    end: str = ""
    #: Hash of the last event seen: the value to anchor elsewhere.
    head: str = ""
    #: Hash of every event seen, to find an anchor recorded earlier.
    hashes: set[str] = field(default_factory=set)
    #: The last event closed its window on a clean shutdown.
    closed: bool = False
    problems: list[str] = field(default_factory=list)

    def report(self) -> dict[str, object]:
        return {
            "chain": self.id,
            "instance": self.instance,
            "events": self.events,
            "window": {"start": self.start, "end": self.end},
            "closed": self.closed,
            "head": self.head,
            "problems": self.problems,
        }


def verify(lines: Iterable[bytes]) -> tuple[list[Chain], int]:
    """Check audit events (one JSON document per line, in published order).

    Returns the chains found and the number of events that carry no chain
    (``safestream.audit/v1``), which cannot be checked.
    """
    chains: dict[str, Chain] = {}
    unchained = 0
    for number, raw in enumerate(lines, 1):
        line = raw.rstrip(b"\r\n")
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            link = event.get("chain")
            if link is None:
                unchained += 1
                continue
            chain_id, seq, prev = str(link["id"]), link["seq"], link["prev"]
            window = event["window"]
        except (ValueError, KeyError, TypeError, AttributeError):
            chains.setdefault("?", Chain("?")).problems.append(
                f"line {number} is not an audit event"
            )
            continue
        chain = chains.setdefault(chain_id, Chain(chain_id, start=str(window.get("start", ""))))
        if seq != chain.events:
            what = "missing" if isinstance(seq, int) and seq > chain.events else "out of order"
            chain.problems.append(
                f"line {number}: expected event {chain.events}, found {seq} ({what})"
            )
        elif prev != (chain.head or None):
            # The event before this one is not the one this event was chained to.
            chain.problems.append(
                f"line {number}: event {seq - 1 if seq else seq} was altered or replaced"
            )
        chain.instance = str(event.get("instance", ""))
        chain.events = seq + 1 if isinstance(seq, int) else chain.events + 1
        chain.end = str(window.get("end", ""))
        chain.closed = bool(window.get("final"))
        chain.head = event_hash(line)
        chain.hashes.add(chain.head)
    return list(chains.values()), unchained


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``safestream-audit``): 0 intact, 1 problems found, 2 usage."""
    parser = argparse.ArgumentParser(
        prog="safestream-audit", description="Verify SafeStream Enterprise audit events."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="check the hash chains in exported audit events")
    check.add_argument("files", nargs="+", help="NDJSON files of audit events, or - for stdin")
    check.add_argument(
        "--head",
        action="append",
        default=[],
        metavar="CHAIN=HASH",
        help="a chain head recorded earlier; fails unless that chain contains it (repeatable)",
    )
    check.add_argument(
        "--require-closed",
        action="store_true",
        help="also fail for a chain that does not end with a clean shutdown",
    )
    args = parser.parse_args(argv)

    def lines() -> Iterable[bytes]:
        for name in args.files:
            if name == "-":
                yield from sys.stdin.buffer
            else:
                with open(name, "rb") as source:
                    yield from source

    try:
        chains, unchained = verify(lines())
        expected = dict(item.split("=", 1) for item in args.head)
    except OSError as exc:
        print(f"safestream-audit: {exc.filename}: {exc.strerror}", file=sys.stderr)
        return 2
    except ValueError:
        parser.error("--head takes CHAIN=HASH")
    by_id = {c.id: c for c in chains}
    for chain_id, head in expected.items():
        found = by_id.setdefault(chain_id, Chain(chain_id))
        if found not in chains:
            chains.append(found)
        if head not in found.hashes:
            found.problems.append(
                "does not contain the recorded head: events were removed or the chain rewritten"
                if found.events
                else "recorded chain is absent"
            )
    if args.require_closed:
        for chain in chains:
            if not chain.closed and chain.events:
                chain.problems.append("not closed: the process crashed, or final events are gone")
    intact = not any(c.problems for c in chains)
    print(
        json.dumps(
            {
                "intact": intact,
                "chains": [c.report() for c in chains],
                "unchained_events": unchained,
            },
            indent=2,
        )
    )
    return 0 if intact else 1


if __name__ == "__main__":
    sys.exit(main())
