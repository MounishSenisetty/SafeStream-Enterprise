"""Signed policy bundles: field rules that cannot be weakened by editing a file.

A plain rules file (``SAFESTREAM_FIELD_RULES_FILE``) is trusted because of
where it is mounted: anyone who can edit that ConfigMap can quietly remove a
rule. A *policy bundle* carries the same rules with an Ed25519 signature, and
the connector only obeys bundles signed by a key it was told to trust::

    safestream-policy keygen policy-signing.key
    safestream-policy sign field-rules.json --key policy-signing.key \\
        --tenant acme --version 7 -o policy.json
    safestream-policy verify policy.json

The bundle is JSON::

    {"schema": "safestream.policy/v1",
     "payload": "<base64 of the payload JSON below>",
     "signatures": [{"key_id": "…", "algorithm": "ed25519", "signature": "<base64>"}]}

    {"tenant": "acme", "version": 7, "issued_at": "2026-11-11T09:00:00+00:00",
     "field_rules": {"mode": "extend", "rules": {...}, "disable": [...]}}

The signature covers the payload bytes exactly as stored, so nothing has to be
re-serialised to check it. Several signatures are allowed, which is how a
signing key is rotated: sign with the old and the new key until every
connector trusts the new one.

A bundle is refused, and the rules already in force stay in force, when

* it is not a well-formed bundle of this schema;
* no trusted key signed it, or the signature does not verify;
* it is for another tenant;
* its version is below the configured minimum, or not newer than the bundle
  it would replace (a rollback to an older, weaker policy);
* its field rules are invalid (same checks as a rules file).

Versions are compared within a running process. Across restarts the floor is
``SAFESTREAM_POLICY_MIN_VERSION``: raise it when you retire a policy, so an old
signed bundle cannot be put back.

Refusal messages name the reason and never quote rule text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from safestream_redactor import EntityType, RedactionMode

from safestream_enterprise.rules import make_redactor, parse_field_rules

SCHEMA = "safestream.policy/v1"
#: Environment variable holding the trusted public keys (comma-separated base64).
PUBLIC_KEYS_ENV = "SAFESTREAM_POLICY_PUBLIC_KEYS"


class PolicyError(ValueError):
    """The bundle was refused. The message is safe to log: it holds no rule text."""


@dataclass(frozen=True)
class Policy:
    """A verified bundle."""

    tenant: str
    version: int
    #: Which trusted key signed it.
    key_id: str
    issued_at: str
    #: The effective, ordered rule table for :class:`StructuredRedactor`.
    rules: dict[str, EntityType]
    #: SHA-256 of the bundle file, to notice an unchanged file cheaply.
    digest: str


def key_id(public_key: Ed25519PublicKey) -> str:
    """Short, stable name for a public key: the first 16 hex digits of its SHA-256."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def parse_public_keys(text: str) -> dict[str, Ed25519PublicKey]:
    """Trusted keys from comma-separated base64, by key id. Raises ``ValueError``."""
    keys: dict[str, Ed25519PublicKey] = {}
    for item in filter(None, (part.strip() for part in text.split(","))):
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(item, validate=True))
        except (binascii.Error, ValueError):
            raise ValueError("a policy public key is not a base64 Ed25519 public key") from None
        keys[key_id(key)] = key
    if not keys:
        raise ValueError("no policy public key given")
    return keys


def _checked_rules(field_rules: dict[str, object]) -> dict[str, EntityType]:
    """The effective rule table, proven usable: schema, entity types and regexes."""
    rules = parse_field_rules(field_rules)
    make_redactor(RedactionMode.REPLACE, rules=rules)  # compiles every pattern
    return rules


def sign(
    field_rules: dict[str, object],
    private_key: Ed25519PrivateKey,
    tenant: str,
    version: int,
    issued_at: datetime | None = None,
) -> bytes:
    """A signed bundle for ``field_rules`` (the rules-file document), as file content.

    The rules are validated first: a bundle that no connector would accept is
    never produced. Raises :class:`FieldRulesError` or ``ValueError``.
    """
    if version < 1:
        raise ValueError("policy version must be 1 or greater")
    if not tenant:
        raise ValueError("policy tenant must not be empty")
    _checked_rules(field_rules)
    issued = (issued_at or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    payload = json.dumps(
        {"tenant": tenant, "version": version, "issued_at": issued, "field_rules": field_rules},
        separators=(",", ":"),
    ).encode()
    bundle = {
        "schema": SCHEMA,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "key_id": key_id(private_key.public_key()),
                "algorithm": "ed25519",
                "signature": base64.b64encode(private_key.sign(payload)).decode(),
            }
        ],
    }
    return json.dumps(bundle, indent=2).encode() + b"\n"


def verify(
    data: bytes,
    trusted: dict[str, Ed25519PublicKey],
    tenant: str | None = None,
    min_version: int = 1,
    current: Policy | None = None,
) -> Policy:
    """Check ``data`` (a bundle file's content) and return the policy it carries.

    ``current`` is the policy now in force, if any: the new one must be newer.
    Raises :class:`PolicyError` naming the first reason for refusal.
    """
    try:
        bundle = json.loads(data)
        if bundle["schema"] != SCHEMA:
            raise PolicyError(f"unsupported bundle schema (expected {SCHEMA})")
        payload = base64.b64decode(bundle["payload"], validate=True)
        signatures = [
            (str(s["key_id"]), base64.b64decode(s["signature"], validate=True))
            for s in bundle["signatures"]
            if s.get("algorithm") == "ed25519"
        ]
    except PolicyError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        # ValueError covers bad JSON, bad UTF-8 and bad base64.
        raise PolicyError("not a well-formed policy bundle") from None

    signer = None
    for kid, signature in signatures:
        key = trusted.get(kid)
        if key is None:
            continue
        try:
            key.verify(signature, payload)
        except InvalidSignature:
            raise PolicyError(f"signature by key {kid} does not verify") from None
        signer = kid
        break
    if signer is None:
        raise PolicyError("not signed by a trusted key")

    # Only now is the payload trusted enough to interpret.
    try:
        body = json.loads(payload)
        bundle_tenant, version, field_rules = body["tenant"], body["version"], body["field_rules"]
        issued_at = str(body.get("issued_at", ""))
        if not isinstance(bundle_tenant, str) or type(version) is not int:
            raise TypeError
        if not isinstance(field_rules, dict):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise PolicyError("signed payload is not a policy") from None
    if tenant is not None and bundle_tenant != tenant:
        raise PolicyError("bundle is for another tenant")
    if version < min_version:
        raise PolicyError(f"version {version} is below the minimum {min_version}")
    if current is not None and version <= current.version:
        raise PolicyError(f"version {version} is not newer than version {current.version} in force")
    try:
        rules = _checked_rules(field_rules)
    except ValueError:
        # The validation message can quote patterns: keep it out of the log.
        raise PolicyError("field rules in the bundle are invalid") from None
    return Policy(
        tenant=bundle_tenant,
        version=version,
        key_id=signer,
        issued_at=issued_at,
        rules=rules,
        digest=hashlib.sha256(data).hexdigest(),
    )


#: Where bundle bytes come from: returns ``None`` when there is no bundle
#: (a candidate that was withdrawn, a control plane with nothing published).
BundleReader = Callable[[], "bytes | None"]


class PolicySource:
    """Where bundles come from, plus the trust settings to check them against.

    ``origin`` is a bundle file (the usual case: a mounted ConfigMap) or a
    reader, such as the control-plane client's latest download. Either way the
    bytes are verified here, by the connector: whatever delivers a bundle is
    never trusted to have checked it.
    """

    def __init__(
        self,
        origin: str | Path | BundleReader,
        trusted: dict[str, Ed25519PublicKey],
        tenant: str | None = None,
        min_version: int = 1,
        missing_ok: bool = False,
    ) -> None:
        self.path = None if callable(origin) else Path(origin)
        self._reader = origin if callable(origin) else None
        self.trusted = trusted
        self.tenant = tenant
        self.min_version = min_version
        #: A missing file means "no bundle" rather than an error (candidates).
        self.missing_ok = missing_ok

    def read(self) -> bytes | None:
        """The bundle's bytes, or ``None`` if there is none. Raises :class:`PolicyError`."""
        if self._reader is not None:
            return self._reader()
        assert self.path is not None
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            if self.missing_ok:
                return None
            raise PolicyError("cannot read policy bundle: No such file or directory") from None
        except OSError as exc:
            raise PolicyError(f"cannot read policy bundle: {exc.strerror}") from None

    def load(self, current: Policy | None = None) -> Policy | None:
        """The policy on offer, or ``None`` if it is the one already in force (or
        there is none on offer while a policy is in force).

        Raises :class:`PolicyError` if it cannot be read or is refused.
        """
        data = self.read()
        if data is None:
            if current is not None:
                return None
            raise PolicyError("no policy bundle available")
        if current is not None and hashlib.sha256(data).hexdigest() == current.digest:
            return None
        return verify(data, self.trusted, self.tenant, self.min_version, current)


# ----------------------------------------------------------------------
# safestream-policy
# ----------------------------------------------------------------------


def _load_private_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point (``safestream-policy``): 0 ok, 1 refused or failed, 2 usage."""
    parser = argparse.ArgumentParser(
        prog="safestream-policy",
        description="Create and check signed policy bundles for SafeStream Enterprise.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="create a signing key; prints the public key to trust")
    keygen.add_argument("private_key", help="file to write the private key to (PEM, mode 0600)")
    signer = sub.add_parser("sign", help="sign a field-rules file into a policy bundle")
    signer.add_argument("rules", help="field rules JSON file")
    signer.add_argument("--key", required=True, help="private key file from keygen")
    signer.add_argument("--tenant", required=True)
    signer.add_argument("--version", required=True, type=int, help="must increase on every change")
    signer.add_argument("-o", "--output", required=True, help="bundle file to write")
    checker = sub.add_parser("verify", help="check a bundle as a connector would")
    checker.add_argument("bundle")
    checker.add_argument(
        "--public-key", help=f"trusted key(s), comma-separated base64 (default: ${PUBLIC_KEYS_ENV})"
    )
    checker.add_argument("--tenant")
    checker.add_argument("--min-version", type=int, default=1)
    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            private = Ed25519PrivateKey.generate()
            pem = private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            # O_EXCL: never overwrite a key; 0600: the file is the signing authority.
            fd = os.open(args.private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(pem)
            public = private.public_key()
            print(json.dumps({"key_id": key_id(public), "public_key": encode_public_key(public)}))
        elif args.command == "sign":
            rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
            if not isinstance(rules, dict):
                raise ValueError("the rules file must contain a JSON object")
            bundle = sign(rules, _load_private_key(args.key), args.tenant, args.version)
            Path(args.output).write_bytes(bundle)
            print(json.dumps({"tenant": args.tenant, "version": args.version}))
        else:
            trusted = parse_public_keys(args.public_key or os.environ.get(PUBLIC_KEYS_ENV, ""))
            policy = verify(Path(args.bundle).read_bytes(), trusted, args.tenant, args.min_version)
            print(
                json.dumps(
                    {
                        "tenant": policy.tenant,
                        "version": policy.version,
                        "key_id": policy.key_id,
                        "issued_at": policy.issued_at,
                        "rules": len(policy.rules),
                    }
                )
            )
    except (OSError, ValueError) as exc:  # PolicyError and FieldRulesError are ValueErrors
        print(f"safestream-policy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
