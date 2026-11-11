-- SafeStream control plane. Nothing in this database is record content:
-- tenants and their keys, access tokens (hashed), policy metadata, and what
-- each connector last reported about itself.

CREATE TABLE tenants (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  created_at          TEXT NOT NULL,
  -- Ed25519 policy-signing key. The private half is AES-GCM encrypted with the
  -- Worker's KEY_ENCRYPTION_KEY secret; the database alone cannot sign.
  key_id              TEXT NOT NULL,
  public_key          TEXT NOT NULL,
  wrapped_private_key TEXT NOT NULL,
  active_version      INTEGER,
  candidate_version   INTEGER
);

CREATE TABLE tokens (
  hash       TEXT PRIMARY KEY,              -- SHA-256 of the token; the token itself is never stored
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  kind       TEXT NOT NULL CHECK (kind IN ('admin', 'agent')),
  label      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX tokens_by_tenant ON tokens (tenant_id);

CREATE TABLE policies (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  version    INTEGER NOT NULL,
  digest     TEXT NOT NULL,                 -- SHA-256 of the signed bundle
  rule_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE agents (
  tenant_id         TEXT NOT NULL REFERENCES tenants (id),
  instance          TEXT NOT NULL,
  first_seen_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL,
  connector_version TEXT NOT NULL,
  policy_version    INTEGER,
  shadow_version    INTEGER,
  PRIMARY KEY (tenant_id, instance)
);

-- Head of every audit hash chain, anchored outside the customer's own audit
-- store: what "safestream-audit verify --head" checks against.
CREATE TABLE chains (
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  chain_id   TEXT NOT NULL,
  instance   TEXT NOT NULL,
  first_seq  INTEGER NOT NULL,
  next_seq   INTEGER NOT NULL,
  head       TEXT NOT NULL,
  closed     INTEGER NOT NULL DEFAULT 0,
  broken     INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, chain_id)
);
