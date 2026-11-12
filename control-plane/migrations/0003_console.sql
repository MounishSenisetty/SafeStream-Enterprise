-- The console (app.safestreamdata.com). People sign in through Cloudflare
-- Access with their own identity provider; this table says which tenant each
-- verified email may see, and whether it may change anything there.

CREATE TABLE console_users (
  email      TEXT NOT NULL,                 -- lower case, as verified by Access
  tenant_id  TEXT NOT NULL REFERENCES tenants (id),
  role       TEXT NOT NULL CHECK (role IN ('viewer', 'admin')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (email, tenant_id)
);
CREATE INDEX console_users_by_tenant ON console_users (tenant_id);

-- Each connector's latest shadow comparison, for the fleet-wide "what would
-- promoting the candidate change" view. Counts and entity-type names only,
-- cumulative since the connector began evaluating the candidate.
ALTER TABLE agents ADD COLUMN shadow_since TEXT;
ALTER TABLE agents ADD COLUMN shadow_records INTEGER;
ALTER TABLE agents ADD COLUMN shadow_changed_records INTEGER;
ALTER TABLE agents ADD COLUMN shadow_errors INTEGER;
ALTER TABLE agents ADD COLUMN shadow_active TEXT;     -- JSON {"entity": count}
ALTER TABLE agents ADD COLUMN shadow_candidate TEXT;  -- JSON {"entity": count}
