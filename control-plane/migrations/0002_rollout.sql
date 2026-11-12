-- Staged rollout of a promoted policy, and the per-window health a rollout
-- is judged on. Still no record content: counts and connector names only.

-- The version being rolled out, which stage it is in, since when, and why it
-- stopped (NULL while it is progressing). While a rollout runs, active_version
-- is what every connector outside the rollout's cohort is served.
ALTER TABLE tenants ADD COLUMN rollout_version INTEGER;
ALTER TABLE tenants ADD COLUMN rollout_stage INTEGER;
ALTER TABLE tenants ADD COLUMN rollout_stage_started_at TEXT;
ALTER TABLE tenants ADD COLUMN rollout_soak_seconds INTEGER;
ALTER TABLE tenants ADD COLUMN rollout_halted_reason TEXT;

-- The connector's most recent audit window, and when it arrived (server
-- time, so it compares with rollout_stage_started_at): what a stage checks.
ALTER TABLE agents ADD COLUMN window_reported_at TEXT;
ALTER TABLE agents ADD COLUMN window_egress INTEGER;
ALTER TABLE agents ADD COLUMN window_dlq INTEGER;
ALTER TABLE agents ADD COLUMN window_canary_checks INTEGER;
ALTER TABLE agents ADD COLUMN window_canary_leaks INTEGER;
