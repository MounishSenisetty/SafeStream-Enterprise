// Staged rollout of a promoted policy.
//
// Promoting a version does not hand it to every connector at once. It goes
// to one connector first, then to a tenth of the fleet, then to all of it.
// A stage moves on only when every connector in it has reported a window
// under the new version and the stage has lasted its soak time. It halts,
// and stays where it is until an admin resumes or aborts it, as soon as a
// connector on the new version reports a leak canary, or a DLQ rate clearly
// above the rest of the fleet's.
//
// A halt cannot pull the version back from connectors that already have it:
// a connector refuses any policy older than the one in force, by design (an
// older policy may be a weaker one). The fix for a bad version is a newer one,
// which is rolled out the same way.
//
// The cohort of a stage is the first N connectors seen in the last
// LIVE_MINUTES, ordered by a hash of the tenant, version and connector name:
// stable while the fleet is, different for every version (so the same pod is
// not always first), and unguessable from outside.

import { sha256Hex } from "./crypto";

export const STAGES = ["first_agent", "ten_percent"] as const;
export const DEFAULT_SOAK_SECONDS = 600;
const LIVE_MINUTES = 10;
/** A window needs this many records before its DLQ rate is judged. */
const MIN_RECORDS = 100;
/** Halt when the new version's DLQ rate exceeds the fleet's by this much. */
const DLQ_MARGIN = 0.01;

export interface Rollout {
  version: number;
  stage: number;
  stageStartedAt: string;
  soakSeconds: number;
  haltedReason: string | null;
}

interface TenantRow {
  active_version: number | null;
  rollout_version: number | null;
  rollout_stage: number | null;
  rollout_stage_started_at: string | null;
  rollout_soak_seconds: number | null;
  rollout_halted_reason: string | null;
}

export interface AgentRow {
  instance: string;
  policy_version: number | null;
  window_reported_at: string | null;
  window_egress: number | null;
  window_dlq: number | null;
  window_canary_leaks: number | null;
}

export async function tenantState(db: D1Database, tenant: string): Promise<{ active: number | null; rollout: Rollout | null }> {
  const row = await db
    .prepare(
      "SELECT active_version, rollout_version, rollout_stage, rollout_stage_started_at, rollout_soak_seconds, rollout_halted_reason FROM tenants WHERE id = ?",
    )
    .bind(tenant)
    .first<TenantRow>();
  if (!row?.rollout_version) return { active: row?.active_version ?? null, rollout: null };
  return {
    active: row.active_version,
    rollout: {
      version: row.rollout_version,
      stage: row.rollout_stage ?? 0,
      stageStartedAt: row.rollout_stage_started_at!,
      soakSeconds: row.rollout_soak_seconds ?? DEFAULT_SOAK_SECONDS,
      haltedReason: row.rollout_halted_reason,
    },
  };
}

export async function liveAgents(db: D1Database, tenant: string, now: Date): Promise<AgentRow[]> {
  const since = new Date(now.getTime() - LIVE_MINUTES * 60_000).toISOString();
  const { results } = await db
    .prepare(
      "SELECT instance, policy_version, window_reported_at, window_egress, window_dlq, window_canary_leaks FROM agents WHERE tenant_id = ? AND last_seen_at >= ? LIMIT 5000",
    )
    .bind(tenant, since)
    .all<AgentRow>();
  return results;
}

const cohortSize = (stage: number, live: number): number =>
  stage === 0 ? Math.min(1, live) : Math.max(1, Math.ceil(live / 10));

/** The connectors a stage covers, by name. */
export async function cohort(tenant: string, rollout: Rollout, live: AgentRow[]): Promise<string[]> {
  const ranked = await Promise.all(
    live.map(async (a) => ({ instance: a.instance, rank: await sha256Hex(`${tenant}:${rollout.version}:${a.instance}`) })),
  );
  ranked.sort((x, y) => (x.rank < y.rank ? -1 : x.rank > y.rank ? 1 : 0));
  return ranked.slice(0, cohortSize(rollout.stage, live.length)).map((r) => r.instance);
}

/**
 * The version to serve as "active" to one connector: the rollout's version
 * if it is in the current cohort, otherwise the tenant's active version. A
 * connector is never served less than it already runs (it would refuse it).
 */
export async function servedVersion(db: D1Database, tenant: string, instance: string | null, now: Date): Promise<number | null> {
  const { active, rollout } = await tenantState(db, tenant);
  let version = active;
  let running: number | null = null;
  if (instance) {
    const row = await db
      .prepare("SELECT policy_version FROM agents WHERE tenant_id = ? AND instance = ?")
      .bind(tenant, instance)
      .first<{ policy_version: number | null }>();
    running = row?.policy_version ?? null;
  }
  if (rollout && !rollout.haltedReason && instance) {
    const members = await cohort(tenant, rollout, await liveAgents(db, tenant, now));
    if (members.includes(instance)) version = Math.max(version ?? 0, rollout.version);
  }
  if (running !== null && running > (version ?? 0)) {
    // Only if that version exists for this tenant (an agent reports its own).
    const known = await db
      .prepare("SELECT 1 AS ok FROM policies WHERE tenant_id = ? AND version = ?")
      .bind(tenant, running)
      .first();
    if (known) version = running;
  }
  return version;
}

/**
 * Judges one reported window against the rollout. Returns the reason to
 * halt, or null. Called with the window just recorded for `agent`.
 */
export function healthProblem(
  rollout: Rollout,
  agent: AgentRow,
  fleet: AgentRow[],
): string | null {
  if (agent.policy_version !== rollout.version) return null;
  if ((agent.window_canary_leaks ?? 0) > 0)
    return `leak canary failed on ${agent.instance} under version ${rollout.version}`;
  const total = (agent.window_egress ?? 0) + (agent.window_dlq ?? 0);
  if (total < MIN_RECORDS) return null;
  const rate = (agent.window_dlq ?? 0) / total;
  let baseDlq = 0;
  let baseTotal = 0;
  for (const other of fleet) {
    if (other.policy_version === null || other.policy_version >= rollout.version) continue;
    baseDlq += other.window_dlq ?? 0;
    baseTotal += (other.window_egress ?? 0) + (other.window_dlq ?? 0);
  }
  const baseline = baseTotal >= MIN_RECORDS ? baseDlq / baseTotal : 0;
  if (rate > baseline + DLQ_MARGIN)
    return `DLQ rate ${(rate * 100).toFixed(1)}% on ${agent.instance} under version ${rollout.version}, fleet ${(baseline * 100).toFixed(1)}%`;
  return null;
}

export async function halt(db: D1Database, tenant: string, version: number, reason: string): Promise<void> {
  await db
    .prepare(
      "UPDATE tenants SET rollout_halted_reason = ? WHERE id = ? AND rollout_version = ? AND rollout_halted_reason IS NULL",
    )
    .bind(reason, tenant, version)
    .run();
}

/**
 * Moves the rollout on if its current stage is done. After the last stage
 * the version becomes the tenant's active version and the rollout ends.
 */
export async function advance(db: D1Database, tenant: string, now: Date): Promise<void> {
  const { rollout } = await tenantState(db, tenant);
  if (!rollout || rollout.haltedReason) return;
  if (now.getTime() - Date.parse(rollout.stageStartedAt) < rollout.soakSeconds * 1000) return;
  const live = await liveAgents(db, tenant, now);
  const members = new Set(await cohort(tenant, rollout, live));
  if (members.size === 0) return; // nobody to judge it on yet
  const done = live
    .filter((a) => members.has(a.instance))
    .every((a) => a.policy_version === rollout.version && a.window_reported_at !== null && a.window_reported_at > rollout.stageStartedAt);
  if (!done) return;
  if (rollout.stage + 1 < STAGES.length) {
    await db
      .prepare(
        "UPDATE tenants SET rollout_stage = ?, rollout_stage_started_at = ? WHERE id = ? AND rollout_version = ? AND rollout_stage = ? AND rollout_halted_reason IS NULL",
      )
      .bind(rollout.stage + 1, now.toISOString(), tenant, rollout.version, rollout.stage)
      .run();
  } else {
    await db
      .prepare(
        `UPDATE tenants
            SET active_version = rollout_version,
                candidate_version = CASE WHEN candidate_version <= rollout_version THEN NULL ELSE candidate_version END,
                rollout_version = NULL, rollout_stage = NULL, rollout_stage_started_at = NULL,
                rollout_soak_seconds = NULL, rollout_halted_reason = NULL
          WHERE id = ? AND rollout_version = ? AND rollout_stage = ? AND rollout_halted_reason IS NULL`,
      )
      .bind(tenant, rollout.version, rollout.stage)
      .run();
  }
}
