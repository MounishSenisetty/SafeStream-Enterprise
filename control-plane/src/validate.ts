// Input validation. Two jobs: keep malformed policies out, and enforce the
// control plane's one hard rule: telemetry carries counts, names, versions
// and hashes, and nothing that could be record content.

export class Invalid extends Error {}

type Json = Record<string, unknown>;

const fail = (path: string, why: string): never => {
  throw new Invalid(`${path}: ${why}`);
};

function object(value: unknown, path: string, allowed: readonly string[]): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(path, "must be an object");
  const obj = value as Json;
  // An unknown field is refused rather than ignored: it is where free text
  // (and so record content) would slip in.
  for (const key of Object.keys(obj)) if (!allowed.includes(key)) fail(`${path}.${key}`, "unknown field");
  return obj;
}

function text(value: unknown, path: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) fail(path, "has an invalid value");
  return value as string;
}

function count(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail(path, "must be a non-negative integer");
  return value as number;
}

const oneOf = <T extends string>(value: unknown, path: string, options: readonly T[]): T =>
  options.includes(value as T) ? (value as T) : fail(path, `must be one of ${options.join(", ")}`);

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/; // hostnames, topics, consumer groups, chain ids
const ENTITY = /^[a-z][a-z0-9_]{0,39}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const KEY_ID = /^[0-9a-f]{16}$/;
const VERSION = /^[0-9A-Za-z.+-]{1,32}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/;
export const TENANT = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;

function entityCounts(value: unknown, path: string): Record<string, number> {
  const obj = object(value, path, Object.keys((value ?? {}) as Json));
  for (const [entity, n] of Object.entries(obj)) {
    text(entity, `${path} key`, ENTITY);
    count(n, `${path}.${entity}`);
  }
  return obj as Record<string, number>;
}

function policyRef(value: unknown, path: string): { tenant: string; version: number } {
  const p = object(value, path, ["tenant", "version", "key_id"]);
  text(p.key_id, `${path}.key_id`, KEY_ID);
  return { tenant: text(p.tenant, `${path}.tenant`, TENANT), version: count(p.version, `${path}.version`) };
}

export interface AuditEvent {
  instance: string;
  connectorVersion: string;
  policyVersion: number | null;
  shadowVersion: number | null;
  chain: { id: string; seq: number; prev: string | null };
  final: boolean;
}

/** Checks a `safestream.audit/v2` event field by field. Throws {@link Invalid}. */
export function auditEvent(value: unknown, tenant: string): AuditEvent {
  const e = object(value, "event", [
    "schema", "connector_version", "instance", "group_id", "topics", "delivery", "redaction_mode",
    "field_rules", "policy", "shadow", "chain", "window", "records", "redactions", "batches",
    "transaction_aborts",
  ]);
  if (e.schema !== "safestream.audit/v2") fail("event.schema", "must be safestream.audit/v2");
  text(e.group_id, "event.group_id", NAME);
  const topics = object(e.topics, "event.topics", ["ingress", "egress", "dlq"]);
  for (const t of ["ingress", "egress", "dlq"]) text(topics[t], `event.topics.${t}`, NAME);
  oneOf(e.delivery, "event.delivery", ["at_least_once", "exactly_once"]);
  oneOf(e.redaction_mode, "event.redaction_mode", ["replace", "mask", "pseudonymize"]);
  const rules = object(e.field_rules, "event.field_rules", ["count", "fingerprint"]);
  if (rules.count !== null) count(rules.count, "event.field_rules.count");
  if (rules.fingerprint !== null) text(rules.fingerprint, "event.field_rules.fingerprint", HASH);

  let policyVersion: number | null = null;
  if (e.policy !== null) {
    const ref = policyRef(e.policy, "event.policy");
    if (ref.tenant !== tenant) fail("event.policy.tenant", "is not this token's tenant");
    policyVersion = ref.version;
  }
  let shadowVersion: number | null = null;
  if (e.shadow !== null) {
    const s = object(e.shadow, "event.shadow", [
      "candidate", "since", "records", "changed_records", "errors", "redactions",
    ]);
    shadowVersion = policyRef(s.candidate, "event.shadow.candidate").version;
    text(s.since, "event.shadow.since", TIME);
    for (const k of ["records", "changed_records", "errors"]) count(s[k], `event.shadow.${k}`);
    const r = object(s.redactions, "event.shadow.redactions", ["active", "candidate"]);
    entityCounts(r.active, "event.shadow.redactions.active");
    entityCounts(r.candidate, "event.shadow.redactions.candidate");
  }

  const chain = object(e.chain, "event.chain", ["id", "seq", "prev"]);
  const window = object(e.window, "event.window", ["start", "end", "final"]);
  text(window.start, "event.window.start", TIME);
  text(window.end, "event.window.end", TIME);
  if (typeof window.final !== "boolean") fail("event.window.final", "must be true or false");
  const records = object(e.records, "event.records", ["egress", "dlq"]);
  count(records.egress, "event.records.egress");
  count(records.dlq, "event.records.dlq");
  entityCounts(e.redactions, "event.redactions");
  count(e.batches, "event.batches");
  count(e.transaction_aborts, "event.transaction_aborts");

  return {
    instance: text(e.instance, "event.instance", NAME),
    connectorVersion: text(e.connector_version, "event.connector_version", VERSION),
    policyVersion,
    shadowVersion,
    chain: {
      id: text(chain.id, "event.chain.id", NAME),
      seq: count(chain.seq, "event.chain.seq"),
      prev: chain.prev === null ? null : text(chain.prev, "event.chain.prev", HASH),
    },
    final: window.final as boolean,
  };
}

/**
 * Structural check of a field-rules document. The connector makes the full
 * check (entity types, regular expressions) and refuses a bundle that fails
 * it, so a mistake here costs a rejected candidate, never weaker redaction.
 */
export function fieldRules(value: unknown): { ruleCount: number } {
  const doc = object(value, "field_rules", ["mode", "rules", "disable"]);
  if (doc.mode !== undefined) oneOf(doc.mode, "field_rules.mode", ["extend", "replace"]);
  const rules = (doc.rules ?? {}) as Json;
  if (typeof rules !== "object" || rules === null || Array.isArray(rules)) fail("field_rules.rules", "must be an object");
  const entries = Object.entries(rules);
  if (entries.length > 1000) fail("field_rules.rules", "has more than 1000 rules");
  for (const [pattern, entity] of entries) {
    if (!pattern.trim() || pattern.length > 200) fail("field_rules.rules", "has an empty or over-long pattern");
    text(entity, "field_rules.rules value", ENTITY);
  }
  if (doc.disable !== undefined) {
    if (!Array.isArray(doc.disable) || doc.disable.some((d) => typeof d !== "string" || d.length > 200))
      fail("field_rules.disable", "must be a list of patterns");
  }
  if (doc.mode === "replace" && entries.length === 0) fail("field_rules.rules", "mode replace needs at least one rule");
  return { ruleCount: entries.length };
}

export { text as string_, object as object_ };
