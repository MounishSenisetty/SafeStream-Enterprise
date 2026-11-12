// SafeStream console. Talks only to /console/api on its own origin; the
// person is identified by Cloudflare Access, never by a token in the page.
// Everything shown is built with textContent: nothing from the API is ever
// parsed as HTML.

const state = { me: null, tenant: null, tab: "fleet" };
const LIVE_MS = 3 * 60_000; // a connector reports once a minute by default

// ---------------------------------------------------------------- helpers

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const fmt = (n) => (n === null || n === undefined ? "–" : Number(n).toLocaleString());
const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};
const isAdmin = () => state.tenant?.role === "admin";

function notice(text, error = false) {
  const el = document.getElementById("notice");
  el.textContent = text;
  el.className = error ? "error" : "";
  el.hidden = !text;
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { accept: "application/json" };
  if (state.tenant) headers["x-safestream-tenant"] = state.tenant.id;
  if (method !== "GET") {
    headers["content-type"] = "application/json";
    headers["x-safestream-console"] = "1"; // proves the change comes from this page
  }
  const response = await fetch(`/console/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!response.ok) throw new Error((data && data.message) || `HTTP ${response.status}`);
  return data;
}

/** Run a change, report the outcome, and redraw. */
async function change(label, fn) {
  try {
    const result = await fn();
    notice(label);
    await render();
    return result;
  } catch (err) {
    notice(`${label} failed: ${err.message}`, true);
    return null;
  }
}

const table = (headings, rows, numeric = []) =>
  h(
    "div",
    { class: "scroll" },
    h(
      "table",
      {},
      h("thead", {}, h("tr", {}, headings.map((t, i) => h("th", { class: numeric.includes(i) ? "num" : null }, t)))),
      h(
        "tbody",
        {},
        rows.length
          ? rows.map((r) => h("tr", {}, r.map((c, i) => h("td", { class: numeric.includes(i) ? "num" : null }, c))))
          : h("tr", {}, h("td", { colspan: headings.length, class: "hint" }, "Nothing yet.")),
      ),
    ),
  );

const tile = (value, label) => h("div", { class: "tile" }, h("b", {}, value), h("span", {}, label));

// ---------------------------------------------------------------- fleet

function health(agent) {
  if ((agent.canary_leaks ?? 0) > 0) return h("span", { class: "badge bad" }, "canary leak");
  if (Date.now() - Date.parse(agent.last_seen_at) > LIVE_MS) return h("span", { class: "badge warn" }, "silent");
  const total = (agent.egress_records ?? 0) + (agent.dlq_records ?? 0);
  if (total >= 100 && (agent.dlq_records ?? 0) / total > 0.01) return h("span", { class: "badge warn" }, "dead-lettering");
  return h("span", { class: "badge ok" }, "healthy");
}

async function fleetView() {
  const [{ agents }, policies] = await Promise.all([api("/agents"), api("/policies")]);
  const live = agents.filter((a) => Date.now() - Date.parse(a.last_seen_at) <= LIVE_MS);
  const leaks = agents.reduce((n, a) => n + (a.canary_leaks ?? 0), 0);
  return [
    h("h2", {}, "Fleet"),
    h("p", { class: "hint" }, "Each connector reports one audit window a minute: counts only, never record content."),
    h(
      "div",
      { class: "tiles" },
      tile(fmt(live.length), "connectors reporting"),
      tile(fmt(agents.length - live.length), "silent for 3+ minutes"),
      tile(policies.active_version ?? "none", "active policy version"),
      tile(policies.candidate_version ?? "none", "candidate in shadow"),
      tile(fmt(leaks), "canary leaks, last windows"),
    ),
    table(
      ["Connector", "Health", "Version", "Policy", "Shadow", "Egress", "DLQ", "Canaries", "Last report"],
      agents.map((a) => [
        h("code", {}, a.instance),
        health(a),
        a.connector_version,
        a.policy_version ?? "unsigned",
        a.shadow_version ?? "–",
        fmt(a.egress_records),
        fmt(a.dlq_records),
        a.canary_checks === null ? "off" : `${fmt(a.canary_leaks)} / ${fmt(a.canary_checks)}`,
        ago(a.last_seen_at),
      ]),
      [5, 6],
    ),
  ];
}

// ---------------------------------------------------------------- policies

function ruleDiff(before, after) {
  const a = (before && before.rules) || {};
  const b = (after && after.rules) || {};
  const rows = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (!(k in a)) rows.push([h("span", { class: "plus" }, "added"), h("code", {}, k), b[k]]);
    else if (!(k in b)) rows.push([h("span", { class: "minus" }, "removed"), h("code", {}, k), a[k]]);
    else if (a[k] !== b[k]) rows.push(["changed", h("code", {}, k), `${a[k]} → ${b[k]}`]);
  }
  const modeA = (before && before.mode) || "extend";
  const modeB = (after && after.mode) || "extend";
  if (modeA !== modeB) rows.unshift(["changed", "mode", `${modeA} → ${modeB}`]);
  const disA = JSON.stringify((before && before.disable) || []);
  const disB = JSON.stringify((after && after.disable) || []);
  if (disA !== disB) rows.push(["changed", "disable", `${disA} → ${disB}`]);
  return rows;
}

async function shadowPanel() {
  const s = await api("/shadow");
  if (!s.candidate_version) return [h("h2", {}, "Shadow evaluation"), h("p", { class: "hint" }, "No candidate is being evaluated.")];
  return [
    h("h2", {}, `Shadow evaluation of version ${s.candidate_version}`),
    h(
      "p",
      { class: "hint" },
      `What promoting it would change, measured on live records by ${s.agents.length} connector(s) and reported as counts. ` +
        "Nothing the candidate produces is ever published.",
    ),
    h(
      "div",
      { class: "tiles" },
      tile(fmt(s.records), "records compared"),
      tile(fmt(s.changed_records), "would be redacted differently"),
      tile(fmt(s.errors), "candidate errors"),
    ),
    table(
      ["Entity type", `Version ${s.active_version ?? "in force"}`, `Version ${s.candidate_version}`, "Change"],
      s.entities.map((e) => [
        e.entity,
        fmt(e.active),
        fmt(e.candidate),
        h("span", { class: e.delta > 0 ? "plus" : e.delta < 0 ? "minus" : null }, e.delta > 0 ? `+${fmt(e.delta)}` : fmt(e.delta)),
      ]),
      [1, 2, 3],
    ),
  ];
}

async function policiesView() {
  const list = await api("/policies");
  const versions = list.policies;
  const active = list.active_version ? await api(`/policies/${list.active_version}`) : null;
  const latest = versions.length ? await api(`/policies/${versions[0].version}`) : null;
  const parts = [h("h2", {}, "Policies")];
  parts.push(
    table(
      ["Version", "State", "Rules", "Published", "Digest"],
      versions.map((p) => [
        p.version,
        p.version === list.active_version
          ? h("span", { class: "badge ok" }, "active")
          : p.version === list.candidate_version
            ? h("span", { class: "badge warn" }, "candidate")
            : list.rollout && p.version === list.rollout.version
              ? h("span", { class: "badge warn" }, "rolling out")
              : "",
        p.rules,
        ago(p.created_at),
        h("code", {}, p.digest.slice(0, 19) + "…"),
      ]),
      [2],
    ),
  );
  if (latest && active && latest.version !== active.version) {
    const rows = ruleDiff(active.field_rules, latest.field_rules);
    parts.push(h("h2", {}, `Version ${latest.version} against version ${active.version} in force`));
    parts.push(rows.length ? table(["", "Field pattern", "Entity type"], rows) : h("p", { class: "hint" }, "No rule differences."));
  }
  parts.push(...(await shadowPanel()));

  parts.push(h("h2", {}, "Publish a new version"));
  const editor = h("textarea", { id: "rules", spellcheck: "false", "aria-label": "Field rules JSON", disabled: !isAdmin() });
  editor.value = JSON.stringify((latest && latest.field_rules) || { mode: "extend", rules: {}, disable: [] }, null, 2);
  parts.push(
    h(
      "p",
      { class: "hint" },
      "The field rules document (as in a rules file). It is signed as the next version and offered to connectors as the ",
      "candidate: they evaluate it in shadow, and nothing changes until it is promoted on the Rollout tab.",
    ),
    editor,
    h(
      "div",
      { class: "row" },
      h(
        "button",
        {
          class: "act",
          type: "button",
          id: "publish",
          disabled: !isAdmin(),
          onclick: () => {
            let rules;
            try {
              rules = JSON.parse(editor.value);
            } catch (err) {
              notice(`Not valid JSON: ${err.message}`, true);
              return;
            }
            change("Published as the candidate", () => api("/policies", { method: "POST", body: { field_rules: rules } }));
          },
        },
        "Sign and publish as candidate",
      ),
      isAdmin() ? null : h("span", { class: "hint" }, "Viewers cannot publish."),
    ),
  );
  return parts;
}

// ---------------------------------------------------------------- rollout

async function rolloutView() {
  const [{ active_version, rollout }, list] = await Promise.all([api("/rollout"), api("/policies")]);
  const parts = [h("h2", {}, "Rollout"), h("div", { class: "tiles" }, tile(active_version ?? "none", "active version"))];
  if (rollout) {
    parts.push(
      h(
        "div",
        { class: "tiles" },
        tile(rollout.version, "rolling out"),
        tile(rollout.stage === "first_agent" ? "1 connector" : "10% of fleet", "current stage"),
        tile(`${fmt(rollout.on_version)} / ${fmt(rollout.live_agents)}`, "connectors on it"),
        tile(rollout.halted ? "halted" : "progressing", "state"),
      ),
    );
    if (rollout.halted) parts.push(h("p", { class: "badge bad", id: "halt-reason" }, `Halted: ${rollout.halted_reason}`));
    parts.push(
      h("p", { class: "hint" }, `Stage started ${ago(rollout.stage_started_at)}; soak ${rollout.soak_seconds}s. Connectors in this stage:`),
      h("pre", {}, rollout.cohort.join("\n") || "(none reporting yet)"),
      h(
        "div",
        { class: "row" },
        rollout.halted
          ? h(
              "button",
              { class: "act", type: "button", disabled: !isAdmin(), onclick: () => change("Rollout resumed", () => api("/rollout/resume", { method: "POST" })) },
              "Resume (stage starts over)",
            )
          : null,
        h(
          "button",
          { class: "act danger", type: "button", disabled: !isAdmin(), onclick: () => change("Rollout aborted", () => api("/rollout/abort", { method: "POST" })) },
          "Abort",
        ),
      ),
      h("p", { class: "hint" }, "Aborting stops the version spreading. Connectors that already run it keep it: none accepts an older policy. Fix a bad version with a newer one."),
    );
  }
  const candidate = list.candidate_version;
  if (candidate && (!rollout || candidate > rollout.version)) {
    const soak = h("input", { type: "number", min: "0", max: "604800", value: "600", id: "soak", "aria-label": "Soak seconds", disabled: !isAdmin() });
    parts.push(
      h("h2", {}, `Candidate version ${candidate}`),
      h("p", { class: "hint" }, "Staged: one connector, then a tenth of the fleet, then everyone. Halts by itself on a leak canary or a DLQ rate above the fleet's."),
      h(
        "div",
        { class: "row" },
        h("label", { for: "soak" }, "Soak per stage (seconds)"),
        soak,
        h(
          "button",
          {
            class: "act",
            type: "button",
            id: "promote",
            disabled: !isAdmin(),
            onclick: () => change(`Rollout of version ${candidate} started`, () => api(`/policies/${candidate}/promote`, { method: "POST", body: { soak_seconds: Number(soak.value) } })),
          },
          "Start staged rollout",
        ),
        h(
          "button",
          {
            class: "act secondary",
            type: "button",
            disabled: !isAdmin(),
            onclick: () => {
              if (confirm(`Promote version ${candidate} to every connector at once?`))
                change(`Version ${candidate} is active`, () => api(`/policies/${candidate}/promote`, { method: "POST", body: { strategy: "immediate" } }));
            },
          },
          "Promote to everyone now",
        ),
        h(
          "button",
          { class: "act danger", type: "button", disabled: !isAdmin(), onclick: () => change("Candidate withdrawn", () => api("/policies/candidate/withdraw", { method: "POST" })) },
          "Withdraw candidate",
        ),
      ),
    );
  } else if (!rollout) parts.push(h("p", { class: "hint" }, "Nothing to roll out: publish a version on the Policies tab first."));
  return parts;
}

// ---------------------------------------------------------------- evidence

async function download(chain) {
  try {
    const headers = state.tenant ? { "x-safestream-tenant": state.tenant.id } : {};
    const response = await fetch(`/console/api/chains/${encodeURIComponent(chain.chain)}/events`, { headers, credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const url = URL.createObjectURL(await response.blob());
    const a = h("a", { href: url, download: `${chain.chain}.ndjson` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    notice(`Exported ${chain.chain}.ndjson`);
  } catch (err) {
    notice(`Export failed: ${err.message}`, true);
  }
}

async function evidenceView() {
  const { chains } = await api("/chains");
  return [
    h("h2", {}, "Audit evidence"),
    h(
      "p",
      { class: "hint" },
      "Every connector run is one hash chain of content-free audit events. Its head is anchored here, outside your own audit store. ",
      "Export a chain and verify it offline: any altered, removed or reordered event, or a rewritten chain, fails.",
    ),
    table(
      ["Chain", "Connector", "Events", "State", "Anchored head", ""],
      chains.map((c) => [
        h("code", {}, c.chain),
        h("code", {}, c.instance),
        fmt(c.events),
        c.broken ? h("span", { class: "badge bad" }, "broken") : c.closed ? h("span", { class: "badge ok" }, "closed") : h("span", { class: "badge" }, "open"),
        h("code", { class: "secret" }, c.head),
        h("button", { class: "act secondary", type: "button", "data-chain": c.chain, onclick: () => download(c) }, "Export"),
      ]),
      [2],
    ),
    h("p", { class: "hint" }, "Then, with the connector package installed:"),
    h(
      "pre",
      { id: "verify-command" },
      chains.length
        ? `safestream-audit verify ${chains[0].chain}.ndjson --head ${chains[0].chain}=${chains[0].head}${chains[0].closed ? " --require-closed" : ""}`
        : "safestream-audit verify <chain>.ndjson --head <chain>=<anchored head>",
    ),
  ];
}

// ---------------------------------------------------------------- access

async function accessView() {
  const [{ users }, { tokens }] = await Promise.all([api("/console-users"), api("/tokens")]);
  const email = h("input", { type: "email", id: "grant-email", placeholder: "person@company.example", "aria-label": "Email", disabled: !isAdmin() });
  const role = h("select", { id: "grant-role", "aria-label": "Role", disabled: !isAdmin() }, h("option", { value: "viewer" }, "viewer"), h("option", { value: "admin" }, "admin"));
  const label = h("input", { type: "text", id: "token-label", placeholder: "prod-eu-1", maxlength: "64", "aria-label": "Token label", disabled: !isAdmin() });
  const issued = h("div", { id: "issued" });
  return [
    h("h2", {}, "Console users"),
    h("p", { class: "hint" }, "People Cloudflare Access lets in still see nothing until they are given a role here. Viewers read; admins also publish, roll out and manage access."),
    table(
      ["Email", "Role", "Since", ""],
      users.map((u) => [
        u.email,
        u.role,
        ago(u.created_at),
        h(
          "button",
          { class: "act danger", type: "button", disabled: !isAdmin(), onclick: () => change(`Removed ${u.email}`, () => api("/console-users/remove", { method: "POST", body: { email: u.email } })) },
          "Remove",
        ),
      ]),
    ),
    h(
      "div",
      { class: "row" },
      email,
      role,
      h(
        "button",
        { class: "act", type: "button", id: "grant", disabled: !isAdmin(), onclick: () => change(`Granted ${email.value}`, () => api("/console-users", { method: "POST", body: { email: email.value, role: role.value } })) },
        "Grant",
      ),
    ),
    h("h2", {}, "Connector tokens"),
    h("p", { class: "hint" }, "One token per connector deployment (SAFESTREAM_CONTROL_TOKEN). A token is shown once, when it is issued."),
    table(
      ["Id", "Kind", "Label", "Issued", "State", ""],
      tokens.map((t) => [
        h("code", {}, t.id),
        t.kind,
        t.label,
        ago(t.created_at),
        t.revoked_at ? h("span", { class: "badge bad" }, "revoked") : h("span", { class: "badge ok" }, "active"),
        t.revoked_at || t.kind !== "agent"
          ? ""
          : h(
              "button",
              {
                class: "act danger",
                type: "button",
                disabled: !isAdmin(),
                onclick: () => {
                  if (confirm(`Revoke ${t.label}? Its connectors lose the control plane at once.`))
                    change(`Revoked ${t.label}`, () => api(`/tokens/${t.id}/revoke`, { method: "POST" }));
                },
              },
              "Revoke",
            ),
      ]),
    ),
    h(
      "div",
      { class: "row" },
      label,
      h(
        "button",
        {
          class: "act",
          type: "button",
          id: "issue",
          disabled: !isAdmin(),
          onclick: async () => {
            try {
              const t = await api("/agent-tokens", { method: "POST", body: { label: label.value } });
              notice(`Issued a token for ${t.label}. Copy it now: it is not shown again.`);
              issued.replaceChildren(
                h("pre", { class: "secret" }, `SAFESTREAM_CONTROL_TOKEN=${t.token}\nSAFESTREAM_POLICY_PUBLIC_KEYS=${t.public_key}\nSAFESTREAM_POLICY_TENANT=${t.tenant}`),
              );
            } catch (err) {
              notice(`Issuing failed: ${err.message}`, true);
            }
          },
        },
        "Issue connector token",
      ),
    ),
    issued,
  ];
}

// ---------------------------------------------------------------- shell

const VIEWS = { fleet: fleetView, policies: policiesView, rollout: rolloutView, evidence: evidenceView, access: accessView };

async function render() {
  const view = document.getElementById("view");
  try {
    view.replaceChildren(...(await VIEWS[state.tab]()));
  } catch (err) {
    view.replaceChildren(h("p", { class: "hint" }, `Could not load: ${err.message}`));
  }
}

function selectTab(tab) {
  state.tab = VIEWS[tab] ? tab : "fleet";
  for (const b of document.querySelectorAll("#tabs button")) {
    if (b.dataset.tab === state.tab) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  history.replaceState(null, "", `#${state.tab}`);
  notice("");
  return render();
}

async function start() {
  try {
    state.me = await api("/me");
  } catch (err) {
    document.getElementById("view").replaceChildren(h("p", {}, err.message));
    return;
  }
  document.getElementById("email").textContent = state.me.email;
  const picker = document.getElementById("tenant");
  state.tenant = state.me.tenant || state.me.tenants[0];
  if (state.me.tenants.length > 1) {
    picker.replaceChildren(...state.me.tenants.map((t) => h("option", { value: t.id, selected: t.id === state.tenant.id }, t.name)));
    picker.hidden = false;
    picker.addEventListener("change", () => {
      state.tenant = state.me.tenants.find((t) => t.id === picker.value);
      document.getElementById("role").textContent = state.tenant.role;
      render();
    });
  }
  document.getElementById("role").textContent = state.tenant.role;
  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => selectTab(b.dataset.tab));
  await selectTab(location.hash.slice(1) || "fleet");
}

start();
