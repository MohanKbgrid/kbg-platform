// Sentinel console. Plain JavaScript, no build step, no external requests.
const $app = document.getElementById("app");
if (location.hash.startsWith("#sso=")) {            // back from single sign-on
  sessionStorage.setItem("sentinel_token", decodeURIComponent(location.hash.slice(5)));
  history.replaceState(null, "", location.pathname + "#/overview");
}
const S = {
  token: sessionStorage.getItem("sentinel_token") || "",
  me: null, catalogue: null,
  pending: { registry: null, people: null, connectors: null },     // structured docs edited locally, not yet saved
  changes: { registry: [], people: [], connectors: [] },          // human-readable list of local changes
};

// ---------------------------------------------------------------- helpers
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") el.innerHTML = v;
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const clone = (x) => JSON.parse(JSON.stringify(x ?? null));
const pct = (x) => (x === null || x === undefined ? "–" : `${Math.round(x * 100)}%`);
const when = (t) => {
  if (!t) return "–";
  const d = typeof t === "number" ? new Date(t * 1000) : new Date(t);
  return d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};
const canConfigure = () => !!(S.me && (S.me.open_mode || (S.me.can || {}).__configure__));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers: { Authorization: `Bearer ${S.token}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (res.status === 401) { signOut(); throw new Error("Signed out: the token was not accepted"); }
  if (!res.ok) {
    const err = new Error(typeof data?.detail === "string" ? data.detail : `Request failed (${res.status})`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

function toast(msg, bad = false) {
  document.querySelectorAll(".toast").forEach((x) => x.remove());
  const t = h("div", { class: `toast ${bad ? "bad" : ""}`, role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), bad ? 6000 : 3200);
}

function badgeRoute(r) {
  return h("span", { class: `badge b-${r}` }, { auto: "automatic", llm: "model", hitl: "person" }[r] || r);
}
function statusBadge(s) {
  const cls = { published: "b-ok", draft: "b-warn", superseded: "b-plain", ok: "b-ok", degraded: "b-warn", down: "b-bad" }[s] || "b-plain";
  return h("span", { class: `badge ${cls}` }, s);
}

function problemsList(probs) {
  if (!probs || !probs.length) return h("div", { class: "badge b-ok" }, "No problems found");
  const errs = probs.filter((p) => p.severity === "error").length;
  return h("div", {},
    h("div", { class: "small muted", style: "margin-bottom:6px" },
      `${errs} error${errs === 1 ? "" : "s"} · ${probs.length - errs} warning${probs.length - errs === 1 ? "" : "s"}`,
      errs ? " — errors block publishing" : " — warnings do not block publishing"),
    h("ul", { class: "problems" }, probs.map((p) => h("li", { class: p.severity }, p.message))));
}

function diffView(text) {
  if (!text) return h("div", { class: "small muted" }, "No differences from what is running now.");
  const el = h("div", { class: "diff" });
  for (const line of text.split("\n")) {
    const cls = line.startsWith("+++") || line.startsWith("---") ? "hunk" : line.startsWith("+") ? "add"
      : line.startsWith("-") ? "del" : line.startsWith("@@") ? "hunk" : "";
    el.append(cls ? h("span", { class: cls }, line) : document.createTextNode(line + "\n"));
  }
  return el;
}

function modal(title, body, buttons = []) {
  const close = () => { scrim.remove(); box.remove(); };
  const scrim = h("div", { class: "scrim", onclick: close });
  const box = h("div", { class: "modal", role: "dialog", "aria-label": title },
    h("header", {}, h("h2", { style: "margin:0" }, title), h("span", { class: "spacer" }),
      h("button", { class: "ghost", onclick: close, "aria-label": "Close" }, "✕")),
    h("div", { class: "body" }, body),
    buttons.length ? h("footer", {}, buttons.map((b) => (typeof b === "function" ? b(close) : b))) : null);
  document.body.append(scrim, box);
  return close;
}
// a drawer belongs to the page it was opened on: going to another page, or Escape, closes it
function closeDrawers() { document.querySelectorAll("aside.drawer, .drawer-scrim").forEach((x) => x.remove()); }
window.addEventListener("hashchange", closeDrawers);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && document.querySelector("aside.drawer")) closeDrawers(); });

function drawer(title, body, footer) {
  const close = () => { scrim.remove(); box.remove(); };
  const scrim = h("div", { class: "scrim drawer-scrim", onclick: close });
  const box = h("aside", { class: "drawer", role: "dialog", "aria-label": title },
    h("header", {}, h("h2", { style: "margin:0" }, title), h("span", { class: "spacer" }),
      h("button", { class: "ghost", onclick: close, "aria-label": "Close" }, "✕")),
    h("div", { class: "body" }, body), footer ? h("footer", {}, footer(close)) : null);
  document.body.append(scrim, box);
  return close;
}

function field(labelText, input, help) {
  return h("div", { class: "field" }, h("label", {}, labelText), input, help ? h("div", { class: "help" }, help) : null);
}
function select(options, value, onchange, props = {}) {
  return h("select", { onchange: (e) => onchange(e.target.value), ...props },
    options.map((o) => {
      const [v, label] = Array.isArray(o) ? o : [o, o];
      return h("option", { value: v, selected: v === value ? "selected" : null }, label);
    }));
}
function parseKv(text) {
  const out = {};
  for (const line of String(text || "").split(/[\n,]/)) {
    const m = line.split("=");
    if (m.length < 2 || !m[0].trim()) continue;
    const vals = m.slice(1).join("=").split("|").map((s) => s.trim()).filter(Boolean);
    out[m[0].trim()] = vals.length > 1 ? vals : vals[0] ?? "";
  }
  return out;
}
const kvText = (o) => Object.entries(o || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join("\n");

// ---------------------------------------------------------------- pending changes (structured edits)
async function pendingDoc(kind) {
  if (!S.pending[kind]) S.pending[kind] = await api(`/console/api/config/${kind}/doc`);
  return S.pending[kind];
}
function recordChange(kind, what) {
  S.changes[kind].push(what);
  renderPendingBar();
}
function discard(kind) {
  S.pending[kind] = null; S.changes[kind] = [];
  renderPendingBar();
}
function renderPendingBar() {
  document.querySelector(".pending")?.remove();
  const kinds = Object.keys(S.changes).filter((k) => S.changes[k].length);
  if (!kinds.length) return;
  const n = kinds.reduce((a, k) => a + S.changes[k].length, 0);
  const names = kinds.map((k) => ({ registry: "exceptions", people: "people & roles", connectors: "connectors" }[k])).join(" and ");
  document.body.append(h("div", { class: "pending" }, h("span", { class: "dot" }),
    h("span", {}, h("b", {}, `${n} unsaved change${n === 1 ? "" : "s"}`), ` to ${names}`),
    h("span", { class: "spacer" }),
    h("button", { onclick: () => { kinds.forEach(discard); route(); } }, "Discard"),
    h("button", { class: "primary", onclick: () => reviewPending(kinds) }, "Review and save")));
}

async function reviewPending(kinds) {
  const items = {};
  for (const k of kinds) items[k] = { doc: S.pending[k] };
  const res = await api("/console/api/config-set/check", { body: { items } });
  const note = h("input", { placeholder: "What changed and why (shown in the history)" });
  const body = h("div", {},
    kinds.map((k) => h("div", { class: "section" },
      h("h3", {}, { registry: "Exceptions", people: "People & roles" }[k]),
      h("ul", { class: "small", style: "margin:0 0 10px;padding-left:18px" }, S.changes[k].map((c) => h("li", {}, c))),
      problemsList(res[k].problems), h("div", { style: "height:10px" }), diffView(res[k].diff))),
    h("div", { class: "section" }, field("Note", note)));
  const hasErrors = kinds.some((k) => res[k].problems.some((p) => p.severity === "error"));
  modal("Review changes", body, [
    (close) => h("button", { onclick: close }, "Keep editing"),
    (close) => h("button", { onclick: async () => { await saveSet(kinds, items, note.value, false); close(); } },
      "Save as draft"),
    (close) => h("button", { class: "primary", disabled: hasErrors || !canConfigure() ? "disabled" : null,
      title: !canConfigure() ? "You need the __configure__ right to publish" : hasErrors ? "Fix the errors first" : "",
      onclick: async () => { if (await saveSet(kinds, items, note.value, true)) close(); } }, "Save and publish"),
  ]);
}

async function saveSet(kinds, items, note, publish) {
  try {
    const saved = await api("/console/api/config-set/drafts", { body: { items, note } });
    const ids = kinds.map((k) => saved[k].version.id);
    if (publish) {
      const res = await api("/console/api/config-set/publish", { body: { version_ids: ids } });
      toast(res.waiting ? "Saved. Publishing waits for approval by someone else who can configure (Changes page)."
        : "Published. Every process picks it up within seconds.");
    } else {
      toast(`Saved as draft (${kinds.map((k) => `${k} v${saved[k].version.version}`).join(", ")})`);
    }
    kinds.forEach(discard);
    route();
    return true;
  } catch (e) {
    showError(e);
    return false;
  }
}

function showError(e) {
  if (e.data?.problems?.length) {
    modal("Not published", h("div", {}, h("p", {}, e.message), problemsList(e.data.problems)),
      [(close) => h("button", { onclick: close }, "Close")]);
  } else toast(e.message, true);
}

// ---------------------------------------------------------------- shell
const NAV = [
  ["Operate", [["overview", "Overview"], ["reviews", "Reviews"], ["capabilities", "Capabilities"], ["metrics", "Metrics"], ["silences", "Silences"], ["cases", "Cases"], ["exceptions", "Exceptions"],
    ["trace", "Trace an event"], ["value", "Value"], ["learning", "Learning"], ["insights", "Insights"], ["activity", "Activity"]]],
  ["Configure", [["setup", "Set up from a template"], ["golive", "Go live"], ["plan", "Plan & usage"], ["privacy", "Privacy"], ["fleet", "Fleet"], ["people", "People & roles"], ["agents", "Agents & oversight"], ["connectors", "Data sources & tools"], ["keys", "Keys"],
    ["models", "Models"], ["access", "Access"], ["changes", "Changes"]]],
];

function shell(page, title, sub, actions, content) {
  const nav = h("nav", { class: "nav" }, NAV.map(([group, items]) => [
    h("div", { class: "group" }, group),
    items.map(([id, label]) => h("a", { href: `#/${id}`, class: page === id ? "active" : null }, label,
      id === "reviews" && S.reviewCount ? h("span", { class: "count" }, S.reviewCount) : null)),
  ]));
  const me = S.me;
  $app.replaceChildren(h("div", { class: "shell" },
    h("aside", { class: "side" },
      h("div", { class: "brand" },
        h("div", { class: "logo", html: '<svg width="16" height="16" viewBox="0 0 32 32"><path d="M8 17l5 5 11-13" stroke="white" stroke-width="3.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>' }),
        h("div", {}, h("b", {}, "Sentinel"), h("small", {}, me?.overlay || ""),
          me?.environment && me.environment !== "unnamed" ? h("span", { class: `env env-${me.environment}` }, me.environment) : null)),
      nav,
      h("div", { class: "me" }, h("div", { class: "who" }, me?.name || ""),
        h("div", { class: "roles" }, me?.open_mode ? "open mode (no people configured)" : (me?.roles || []).join(", ") || "no roles"),
        h("button", { onclick: signOut }, "Sign out"))),
    h("main", { class: "main" },
      h("div", { class: "topbar" }, h("div", {}, h("h1", {}, title), sub ? h("div", { class: "sub" }, sub) : null),
        h("div", { class: "actions" }, actions || [])),
      h("div", { class: "content" }, content))));
  renderPendingBar();
}

function signOut() {
  if (S.token && S.me) fetch("/console/api/logout", { method: "POST", headers: { Authorization: `Bearer ${S.token}` } }).catch(() => {});
  sessionStorage.removeItem("sentinel_token");
  S.token = ""; S.me = null;
  signIn();
}

function signIn(msg) {
  const tok = h("input", { type: "password", placeholder: "Your personal token", autocomplete: "off", id: "token" });
  const go = async () => {
    S.token = tok.value.trim();
    try {
      S.me = await api("/console/api/me");
      sessionStorage.setItem("sentinel_token", S.token);
      location.hash = location.hash || "#/overview";
      route();
    } catch (e) { signIn(e.message.includes("person token") ? "That is a service token; sign in with a person token." : e.message); }
  };
  tok.addEventListener("keydown", (e) => e.key === "Enter" && go());
  $app.replaceChildren(h("div", { class: "card signin" },
    h("div", { class: "row", style: "margin-bottom:14px" },
      h("div", { class: "brand", style: "padding:0" }, h("b", { style: "color:var(--text);font-size:18px" }, "Sentinel console"))),
    h("p", { class: "muted" }, "Sign in with the personal token your administrator gave you. It stays in this browser tab only."),
    msg ? h("ul", { class: "problems" }, h("li", { class: "error" }, msg)) : null,
    h("div", { id: "sso" }),
    field("Token", tok), h("button", { class: "primary", onclick: go, id: "signin" }, "Sign in")));
  tok.focus();
  fetch("/console/sso/info").then((r) => r.json()).then((i) => {
    const slot = document.getElementById("sso");
    if (i.enabled && slot) slot.replaceChildren(h("a", { class: "btn primary", href: "/console/sso/login", id: "sso-login",
      style: "display:block;text-align:center;margin-bottom:14px" }, i.button), h("div", { class: "small faint", style: "text-align:center;margin-bottom:10px" }, "or use a personal token"));
  }).catch(() => {});
}

// ---------------------------------------------------------------- pages
const PAGES = {};
const KIND_LABEL = { registry: "Exceptions", people: "People & roles", connectors: "Data sources & tools", models: "Models", metrics: "Metrics" };

PAGES.overview = async () => {
  const [o, reviews] = await Promise.all([api("/console/api/overview"), api("/console/api/reviews")]);
  S.reviewCount = reviews.length;
  const health = o.health;
  const tiles = h("div", { class: "grid g4" },
    stat("Automation", pct(o.automation_rate), `${o.unattended} of ${o.closed} closed without a person`),
    stat("Waiting for people", reviews.length, `${health.overdue_reviews || 0} past their SLA`),
    stat("Exception patterns", o.patterns, `${o.pending_promotions} promotion${o.pending_promotions === 1 ? "" : "s"} to approve`),
    h("div", { class: "card stat" }, h("div", { class: "label" }, "System"), h("div", { class: "value" }, statusBadge(health.status)),
      h("div", { class: "hint" }, (health.problems || []).join("; ") || `queue ${Object.entries(health.queue?.counts || {}).map(([k, v]) => `${k} ${v}`).join(", ") || "empty"}`)));
  const cfg = h("div", { class: "grid g4 section" }, ["registry", "people", "connectors", "models", "metrics"].filter((k) => o.config[k]).map((k) => {
    const c = o.config[k];
    return h("div", { class: "card" },
      h("h3", {}, KIND_LABEL[k]),
      c.active ? h("div", {}, h("div", { class: "row" }, h("b", {}, `v${c.active.version}`), statusBadge("published")),
        h("div", { class: "small muted" }, `by ${c.active.published_by} · ${when(c.active.published_at)}`))
        : h("div", { class: "small muted" }, "Running the overlay's own files (nothing published here yet)"),
      c.drafts ? h("div", { class: "small", style: "margin-top:6px" }, h("a", { href: `#/changes?kind=${k}` }, `${c.drafts} draft${c.drafts === 1 ? "" : "s"} waiting`)) : null);
  }));
  const coverage = o.coverage.length ? h("div", { class: "card section" }, h("h2", {}, "Queues nobody can act on"),
    h("ul", { class: "problems" }, o.coverage.map((w) => h("li", { class: "warning" }, w))),
    h("a", { href: "#/people" }, "Fix in People & roles →")) : null;
  const activity = h("div", { class: "card section" }, h("h2", {}, "Recent changes"),
    o.activity.length ? activityTable(o.activity) : h("div", { class: "empty" }, "Nothing yet."));
  shell("overview", "Overview", `${o.overlay} · ${o.people} people in ${o.roles} roles`, [
    h("button", { onclick: () => (location.hash = "#/reviews") }, "Open reviews"),
  ], [tiles, cfg, coverage, activity]);
};

function stat(label, value, hint) {
  return h("div", { class: "card stat" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value),
    h("div", { class: "hint" }, hint));
}

function activityTable(rows) {
  return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "When"), h("th", {}, "What"), h("th", {}, "Detail"))),
    h("tbody", {}, rows.map((r) => h("tr", {},
      h("td", { class: "small muted", style: "white-space:nowrap" }, when(r.ts)),
      h("td", {}, h("span", { class: "badge b-plain" }, r.kind.replaceAll("_", " "))),
      h("td", { class: "small" }, describe(r))))));
}
function describe(r) {
  const d = r.data || {};
  switch (r.kind) {
    case "config_published": return `${d.kind} v${d.version} published by ${d.actor}`;
    case "config_saved": return `${d.kind} v${d.version} saved by ${d.author}${d.errors ? ` (${d.errors} errors)` : ""}`;
    case "config_apply_failed": return `${d.kind} v${d.version} could not be applied: ${d.error}`;
    case "model_evaluation": return `${d.model}: ${d.overall?.cases} cases, exact ${pct(d.overall?.exact)}, ready for ${(d.overall?.ready_patterns || []).join(", ") || "none yet"}`;
    case "promotion_approved": return `${d.pattern || ""} → ${d.to || d.route || ""} by ${d.actor || ""}`;
    case "route_set": return `${d.pattern || ""} → ${d.route || ""} by ${d.actor || ""}`;
    case "pattern_changed": return `${d.pattern || ""}: trust reset because its meaning changed`;
    default: return Object.entries(d).slice(0, 4).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ");
  }
}

// ---- reviews
PAGES.reviews = async (q) => {
  const [cards, cat, ranked] = await Promise.all([api("/console/api/reviews"), catalogue(),
    api("/console/api/reviews/ranked").catch(() => [])]);
  S.reviewCount = cards.length;
  const only = q?.get("pattern") || "";
  const order = q?.get("order") || "due";
  const info = Object.fromEntries(ranked.map((r) => [r.review, r]));
  const hasMoney = ranked.some((r) => r.money > 0);
  let shown = only ? cards.filter((c) => c.pattern_id === only) : cards;
  if (order === "money") shown = [...shown].sort((a, b) => ((info[b.review_id]?.money || 0) - (info[a.review_id]?.money || 0))
    || String(a.due_at).localeCompare(String(b.due_at)));
  const picked = new Set();
  const count = h("span", { class: "small muted" }, "none selected");
  const codes = [...new Set(shown.flatMap((c) => c.disposition_codes))];
  const code = select(codes.length ? codes : ["no_action"], codes.includes("no_action") ? "no_action" : codes[0], () => {});
  const bulk = async (kind) => {
    if (!picked.size) return toast("Select some cases first", true);
    try {
      const r = await api("/v1/reviews/bulk", { body: { review_ids: [...picked], kind, disposition_code: kind === "reject" ? code.value : null } });
      toast(`${r.decided.length} decided${r.refused.length ? `, ${r.refused.length} not: ${r.refused[0].reason}` : ""}`, !!r.refused.length && !r.decided.length);
      route();
    } catch (e) { toast(e.message, true); }
  };
  const patterns = [...new Set(cards.map((c) => c.pattern_id))];
  const bar = cards.length > 1 ? h("div", { class: "card row", style: "position:sticky;top:0;z-index:2" },
    select([["", "all exceptions"], ...patterns.map((p) => [p, p])], only, (v) => (location.hash = `#/reviews?${new URLSearchParams({ ...(v ? { pattern: v } : {}), order })}`)),
    hasMoney ? select([["due", "soonest due first"], ["money", "most money at stake first"]], order,
      (v) => (location.hash = `#/reviews?${new URLSearchParams({ ...(only ? { pattern: only } : {}), order: v })}`), { "aria-label": "Order" }) : null,
    h("button", { onclick: () => { document.querySelectorAll(".review input.pick").forEach((x) => { x.checked = true; picked.add(x.value); }); count.textContent = `${picked.size} selected`; } }, "Select all shown"),
    count, h("span", { class: "spacer" }),
    h("button", { class: "primary", onclick: () => bulk("approve") }, "Approve selected"),
    h("span", { class: "small muted" }, "or close as"), code, h("button", { class: "danger", onclick: () => bulk("reject") }, "Close selected")) : null;
  const list = shown.length ? shown.map((c) => {
    const el = reviewCard(c, cat);
    const r = info[c.review_id];
    if (r && (r.money > 0 || r.digested)) el.firstChild.append(...[      // DOM append prints null: drop empties
      r.money > 0 ? h("span", { class: "badge b-warn", style: "margin-left:6px" }, `${Math.round(r.money).toLocaleString()} at stake`) : null,
      r.digested ? h("span", { class: "badge b-info", style: "margin-left:6px", title: "Sent on the template digest, not as a card" }, "on digest") : null].filter(Boolean));
    const box = h("input", { type: "checkbox", class: "pick", value: c.review_id, style: "width:auto;margin-right:8px",
      onchange: (e) => { e.target.checked ? picked.add(c.review_id) : picked.delete(c.review_id); count.textContent = picked.size ? `${picked.size} selected` : "none selected"; } });
    el.firstChild.prepend(box);
    return el;
  }) : h("div", { class: "empty" }, "No reviews waiting for you.");
  shell("reviews", "Reviews", "Cases waiting for a decision from you or a role below you", null, [bar, list]);
};

function reviewCard(c, cat) {
  const steps = c.proposal_steps || [];
  const decide = async (body) => {
    try {
      await api(`/v1/reviews/${c.review_id}/decision`, { body });
      toast("Decision recorded");
      route();
    } catch (e) { toast(e.data?.escalate_to ? `${e.message} — ${e.data.escalate_to} can approve this` : e.message, true); }
  };
  const code = select(c.disposition_codes, c.proposal_code || c.disposition_codes[0], () => {});
  const modify = () => {
    const allowed = c.allowed_actions.map((a) => a.action);
    let action = steps[0]?.action || allowed[0];
    const skeleton = (name) => {            // the action's parameters, filled from the case's facts where they match
      const schema = (c.allowed_actions.find((a) => a.action === name) || {}).params || {};
      const out = {};
      for (const k of Object.keys(schema)) {
        const key = k.replace(/\?$/, "");
        out[key] = c.facts[key] ?? c.facts[key.replace(/_id$/, "")] ?? "";
      }
      return out;
    };
    const params = h("textarea", { class: "code", style: "min-height:120px" },
      JSON.stringify(steps[0]?.action === action ? steps[0].params : skeleton(action), null, 2));
    const mcode = select(c.disposition_codes, c.proposal_code || c.disposition_codes[0], () => {});
    const note = h("input", { placeholder: "Why (optional)" });
    modal("Do something else", h("div", {},
      field("Action", select(allowed, action, (v) => { action = v; params.value = JSON.stringify(skeleton(v), null, 2); }),
        (cat.actions.find((a) => a.name === action) || {}).description),
      field("Parameters (JSON)", params), field("Outcome", mcode), field("Note", note)), [
      (close) => h("button", { onclick: close }, "Cancel"),
      (close) => h("button", { class: "primary", onclick: async () => {
        let p; try { p = JSON.parse(params.value || "{}"); } catch { return toast("Parameters must be valid JSON", true); }
        close(); decide({ kind: "modify", action, params: p, disposition_code: mcode.value, note: note.value });
      } }, "Do it"),
    ]);
  };
  return h("div", { class: "card review" },
    h("div", { class: "row" }, h("b", {}, c.title), h("span", { class: "badge b-plain" }, c.pattern_id),
      h("span", { class: `badge ${c.severity === "critical" || c.severity === "high" ? "b-bad" : "b-plain"}` }, c.severity),
      h("span", { class: "spacer" }), h("span", { class: "small muted" }, `due ${when(c.due_at)}`)),
    h("div", { class: "small muted" }, c.reason, c.escalation_level ? ` · escalated ${c.escalation_level}×` : ""),
    c.hold ? h("div", { class: "small", style: "color:var(--info)" }, c.hold.kind === "pause"
      ? `Paused (${c.hold.reason.replace(/_/g, " ")}) by ${c.hold.by || "someone"} until ${when(c.hold.until)}; comes back sooner if the source reports it again.`
      : `Held by a silence until ${when(c.hold.until)}: ${c.hold.reason}`) : null,
    c.quiet ? h("div", { class: "small", style: "color:var(--bad)" }, "Past every escalation: no longer sent as a card, only on the daily overdue list.") : null,
    h("div", { class: "facts" }, Object.entries(c.facts).map(([k, v]) => h("span", { class: "chip" }, `${k}=${v}`))),
    steps.length ? h("div", { class: "proposal" },
      h("div", { class: "small muted" }, `Suggested${c.proposal_confidence != null ? ` (confidence ${pct(c.proposal_confidence)})` : ""}`),
      steps.map((s) => h("div", {}, h("b", {}, s.action), " ", h("span", { class: "mono small muted" }, JSON.stringify(s.params)))),
      c.proposal_rationale ? h("div", { class: "small", style: "margin-top:4px" }, c.proposal_rationale) : null) : null,
    c.sop ? h("details", { class: "small", style: "margin:6px 0" }, h("summary", {}, "Procedure"), h("pre", { class: "diff", style: "white-space:pre-wrap" }, c.sop)) : null,
    (c.similar_cases || []).length ? h("div", { class: "small muted" }, "Similar past cases: ",
      c.similar_cases.map((s) => h("span", { class: "chip" }, `${(s.actions || []).join("+") || "no action"} → ${s.code}${s.reversed ? " (reversed)" : ""}`))) : null,
    h("div", { class: "row", style: "margin-top:10px" },
      steps.length ? h("button", { class: "primary", onclick: () => decide({ kind: "approve", disposition_code: c.proposal_code }) }, "Approve") : null,
      h("button", { onclick: modify }, steps.length ? "Do something else" : "Choose an action"),
      c.hold?.kind === "pause" ? h("button", { onclick: async () => {
        try { await api(`/console/api/reviews/${c.review_id}/resume`, { body: {} }); toast("Back in the queue"); route(); } catch (e) { showError(e); }
      } }, "Resume") : !c.hold && (c.pause_reasons || []).length ? h("button", { class: "ghost", onclick: () => pauseReview(c) }, "Pause…") : null,
      h("span", { class: "spacer" }), h("span", { class: "small muted" }, "Close without action as"), code,
      h("button", { class: "danger", onclick: () => decide({ kind: "reject", disposition_code: code.value }) }, "Close")));
}

// ---- metrics (KPIs, monitors; from a number to an action)
function fmtMetric(v, kind) {
  if (v === null || v === undefined) return "–";
  if (kind === "percent") return `${(v * 100).toFixed(1)}%`;
  if (kind === "hours") return `${v.toFixed(1)} h`;
  if (kind === "currency") return `₹${Math.round(v).toLocaleString("en-IN")}`;
  return Number.isInteger(v) ? v.toLocaleString("en-IN") : v.toFixed(2);
}

function sparkline(points, w = 160, hgt = 36) {
  const ys = points.map((p) => p.y).filter((y) => y !== null && y !== undefined);
  if (ys.length < 2) return h("div", { class: "small faint" }, "no trend yet");
  const lo = Math.min(...ys), hi = Math.max(...ys), span = hi - lo || 1;
  const xy = points.map((p, i) => `${(i / (points.length - 1)) * w},${hgt - 4 - ((p.y - lo) / span) * (hgt - 8)}`).join(" ");
  const box = document.createElement("span");      // the HTML parser puts <svg> in the SVG namespace
  box.innerHTML = `<svg width="${w}" height="${hgt}" viewBox="0 0 ${w} ${hgt}"><polyline fill="none" stroke="var(--info)" stroke-width="2"></polyline></svg>`;
  box.querySelector("polyline").setAttribute("points", xy);      // numbers only
  return box;
}

function bars(rows, by, kind) {
  const max = Math.max(...rows.map((r) => r.value || 0), 1e-9);
  return h("table", {}, h("tbody", {}, rows.map((r) => h("tr", {},
    h("td", { class: "small" }, by.map((d) => r[d]).join(", ") || r.period),
    h("td", { style: "width:55%" }, h("div", { style: `height:10px;border-radius:3px;width:${Math.max(2, (r.value / max) * 100)}%;background:${r.target_ok === false ? "var(--bad)" : "var(--info)"}` })),
    h("td", { class: "num small" }, fmtMetric(r.value, kind), r.target_ok === false ? h("span", { class: "badge b-bad", style: "margin-left:6px" }, "missed") : null),
    h("td", { class: "num small faint" }, r.change_pct === null || r.change_pct === undefined ? "" : `${r.change_pct > 0 ? "+" : ""}${r.change_pct}%`)))));
}

function metricDrawer(m) {
  let by = m.dimensions[0] || "", days = 7;
  const box = h("div", {}, h("div", { class: "empty" }, "Loading…"));
  const load = async () => {
    try {
      const r = await api("/console/api/metrics/query", { body: { metric: m.name, by: by ? [by] : [], days } });
      box.replaceChildren(r.result.rows.length ? bars(r.result.rows, r.result.by, m.format) : h("div", { class: "empty" }, "No data in this period."),
        h("div", { class: "small faint", style: "margin-top:6px" }, `Data loaded ${when(r.result.loaded_at)}`));
    } catch (e) { box.replaceChildren(h("div", { class: "empty" }, e.message)); }
  };
  const note = h("input", { placeholder: "What should the agent look at? (optional)" });
  const filt = h("input", { placeholder: "only where (fact=value), e.g. location=WH_CHN" });
  drawer(m.title, h("div", {},
    h("div", { class: "small muted", style: "margin-bottom:10px" }, m.description || "", m.target ? ` Target ${m.target}.` : "", m.owner ? ` Owned by ${m.owner}.` : ""),
    h("div", { class: "row" }, field("Split by", select([["", "nothing"], ...m.dimensions.map((d) => [d, d])], by, (v) => { by = v; load(); })),
      field("Period", select([["1", "today"], ["7", "7 days"], ["30", "30 days"], ["90", "90 days"]], String(days), (v) => { days = Number(v); load(); }))),
    box,
    h("div", { class: "card section" }, h("h3", {}, "Ask the agent to act on this"),
      h("div", { class: "small muted" }, "Opens a case for the KPI's owner with the number you are looking at; the agent prepares what to do."),
      field("For", filt), field("Note", note))), (close) => [
    h("button", { onclick: close }, "Close"),
    h("button", { class: "primary", onclick: async () => {
      try {
        const r = await api("/console/api/metrics/raise", { body: { metric: m.name, filters: parseKv(filt.value), note: note.value } });
        close(); toast(r.status === "duplicate" ? "Already raised today" : "Case opened for the owner"); if (r.incident_id) location.hash = `#/case?id=${r.incident_id}`;
      } catch (e) { showError(e); }
    } }, "Open a case"),
  ]);
  load();
}

// ---- capabilities: what the business does, how far each part has got, and the evidence per method
const STAGE = { planned: ["b-plain", "planned"], observed: ["b-info", "observed"], measured: ["b-info", "measured"],
  verified: ["b-ok", "verified"], acting: ["b-ok", "acting"] };

PAGES.capabilities = async (q) => {
  const days = q.get("days") || "30";
  const [c, m, cands] = await Promise.all([api(`/console/api/capabilities?days=${days}`), api("/console/api/methods?days=90"),
    api("/console/api/methods/candidates").catch(() => [])]);
  if (!c.capabilities.length) {
    return shell("capabilities", "Capabilities", "Business capabilities and how far each has got", null,
      h("div", { class: "empty" }, "No exceptions or capabilities yet. Add capabilities: to the registry (an accountable role, its intent, the metrics that measure it) and give each exception its capability."));
  }
  const cards = c.capabilities.map((x) => {
    const [cls, label] = STAGE[x.stage] || ["b-plain", x.stage];
    const s = x.stats;
    return h("div", { class: "card section" },
      h("div", { style: "display:flex;gap:10px;align-items:baseline;flex-wrap:wrap" },
        h("h2", { style: "margin:0" }, x.title), h("span", { class: "mono small muted" }, x.id),
        h("span", { class: `badge ${cls}` }, label),
        x.mode === "observe" ? h("span", { class: "badge b-warn", title: "Instrumented and measured; every exception in shadow: nothing happens without a person" }, "observe only") : null,
        x.max_route ? h("span", { class: "small muted" }, `automation up to ${x.max_route}`) : null,
        x.owner ? h("span", { class: "small" }, "owner ", h("b", {}, x.owner)) : null),
      x.description ? h("div", { class: "small muted", style: "margin-top:4px" }, x.description) : null,
      x.intent.length ? h("ul", { class: "small", style: "margin:8px 0 0 18px;padding:0" }, x.intent.map((i) => h("li", {}, i))) : null,
      x.outcomes.length ? h("div", { class: "grid g4", style: "margin-top:12px" }, x.outcomes.map((o) =>
        stat(o.title || o.metric, o.error ? "–" : (o.text ?? "–"),
          o.error || [o.target ? `target ${o.target}` : "", o.target_ok === false ? "missed" : o.target_ok ? "met" : "", o.trusted === false ? "data not trusted" : ""].filter(Boolean).join(" · ")))) : null,
      h("div", { class: "small muted", style: "margin:12px 0 6px" },
        `${x.open} open · ${s.cases} decided in ${c.days} days · ${s.unattended} without a person · agreement ${pct(s.agreement)} · outcomes held ${s.outcomes.held}, failed ${s.outcomes.failed}`),
      x.exceptions.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "Method", "Owner", "Route now", "Up to", "Checks", "Open"].map((t, i) => h("th", { class: i === 6 ? "num" : null }, t)))),
        h("tbody", {}, x.exceptions.map((e) => h("tr", {},
          h("td", {}, h("b", { class: "mono small" }, e.id), e.shadow ? h("span", { class: "badge b-warn", style: "margin-left:6px" }, "shadow") : null, h("div", { class: "small muted" }, e.description)),
          h("td", { class: "mono small" }, e.method || "–"), h("td", { class: "small" }, e.owner_role),
          h("td", {}, badgeRoute(e.route_now)), h("td", { class: "small" }, e.max_route),
          h("td", { class: "small" }, [e.playbook ? "playbook" : "", e.outcome_check ? "outcome check" : "", e.clears_at_source ? "clears at source" : ""].filter(Boolean).join(" · ") || "–"),
          h("td", { class: "num" }, e.open))))) : h("div", { class: "small muted" }, "No exceptions yet: measured by its metrics only."));
  });
  const rows = m.methods.map((r) => h("tr", {},
    h("td", { class: "small" }, r.capability || "–"), h("td", { class: "mono small" }, r.pattern),
    h("td", { class: "mono small" }, r.method || "–", r.current ? h("span", { class: "badge b-ok", style: "margin-left:6px" }, "current") : null,
      h("div", { class: "faint small" }, (r.definition || "").slice(0, 8), r.configs.length ? ` · registry ${r.configs.join(", ")}` : "")),
    h("td", { class: "num" }, r.cases), h("td", { class: "num" }, r.shadow), h("td", { class: "num" }, r.unattended),
    h("td", { class: "num" }, pct(r.agreement)), h("td", { class: "num" }, r.reversed),
    h("td", { class: "num" }, `${r.outcomes.held} / ${r.outcomes.failed}`), h("td", { class: "num" }, pct(r.held_rate))));
  const methods = h("div", { class: "card section", style: "padding:0" },
    h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Methods of work"),
      h("div", { class: "small muted" }, "Each version of how an exception is handled, with its results on real cases over 90 days. Try a change on past cases first (Exceptions → replay), run it in shadow, then publish; publishing the earlier version rolls it back.")),
    rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Capability", "Exception", "Method", "Cases", "Shadow", "Unattended", "Agreement", "Reversed", "Held / failed", "Held"].map((t, i) => h("th", { class: i > 2 ? "num" : null }, t)))), h("tbody", {}, rows))
      : h("div", { class: "empty", style: "margin:16px" }, "No decided cases yet."));
  const send = async (id, what, label, note) => {
    try { await api(`/console/api/methods/candidates/${id}/${what}`, { body: { note } }); toast(label); route(); } catch (e) { showError(e); }
  };
  const decide = (id, what, label) => () => {
    if (what !== "reject" && what !== "rollback") return send(id, what, label, "");
    const note = h("textarea", { placeholder: "Why? (kept with the method)", style: "min-height:70px;width:100%" });
    modal(what === "reject" ? "Reject this method" : "Roll back this method", h("div", {}, note), [
      (close) => h("button", { onclick: close }, "Cancel"),
      (close) => h("button", { class: what === "rollback" ? "danger" : "primary", onclick: () => { close(); send(id, what, label, note.value); } }, what === "reject" ? "Reject" : "Roll back"),
    ]);
  };
  const showTrial = async (id) => {
    try {
      const t = await api(`/console/api/methods/candidates/${id}/trial`);
      const arm = (label, a) => h("tr", {}, h("td", {}, label), h("td", { class: "num" }, a.cases), h("td", { class: "num" }, `${a.held} / ${a.failed}`),
        h("td", { class: "num" }, pct(a.held_rate)), h("td", { class: "num" }, a.hours_to_resolve ?? "–"), h("td", { class: "num" }, pct(a.agreement)));
      modal(`Trial of ${t.name}`, h("div", {},
        h("p", {}, h("span", { class: `badge ${t.verdict === "better" ? "b-ok" : t.verdict === "worse" ? "b-bad" : "b-plain"}` }, t.verdict), " ", t.summary),
        h("div", { class: "small muted" }, `Since ${when(t.since)}, ${Math.round(t.share * 100)}% of new cases at random; every trial case is decided by a person.`),
        h("table", {}, h("thead", {}, h("tr", {}, ["", "Cases", "Held / failed", "Held", "Hours to resolve", "Agreement"].map((x, i) => h("th", { class: i ? "num" : null }, x)))),
          h("tbody", {}, arm(t.name, t.candidate_arm), arm("Current method", t.current_arm)))),
        [(close) => h("button", { onclick: close }, "Close")]);
    } catch (e) { showError(e); }
  };
  const statusCls = { proposed: "b-info", shadow: "b-warn", trial: "b-warn", awaiting_approval: "b-warn", promoted: "b-ok", rejected: "b-plain", rolled_back: "b-plain" };
  const candRows = cands.map((x) => h("tr", {},
    h("td", { class: "mono small" }, x.pattern_id), h("td", { class: "mono small" }, x.name, h("div", { class: "faint" }, x.replaces ? `replaces ${x.replaces}` : "first method")),
    h("td", { class: "small" }, x.steps.map((st) => `${st.action}(${Object.entries(st.params).map(([k, v]) => `${k}=${v}`).join(", ")})`).join(" → ")),
    h("td", { class: "num small" }, `${x.support.cases} of ${x.support.decided}`),
    h("td", { class: "num small" }, `${pct(x.backtest.agreement)} vs ${pct(x.backtest.current?.agreement)}`),
    h("td", { class: "num small" }, x.shadow.cases ? `${x.shadow.agreed}/${x.shadow.cases} (${pct(x.shadow.agreement)})` : "–"),
    h("td", {}, h("span", { class: `badge ${statusCls[x.status] || "b-plain"}` }, x.status.replace("_", " "))),
    h("td", {}, canConfigure() ? [
      ["proposed", "rolled_back"].includes(x.status) ? h("button", { class: "ghost", onclick: decide(x.id, "shadow", "Watching in shadow") }, "Watch in shadow") : null,
      x.status === "shadow" ? h("button", { class: "ghost", title: "Give half of new cases this method's proposal, at random, and compare verified outcomes", onclick: decide(x.id, "trial", "Trial started") }, "Try on new cases") : null,
      x.status === "trial" ? h("button", { class: "ghost", onclick: () => showTrial(x.id) }, "Trial results") : null,
      ["shadow", "trial"].includes(x.status) ? h("button", { class: "ghost", onclick: decide(x.id, "promote", "Promoted") }, "Promote") : null,
      x.status === "promoted" ? h("button", { class: "ghost", onclick: decide(x.id, "rollback", "Rolled back") }, "Roll back") : null,
      ["proposed", "shadow", "trial"].includes(x.status) ? h("button", { class: "ghost", onclick: decide(x.id, "reject", "Rejected") }, "Reject") : null] : null)));
  const proposed = h("div", { class: "card section", style: "padding:0" },
    h("div", { style: "padding:16px 18px 6px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap" },
      h("div", { style: "flex:1" }, h("h2", { style: "margin:0" }, "Proposed methods"),
        h("div", { class: "small muted" }, "Ways of handling an exception that learning found in what people keep doing, tested on past cases. Watch one in shadow; promote it once it agrees with people often enough. Learning never approves its own change, and never uses an action the exception does not allow.")),
      canConfigure() ? h("button", { onclick: async () => { try { const n = await api("/console/api/methods/propose", { body: {} }); toast(`${n.length} new`); route(); } catch (e) { showError(e); } } }, "Look for better methods") : null),
    candRows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "Method", "Does", "Support", "Past cases: new vs now", "Shadow", "Status", ""].map((t, i) => h("th", { class: i >= 3 && i <= 5 ? "num" : null }, t)))), h("tbody", {}, candRows))
      : h("div", { class: "empty", style: "margin:16px" }, "Nothing proposed yet. Proposals come once a day from the cases people decided."));
  shell("capabilities", "Capabilities", "What the business does, who is accountable, how each part is measured and how far it has got: planned, observed, measured, verified, acting",
    [select([["7", "7 days"], ["30", "30 days"], ["90", "90 days"]], days, (x) => (location.hash = `#/capabilities?days=${x}`))], [...cards, proposed, methods]);
};

PAGES.metrics = async () => {
  const k = await api("/console/api/metrics");
  if (!k.configured) {
    return shell("metrics", "Metrics", "KPIs from your data, watched by monitors that raise cases", canConfigure() ? h("button", { class: "primary", onclick: () => yamlEditor("metrics") }, "Set up metrics") : null,
      h("div", { class: "empty" }, "No metrics yet. Define datasets, KPIs and monitors (kind: metrics): monitors raise a case when a KPI misses its target and close it when it recovers."));
  }
  const tiles = h("div", { class: "grid g4" }, k.metrics.map((m) => {
    const v = m.value || {};
    return h("div", { class: "card stat", style: "cursor:pointer", onclick: () => metricDrawer(m) },
      h("div", { class: "label" }, m.title),
      h("div", { class: "value", style: v.target_ok === false ? "color:var(--bad)" : null }, m.error ? "–" : fmtMetric(v.value, m.format)),
      h("div", { class: "hint" }, m.error || [m.target ? `target ${m.target}` : "", m.change_pct === null || m.change_pct === undefined ? "" : `${m.change_pct > 0 ? "+" : ""}${m.change_pct}% vs previous 7 days`].filter(Boolean).join(" · ")),
      m.trend ? sparkline(m.trend) : null);
  }));
  const mons = h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Monitors"),
    h("div", { class: "small muted" }, "Each one raises a case when its metric misses, reports it again while it lasts, and closes it when the metric recovers.")),
    h("table", {}, h("thead", {}, h("tr", {}, ["Monitor", "Watches", "Every", "In breach now", "Last run", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, k.monitors.map((x) => h("tr", {},
        h("td", {}, h("b", { class: "mono small" }, x.name)),
        h("td", { class: "small" }, `${x.metric}${x.by.length ? ` by ${x.by.join(", ")}` : ""}, last ${x.window_days} day(s)`),
        h("td", { class: "small" }, `${x.every_minutes} min`),
        h("td", { class: "small" }, Object.keys(x.breaching).length ? Object.entries(x.breaching).map(([g, b]) => h("span", { class: "badge b-bad", style: "margin-right:4px" }, `${g.replace(/^[a-z_]+=/, "")} since ${when(b.since)}`)) : h("span", { class: "badge b-ok" }, "none")),
        h("td", { class: "small" }, x.last_run ? when(x.last_run) : "not yet"),
        h("td", {}, k.can_run ? h("button", { class: "ghost", onclick: async () => {
          try { const r = await api(`/console/api/monitors/${x.name}/run`, { body: {} }); toast(`${r.raised.length} raised, ${r.recovered.length} recovered`); route(); } catch (e) { showError(e); }
        } }, "Run now") : null))))));
  const ds = h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Datasets")),
    h("table", {}, h("thead", {}, h("tr", {}, ["Dataset", "From", "Rows", "Loaded", "Refresh", "Trusted"].map((t) => h("th", {}, t)))),
      h("tbody", {}, k.datasets.map((d) => h("tr", {}, h("td", { class: "mono small" }, d.name), h("td", { class: "small" }, d.kind),
        h("td", { class: "num small" }, d.rows ?? "–"), h("td", { class: "small" }, d.error ? h("span", { style: "color:var(--bad)" }, d.error) : d.loaded_at ? when(d.loaded_at) : "not yet"),
        h("td", { class: "small" }, `${d.refresh_minutes} min`),
        h("td", { class: "small" }, !d.trust ? h("span", { class: "faint" }, "no checks") : d.trust.ok === false
          ? h("span", { title: d.trust.problems.join("; ") }, h("span", { class: "badge b-bad" }, "not trusted"), " ", d.trust.problems[0], d.owner ? ` · ${d.owner} fixes it` : "")
          : h("span", { class: "badge b-ok" }, "checks pass")))))));
  shell("metrics", "Metrics", "KPIs from your data. Click one to split it, or to ask the agent to act on it", canConfigure() ? h("button", { onclick: () => yamlEditor("metrics") }, "Edit metrics") : null, [tiles, mons, ds]);
};

function pauseReview(c) {
  const reason = select(c.pause_reasons.map((r) => [r, r.replace(/_/g, " ")]), c.pause_reasons[0], () => {});
  const hours = h("input", { type: "number", min: 1, max: 720, value: 72 });
  modal("Pause this case", h("div", {},
    h("div", { class: "small muted", style: "margin-bottom:10px" }, "The clock stops: no escalation and no expiry while you wait. It comes back to you when the time is up, or at once if the source reports the problem again."),
    field("Waiting for", reason), field("For up to (hours)", hours)), [
    (close) => h("button", { onclick: close }, "Cancel"),
    (close) => h("button", { class: "primary", onclick: async () => {
      try { await api(`/console/api/reviews/${c.review_id}/pause`, { body: { reason: reason.value, hours: Number(hours.value) || null } }); close(); toast("Paused"); route(); }
      catch (e) { showError(e); }
    } }, "Pause"),
  ]);
}

PAGES.silences = async () => {
  const s = await api("/console/api/silences");
  const factsText = (f) => Object.entries(f || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(", ");
  const row = (x, live) => h("tr", {},
    h("td", {}, h("b", {}, x.reason), h("div", { class: "small faint" }, `by ${x.by}`)),
    h("td", { class: "small" }, x.pattern || "every exception", x.facts && Object.keys(x.facts).length ? h("div", { class: "mono faint" }, factsText(x.facts)) : null),
    h("td", { class: "small" }, `${when(x.starts_at)} → ${when(x.ends_at)}`, x.ended_at ? h("div", { class: "faint" }, `ended early by ${x.ended_by}`) : null),
    h("td", { class: "num small" }, live ? String(x.holding) : "–"),
    h("td", {}, live && s.can_silence ? h("button", { class: "ghost danger", onclick: async () => {
      try { await api(`/console/api/silences/${x.id}`, { method: "DELETE" }); toast("Silence ended; held cases go out now"); route(); } catch (e) { showError(e); }
    } }, "End now") : null));
  const table = (rows, live, empty) => rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Why", "Covers", "When", "Cases held", ""].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((x) => row(x, live)))) : h("div", { class: "empty", style: "margin:12px" }, empty);
  const add = () => {
    const f = { pattern: "", facts: "", hours: 3, reason: "" };
    modal("New silence", h("div", {},
      h("div", { class: "small muted", style: "margin-bottom:10px" }, "Cases that match are still recorded, but nothing runs on its own and nobody is sent a card until the silence ends. Then they go to people as usual."),
      field("Why", h("input", { placeholder: "e.g. stock count at WH_CHN tonight", oninput: (e) => (f.reason = e.target.value) })),
      field("Exception", select([["", "every exception"], ...s.patterns.map((p) => [p, p])], "", (v) => (f.pattern = v))),
      field("Only where (fact=value, one per line; a|b for either)", h("textarea", { class: "code", style: "min-height:60px", placeholder: "location=WH_CHN", oninput: (e) => (f.facts = e.target.value) })),
      field("For (hours)", h("input", { type: "number", min: 1, max: 336, value: 3, oninput: (e) => (f.hours = Number(e.target.value)) }))), [
      (close) => h("button", { onclick: close }, "Cancel"),
      (close) => h("button", { class: "primary", onclick: async () => {
        const facts = {};
        for (const [k, v] of Object.entries(parseKv(f.facts))) facts[k] = typeof v === "string" && v.includes("|") ? v.split("|").map((x) => x.trim()) : v;
        try { await api("/console/api/silences", { body: { reason: f.reason, hours: f.hours, pattern: f.pattern || null, facts } }); close(); toast("Silence on"); route(); }
        catch (e) { showError(e); }
      } }, "Silence"),
    ]);
  };
  shell("silences", "Silences", "Planned noise: hold matching cases while you do planned work", s.can_silence ? h("button", { class: "primary", onclick: add }, "New silence") : null, [
    s.can_silence ? null : h("div", { class: "small muted" }, "Silences need the __silence__ or __kill_switch__ right."),
    h("div", { class: "card", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Now")), table(s.active, true, "Nothing is silenced.")),
    s.upcoming.length ? h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Coming up")), table(s.upcoming, false, "")) : null,
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Ended")), table(s.ended, false, "None yet.")),
  ]);
};

// ---- exceptions (operate + configure)
async function catalogue() {
  if (!S.catalogue) S.catalogue = await api("/console/api/catalogue");
  return S.catalogue;
}

PAGES.exceptions = async () => {
  const [pats, cat, dir] = await Promise.all([api("/console/api/patterns"), catalogue(), api("/console/api/directory")]);
  const doc = S.pending.registry;
  const known = new Set(pats.map((p) => p.id));
  const added = doc ? (doc.patterns || []).filter((x) => !known.has(x.id)) : [];
  const removed = doc ? pats.filter((p) => !(doc.patterns || []).some((x) => x.id === p.id)).map((p) => p.id) : [];
  const rows = pats.map((p) => {
    const changed = S.changes.registry.some((c) => c === `edited ${p.id}`);
    if (removed.includes(p.id)) return h("tr", {}, h("td", { colspan: 8 }, h("span", { class: "mono" }, p.id), " ", h("span", { class: "badge b-bad" }, "removed (unsaved)")));
    return h("tr", { class: "click", onclick: () => editPattern(p.id, cat, dir) },
      h("td", {}, h("div", { class: "row" }, h("b", { class: "mono" }, p.id), changed ? h("span", { class: "badge b-warn" }, "edited") : null,
        p.shadow ? h("span", { class: "badge b-info" }, "shadow") : null),
        h("div", { class: "desc" }, p.description)),
      h("td", {}, badgeRoute(p.route), h("span", { class: "arrow" }, "max"), badgeRoute(p.ceiling)),
      h("td", { class: "small" }, p.owner_role, p.escalation_role ? h("div", { class: "faint" }, `→ ${p.escalation_role}`) : null),
      h("td", { class: "num small" }, `${p.sla_minutes}m`),
      h("td", { class: "small" }, p.model_task || h("span", { class: "faint" }, "–")),
      h("td", { class: "num" }, p.dispositions),
      h("td", {}, h("div", { class: "bar", title: pct(p.automation_rate) }, h("i", { style: `width:${Math.round((p.automation_rate || 0) * 100)}%` })),
        h("div", { class: "small faint" }, pct(p.automation_rate))),
      h("td", { class: "small" }, p.trust_by && p.trust_by.length ? segTrust(p) : trustCell(p.id, p)));
  });
  const sugBox = h("div", {});
  api("/console/api/suggestions?days=30").then((sugs) => {
    if (!sugs.length) return;
    sugBox.replaceChildren(h("div", { class: "card section", style: "padding:0" },
      h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Suggested from unmatched cases"),
        h("div", { class: "small muted" }, "Groups of recent cases no exception recognised, with how people handled them. Add one as a draft, review it, then save.")),
      h("table", {}, h("tbody", {}, sugs.slice(0, 10).map((x) => h("tr", {},
        h("td", {}, h("b", { class: "mono" }, x.id), h("div", { class: "desc" }, x.pattern.description)),
        h("td", { class: "num" }, `${x.cases} cases`),
        h("td", { class: "small" }, x.usual_actions.length ? `usually ${x.usual_actions.join(" then ")} (${x.usual_share})` : x.usual_outcome ? `usually closed as ${x.usual_outcome}` : "not decided yet"),
        h("td", {}, h("button", { onclick: async () => {
          const doc = await pendingDoc("registry");
          doc.patterns = [...(doc.patterns || []), x.pattern];
          doc.roles = { ...(x.roles || {}), ...(doc.roles || {}) };
          if (x.fingerprint && !(doc.fingerprints || []).some((f) => f.event_type === x.fingerprint.event_type)) doc.fingerprints = [...(doc.fingerprints || []), x.fingerprint];
          recordChange("registry", `added ${x.id}`); toast(`${x.id} added as a draft`); route();
        } }, "Add as draft"))))))));
  }).catch(() => {});
  shell("exceptions", "Exceptions", "Every exception the registry recognises, how it is handled now and how far it may go", [
    h("button", { onclick: () => yamlEditor("registry") }, "Edit as YAML"),
    h("button", { class: "primary", onclick: () => editPattern(null, cat, dir) }, "New exception"),
  ], [sugBox, h("div", { class: "card", style: "padding:0" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Exception", "Handled by", "Owner", "SLA", "Model", "Closed", "Automation", "Trust"].map((t, i) =>
      h("th", { class: i === 3 || i === 5 ? "num" : null }, t)))),
    h("tbody", {}, rows, added.map((x) => h("tr", { class: "click", onclick: () => editPattern(x.id, cat, dir) },
      h("td", { colspan: 8 }, h("b", { class: "mono" }, x.id), " ", h("span", { class: "badge b-warn" }, "new (unsaved)"),
        h("div", { class: "desc" }, x.description || "")))))))]); 
};

function trustCell(id, s) {
  return s.pending_promotion
    ? h("div", {}, h("span", { class: "badge b-info" }, `ready for ${s.pending_promotion}`),
      h("div", { class: "row", style: "margin-top:4px" },
        h("button", { onclick: (e) => { e.stopPropagation(); promote(id, true); } }, "Approve"),
        h("button", { class: "ghost", onclick: (e) => { e.stopPropagation(); promote(id, false); } }, "Reject")))
    : h("span", { class: "faint" }, `streak ${s.streak}${s.reversals ? ` · ${s.reversals} reversed` : ""}`);
}

function segTrust(p) {
  const segs = p.segments || [];
  return h("div", {},
    h("div", { class: "faint" }, `earned per ${p.trust_by.join(", ")} · new ones start as `, badgeRoute(p.route)),
    segs.length ? segs.map((s) => h("div", { class: "seg", style: "margin-top:4px" },
      h("span", { class: "mono" }, s.segment), " ", badgeRoute(s.route), " ", trustCell(s.id, s)))
      : h("div", { class: "faint" }, "no cases yet"));
}

async function promote(pid, approve) {
  try {
    const st = await api(`/v1/patterns/${encodeURIComponent(pid)}/promotion/${approve ? "approve" : "reject"}`, { body: { note: "" } });
    toast(approve ? (st.pending_promotion ? "Approval recorded; a second person must also approve" : `Promoted to ${st.route}`) : "Promotion rejected");
    route();
  } catch (e) { toast(e.message, true); }
}

async function editPattern(pid, cat, dir) {
  const doc = await pendingDoc("registry");
  doc.patterns = doc.patterns || [];
  const existing = pid ? doc.patterns.find((p) => p.id === pid) : null;
  const p = clone(existing) || { id: "", description: "", event_types: [], match: {}, route: "hitl", allowed_actions: [],
    owner_role: (dir.roles[0] || {}).id || "supervisor", sla_minutes: 240 };
  const roles = dir.roles.length ? dir.roles.map((r) => [r.id, `${r.name} (${r.id})`]) : Object.keys(doc.roles || {});
  const eventTypes = (doc.fingerprints || []).map((f) => f.event_type);
  const inp = (key, type = "text", extra = {}) => h("input", { type, value: p[key] ?? "", oninput: (e) => {
    p[key] = type === "number" ? (e.target.value === "" ? undefined : Number(e.target.value)) : e.target.value; }, ...extra });
  const actionsBox = h("div", { class: "checks" }, cat.actions.map((a) => h("label", {},
    h("input", { type: "checkbox", checked: (p.allowed_actions || []).includes(a.name), onchange: (e) => {
      const set = new Set(p.allowed_actions || []);
      e.target.checked ? set.add(a.name) : set.delete(a.name);
      p.allowed_actions = [...set];
    } }),
    h("span", {}, h("span", { class: "mono" }, a.name), " ", h("span", { class: `badge ${a.risk === "irreversible" ? "b-bad" : a.risk === "safe" ? "b-ok" : "b-info"}` }, a.risk),
      h("div", { class: "small faint" }, a.description)))));
  const m0 = p.match || {};
  const complexMatch = ["all", "any", "not"].some((k) => k in m0) || Object.values(m0).some((v) => v && typeof v === "object" && !Array.isArray(v));
  const matchBox = complexMatch  // conditions with operators are edited in YAML, so the form never flattens them
    ? h("div", {}, h("pre", { class: "code small" }, JSON.stringify(m0, null, 1)), h("div", { class: "small faint" }, "Uses conditions (edit in YAML)."))
    : h("textarea", { class: "code", style: "min-height:70px", oninput: (e) => (p.match = parseKv(e.target.value)) }, kvText(p.match));
  const evSel = h("div", { class: "checks" }, eventTypes.map((t) => h("label", {},
    h("input", { type: "checkbox", checked: (p.event_types || []).includes(t), onchange: (e) => {
      const set = new Set(p.event_types || []);
      e.target.checked ? set.add(t) : set.delete(t);
      p.event_types = [...set];
    } }), h("span", { class: "mono" }, t))));
  const body = h("div", {},
    pid ? h("div", { class: "small muted", style: "margin-bottom:12px" }, "Changes become a draft of the exception registry. Changing what the exception means (matching, actions, playbook) resets the trust it has earned; wording, owner and SLA do not.")
      : field("Id", inp("id", "text", { placeholder: "e.g. order_stuck_no_stock", pattern: "[a-z0-9_]+" }), "Lowercase letters, digits and underscores."),
    field("Description", inp("description")),
    h("div", { class: "grid g2" },
      field("Handled by now", select([["hitl", "a person"], ["llm", "the model"], ["auto", "automatically (playbook)"]], p.route || "hitl", (v) => (p.route = v))),
      field("May earn up to", select([["auto", "automatic"], ["llm", "the model"], ["hitl", "always a person"]], p.max_route || "auto", (v) => (p.max_route = v)))),
    h("div", { class: "grid g2" },
      field("Owner role", select(roles, p.owner_role, (v) => (p.owner_role = v))),
      field("Escalates to", select([["", "nobody (owner's parent)"], ...roles], p.escalation_role || "", (v) => (p.escalation_role = v || undefined)))),
    h("div", { class: "grid g2" },
      field("SLA (minutes)", inp("sla_minutes", "number", { min: 1 })),
      field("Severity", select(["low", "medium", "high", "critical"], p.severity || "medium", (v) => (p.severity = v)))),
    h("div", { class: "grid g2" },
      field("Model task", select([["", "diagnose (frontier model)"], ["triage", "triage (small local model)"], ["investigate", "investigate (a crew, if configured)"],
        ...(p.model_task && !["triage", "investigate"].includes(p.model_task) ? [[p.model_task, p.model_task]] : [])], p.model_task || "", (v) => (p.model_task = v || undefined))),
      field("Model needs confidence ≥", inp("llm_min_confidence", "number", { step: "0.05", min: 0, max: 1, placeholder: "0.8" }))),
    h("div", { class: "grid g2" },
      field("Model may propose up to (actions)", inp("llm_max_steps", "number", { min: 1, max: 10, placeholder: "1" }),
        "More than one lets the model propose a sequence (hold, then notify). Changing this resets earned trust."),
      field("When a person handles it", select([["yes", "the model prepares a proposal first"], ["no", "no model call (saves cost)"]],
        p.diagnose === false ? "no" : "yes", (v) => (p.diagnose = v === "no" ? false : undefined)))),
    lifecycleFields(p, eventTypes),
    field("Raised by events", evSel.childNodes.length ? evSel : h("div", { class: "small faint" }, "No fingerprint rules yet: add them in the YAML editor.")),
    field("Matches when (fact=value, one per line; a|b for either; * for any)", matchBox),
    field("Earn trust separately per (facts, comma-separated)", h("input", { value: (p.trust_by || []).join(", "), placeholder: "e.g. channel",
      oninput: (e) => { const v = e.target.value.split(",").map((x) => x.trim()).filter(Boolean); p.trust_by = v.length ? v : undefined; } }),
      "Each value (each channel, say) earns its own promotions; lowering the pattern's route lowers them all, and each earns its way back. Changing this resets earned trust."),
    field("Allowed actions", actionsBox, "Only actions the overlay implements are listed. The model and people may only choose from these."),
    field("Instructions for the model", h("textarea", { style: "min-height:70px", oninput: (e) => (p.llm_instructions = e.target.value || undefined) }, p.llm_instructions || "")),
    field("Standard operating procedure", h("textarea", { style: "min-height:140px", placeholder: "# Orders stuck without stock\n1. Check every location...\n2. ...", oninput: (e) => (p.sop = e.target.value || undefined) }, p.sop || ""),
      "Your team's procedure, in plain text or Markdown. The model follows it and names the step it used; people see it on the review. Editing it does not reset earned trust."),
    field("Playbook (what happens automatically, in order)", playbookBuilder(p, cat),
      "Used when the exception is handled automatically, and offered to people as the usual steps. Values may be literal or templates such as {{payload.order_id}}, {{facts.region}} or a lookup's result ({{stock.available}}). Changing the playbook resets earned trust."));
  drawer(pid ? `Edit ${pid}` : "New exception", body, (close) => [
    pid ? h("button", { class: "danger", style: "margin-right:auto", onclick: () => {
      doc.patterns = doc.patterns.filter((x) => x.id !== pid);
      recordChange("registry", `removed ${pid}`); close(); route();
    } }, "Remove") : null,
    h("button", { onclick: close }, "Cancel"),
    h("button", { class: "primary", onclick: () => {
      if (!p.id || !/^[a-z0-9_]+$/.test(p.id)) return toast("Give it an id: lowercase letters, digits, underscores", true);
      if (!pid && doc.patterns.some((x) => x.id === p.id)) return toast("That id is already used", true);
      for (const k of Object.keys(p)) if (p[k] === undefined || p[k] === "") delete p[k];
      if (Array.isArray(p.playbook) && !p.playbook.length) delete p.playbook;
      const bad = playbookProblems(p, cat);
      if (bad.length) return toast(bad[0], true);
      if (pid) doc.patterns[doc.patterns.findIndex((x) => x.id === pid)] = p; else doc.patterns.push(p);
      recordChange("registry", pid ? `edited ${pid}` : `added ${p.id}`);
      close(); route();
    } }, "Keep change"),
  ]);
}

function lifecycleFields(p, eventTypes) {
  const num = (get, set, extra) => h("input", { type: "number", value: get() ?? "", ...extra, oninput: (e) => set(e.target.value === "" ? undefined : Number(e.target.value)) });
  const ev = (p.clear_when?.events || [])[0] || {};
  const setEv = (type, same) => {
    const cw = { ...(p.clear_when || {}) };
    if (type && same.length) cw.events = [{ type, same }]; else delete cw.events;
    p.clear_when = Object.keys(cw).length ? cw : undefined;
  };
  let evType = ev.type || "", evSame = (ev.same || []).join(", ");
  return h("details", { class: "card", style: "margin:8px 0", open: !!(p.escalation || p.clear_when || p.expires_after_hours != null || (p.pause_on || []).length) },
    h("summary", {}, h("b", {}, "When nobody answers, or the problem goes away")),
    h("div", { class: "small muted", style: "margin:6px 0 10px" }, "Left empty, the registry's defaults apply. None of these change earned trust."),
    h("div", { class: "grid g2" },
      field("Re-send at the top of the role tree at most (times)", num(() => p.escalation?.repeat, (v) => (p.escalation = v === undefined ? undefined : { repeat: v }), { min: 0, placeholder: "no limit" }),
        "Then no more cards: the case stays overdue on the console and goes on the daily overdue list."),
      field("Close as expired when untouched for (hours)", num(() => p.expires_after_hours, (v) => (p.expires_after_hours = v), { min: 0, placeholder: "never" }),
        "Counted from the last time a person or the source touched it. 0 = never, even if the default says otherwise.")),
    field("Closes itself when this event arrives", h("div", { class: "row", style: "gap:6px" },
      h("input", { value: evType, placeholder: "e.g. order.fulfilled", list: "evtypes", oninput: (e) => { evType = e.target.value.trim(); setEv(evType, evSame.split(",").map((x) => x.trim()).filter(Boolean)); } }),
      h("datalist", { id: "evtypes" }, eventTypes.map((t) => h("option", { value: t }))),
      h("span", { class: "small muted" }, "for the same"),
      h("input", { value: evSame, placeholder: "facts, e.g. order", oninput: (e) => { evSame = e.target.value; setEv(evType, evSame.split(",").map((x) => x.trim()).filter(Boolean)); } })),
      p.clear_when?.lookup ? `Also checks ${p.clear_when.lookup.tool} every ${p.clear_when.lookup.every_minutes || 30} minutes (edit in YAML).` : "A check by lookup (ask the WMS every 30 minutes) is set in the YAML editor: clear_when.lookup."),
    field("A person may pause it while waiting for (comma-separated)", h("input", { value: (p.pause_on || []).join(", "), placeholder: "e.g. awaiting_customer, awaiting_vendor",
      oninput: (e) => { const v = e.target.value.split(",").map((x) => x.trim().toLowerCase().replace(/\s+/g, "_")).filter(Boolean); p.pause_on = v.length ? v : undefined; } }),
      "The clock stops while paused; the case comes back when the time is up or the source reports it again."));
}

// ---- keys (connector credentials, stored encrypted)
PAGES.keys = async () => {
  const k = await api("/console/api/secrets");
  const can = canConfigure() && k.can_store;
  const badge = (src) => h("span", { class: `badge ${src === "console" ? "b-ok" : src === "environment" ? "b-info" : "b-warn"}` },
    src === "console" ? "set here" : src === "environment" ? "from the server" : "missing");
  const row = (x) => {
    const input = h("input", { type: "password", autocomplete: "off", placeholder: x.source === "missing" ? "paste the key" : "paste a new value to replace it", style: "min-width:220px" });
    return h("tr", {},
      h("td", {}, h("b", { class: "mono small" }, x.name), x.description ? h("div", { class: "small faint" }, x.description) : null,
        x.unused ? h("div", { class: "small faint" }, "not used by the published configuration") : null),
      h("td", { class: "small" }, x.used_by.join(", ") || "–"),
      h("td", {}, badge(x.source), x.hint ? h("span", { class: "mono small faint" }, ` …${x.hint}`) : null,
        x.set_by ? h("div", { class: "small faint" }, `by ${x.set_by}, ${when(x.set_at)}`) : null),
      h("td", {}, can ? h("div", { class: "row", style: "gap:6px" }, input,
        h("button", { class: "primary", onclick: async () => {
          if (!input.value.trim()) return toast("Paste the key first", true);
          try { await api(`/console/api/secrets/${encodeURIComponent(x.name)}`, { method: "PUT", body: { value: input.value } }); input.value = ""; toast(`${x.name} saved`); route(); }
          catch (e) { showError(e); }
        } }, "Save"),
        x.source === "console" ? h("button", { class: "ghost danger", onclick: async () => {
          try { await api(`/console/api/secrets/${encodeURIComponent(x.name)}`, { method: "DELETE" }); toast(`${x.name} cleared`); route(); } catch (e) { showError(e); }
        } }, "Clear") : null) : null));
  };
  const rows = k.keys.filter((x) => !x.platform).map(row);
  const platformRows = k.keys.filter((x) => x.platform).map(row);
  const logins = k.logins.map((n) => h("button", { onclick: async () => {
    try { const r = await api(`/console/api/secrets/test/${encodeURIComponent(n)}`, { body: {} }); toast(`${n}: ${r.detail}`, !r.ok); } catch (e) { showError(e); }
  } }, `Test ${n} login`));
  const missing = k.keys.filter((x) => x.source === "missing" && !x.unused && !x.platform).length;
  shell("keys", "Keys", missing ? `${missing} key${missing === 1 ? "" : "s"} still needed by the configured connectors` : "Every key the connectors need is set", logins, [
    k.can_store ? null : h("div", { class: "card", style: "border-left:3px solid var(--warn)" }, "Keys can't be entered here until the server has SENTINEL_MASTER_KEY set (sentinel new-master-key). Until then they come from the server's environment."),
    problemsList((k.problems || []).map((m) => ({ severity: "error", message: m }))),
    h("div", { class: "card", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Connector keys"),
      h("div", { class: "small muted" }, "Stored encrypted; a saved key is never shown again, only its last four characters. A key saved here is used instead of the server's environment variable of the same name, by every process, at once.")),
      rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Key", "Used by", "Status", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows))
        : h("div", { class: "empty", style: "margin:16px" }, "No connector needs a key yet. Add a connector on the Data sources page; the keys it needs appear here.")),
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Platform keys (optional)"),
      h("div", { class: "small muted" }, "Each turns on a feature: signing the audit trail, usage exports and bundles, SCIM and the pack catalogue.")),
      h("table", {}, h("thead", {}, h("tr", {}, ["Key", "For", "Status", ""].map((t) => h("th", {}, t)))), h("tbody", {}, platformRows))),
  ]);
};

// ---- playbook builder
const WHEN_OPS = [["eq", "is"], ["ne", "is not"], ["gt", ">"], ["gte", "≥"], ["lt", "<"], ["lte", "≤"], ["in", "is one of"],
  ["not_in", "is none of"], ["contains", "contains"], ["exists", "is present"], ["missing", "is missing"], ["empty", "is empty"], ["not_empty", "is not empty"],
  ["matches", "matches (regex)"]];
const NEGATED = { missing: "exists", not_empty: "empty" };          // shown as their own choice, stored as {op: false}

function looseValue(text) {          // 12 -> number, true -> boolean, [a,b] / {"x":1} -> JSON, else the text
  const t = String(text).trim();
  if (t === "") return "";
  if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
  if (t === "true" || t === "false") return t === "true";
  if (/^[\[{]/.test(t)) { try { return JSON.parse(t); } catch { /* text */ } }
  return text;
}
function showValue(v) { return v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v); }

function whenRows(when) {            // a flat condition as rows, or null when it uses all / any / not
  if (!when) return [];
  if (["all", "any", "not"].some((k) => k in when)) return null;
  return Object.entries(when).map(([path, v]) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const [op, val] = Object.entries(v)[0] || ["eq", ""];
      if ((op === "exists" || op === "empty") && val === false) return { path, op: op === "exists" ? "missing" : "not_empty", value: "" };
      return { path, op, value: val };
    }
    return { path, op: Array.isArray(v) ? "in" : "eq", value: v };
  });
}
function rowsToWhen(rows) {
  const out = {};
  for (const r of rows) {
    if (!r.path) continue;
    if (NEGATED[r.op]) { out[r.path] = { [NEGATED[r.op]]: false }; continue; }
    const v = ["exists", "empty"].includes(r.op) ? (r.value === "" ? true : r.value) : r.value;
    out[r.path] = r.op === "eq" && (typeof v !== "object" || v === null) ? v : { [r.op]: v };
  }
  return Object.keys(out).length ? out : undefined;
}

function playbookProblems(p, cat) {
  const out = [];
  const acts = Object.fromEntries(cat.actions.map((a) => [a.name, a]));
  const tools = Object.fromEntries((cat.tools || []).map((t) => [t.name, t]));
  (p.playbook || []).forEach((st, i) => {
    const n = `Playbook step ${i + 1}`;
    if (st.action !== undefined) {
      if (!acts[st.action]) out.push(`${n}: choose an action`);
      else for (const [k] of Object.entries(acts[st.action].params || {}).filter(([k]) => !k.endsWith("?")))
        if (st.params?.[k] === undefined || st.params[k] === "") out.push(`${n}: ${st.action} needs ${k}`);
    } else if (st.lookup !== undefined) {
      if (!tools[st.lookup]) out.push(`${n}: choose a lookup`);
      if (!st.as) out.push(`${n}: name the lookup's result`);
    } else if (st.close && !st.disposition) out.push(`${n}: a closing step needs an outcome`);
  });
  return out;
}

function playbookBuilder(p, cat) {
  const wrap = h("div", { class: "playbook" });
  const acts = Object.fromEntries(cat.actions.map((a) => [a.name, a]));
  const tools = Object.fromEntries((cat.tools || []).map((t) => [t.name, t]));
  const kindOf = (st) => (st.action !== undefined ? "action" : st.lookup !== undefined ? "lookup" : "close");
  const draw = () => {
    const steps = p.playbook || [];
    const paramFields = (schema, values, onset) => Object.entries(schema || {}).map(([raw, typ]) => {
      const key = raw.replace(/\?$/, ""), optional = raw.endsWith("?");
      return h("label", { class: "pf" }, h("span", { class: "small" }, key, optional ? h("span", { class: "faint" }, " (optional)") : null,
        h("span", { class: "faint mono" }, ` ${typ}`)),
        h("input", { value: showValue(values?.[key]), placeholder: optional ? "" : "required",
          oninput: (e) => onset(key, e.target.value === "" ? undefined : (typ === "str" ? e.target.value : looseValue(e.target.value))) }));
    });
    const stepCard = (st, i) => {
      const kind = kindOf(st);
      const set = (patch) => { p.playbook[i] = { ...patch }; draw(); };
      const kindSel = select([["action", "Do an action"], ["lookup", "Look something up (read-only)"], ["close", "Close the case"]], kind, (v) => {
        const keep = { when: st.when, disposition: st.disposition };
        set(v === "action" ? { ...keep, action: "", params: {} } : v === "lookup" ? { ...keep, lookup: "", args: {}, as: "" }
          : { when: st.when, close: true, disposition: st.disposition || (p.disposition_codes || [])[0] || "" });
      });
      let main;
      if (kind === "action") {
        const options = [["", "choose…"], ...cat.actions.map((a) => [a.name, `${a.name} (${a.risk})`])];
        main = h("div", {}, select(options, st.action || "", (v) => {
          set({ ...st, action: v, params: {} });
          if (v && !(p.allowed_actions || []).includes(v)) p.allowed_actions = [...(p.allowed_actions || []), v];
        }), st.action && acts[st.action] ? h("div", { class: "small faint" }, acts[st.action].description) : null,
          h("div", { class: "pfs" }, paramFields(acts[st.action]?.params, st.params, (k, v) => {
            st.params = st.params || {}; if (v === undefined) delete st.params[k]; else st.params[k] = v; })));
      } else if (kind === "lookup") {
        const options = [["", "choose…"], ...(cat.tools || []).map((t) => [t.name, t.name])];
        main = h("div", {}, select(options, st.lookup || "", (v) => set({ ...st, lookup: v, args: {}, as: st.as || v.split(".").pop() })),
          st.lookup && tools[st.lookup] ? h("div", { class: "small faint" }, tools[st.lookup].description) : null,
          h("div", { class: "pfs" }, paramFields(tools[st.lookup]?.params, st.args, (k, v) => {
            st.args = st.args || {}; if (v === undefined) delete st.args[k]; else st.args[k] = v; }),
          h("label", { class: "pf" }, h("span", { class: "small" }, "keep the result as"),
            h("input", { value: st.as || "", placeholder: "e.g. stock", oninput: (e) => (st.as = e.target.value) }))));
      } else {
        main = h("div", { class: "small muted" }, "Finish without an action, with the outcome below.");
      }
      if (!condRows.has(st)) condRows.set(st, whenRows(st.when));
      const rows = condRows.get(st);
      const sync = () => { st.when = rowsToWhen(rows); };
      const whenBox = rows === null
        ? h("div", { class: "small" }, h("span", { class: "faint" }, "Only when (uses all/any/not; edit in YAML): "), h("span", { class: "mono" }, JSON.stringify(st.when)))
        : h("div", { class: "when" }, h("div", { class: "small faint" }, rows.length ? "Only when all of these hold:" : "Always runs."),
          rows.map((r, j) => h("div", { class: "wrow" },
            h("input", { value: r.path, placeholder: "facts.region or stock.available", oninput: (e) => { r.path = e.target.value.trim(); sync(); } }),
            select(WHEN_OPS, r.op, (v) => { r.op = v; sync(); draw(); }),
            ["exists", "empty", "missing", "not_empty"].includes(r.op) ? null : h("input", { value: showValue(r.value), placeholder: r.op === "in" || r.op === "not_in" ? '["a","b"]' : "value",
              oninput: (e) => { r.value = looseValue(e.target.value); sync(); } }),
            h("button", { class: "ghost small", title: "Remove condition", onclick: () => { rows.splice(j, 1); sync(); draw(); } }, "×"))),
          h("button", { class: "ghost small", onclick: () => { rows.push({ path: "", op: "eq", value: "" }); draw(); } }, "+ condition"));
      const codes = p.disposition_codes || [];
      const disp = kind === "close" || st.disposition !== undefined
        ? field(kind === "close" ? "Outcome" : "Outcome when this step runs", select([["", kind === "close" ? "choose…" : "(the case's usual outcome)"], ...codes.map((c) => [c, c]),
          ...(st.disposition && !codes.includes(st.disposition) ? [[st.disposition, st.disposition]] : [])], st.disposition || "", (v) => { if (v) st.disposition = v; else delete st.disposition; }))
        : h("button", { class: "ghost small", onclick: () => { st.disposition = ""; draw(); } }, "+ outcome code");
      return h("div", { class: "step card" },
        h("div", { class: "row" }, h("b", {}, `${i + 1}`), kindSel, h("span", { class: "spacer" }),
          h("button", { class: "ghost small", disabled: i === 0, title: "Move up", onclick: () => { [steps[i - 1], steps[i]] = [steps[i], steps[i - 1]]; draw(); } }, "↑"),
          h("button", { class: "ghost small", disabled: i === steps.length - 1, title: "Move down", onclick: () => { [steps[i + 1], steps[i]] = [steps[i], steps[i + 1]]; draw(); } }, "↓"),
          h("button", { class: "ghost small danger", title: "Remove step", onclick: () => { steps.splice(i, 1); draw(); } }, "Remove")),
        main, whenBox, disp);
    };
    wrap.replaceChildren(
      steps.length ? h("div", { class: "pb-steps" }, steps.map((st, i) => stepCard(st, i))) : h("div", { class: "small faint" }, "No playbook: people (or the model) decide the steps."),
      h("div", { class: "row", style: "margin-top:6px" },
        h("button", { onclick: () => { p.playbook = [...steps, { action: "", params: {} }]; draw(); } }, "+ Action"),
        h("button", { onclick: () => { p.playbook = [...steps, { lookup: "", args: {}, as: "" }]; draw(); } }, "+ Lookup"),
        h("button", { onclick: () => { p.playbook = [...steps, { close: true, disposition: (p.disposition_codes || [])[0] || "" }]; draw(); } }, "+ Close")));
  };
  const condRows = new WeakMap();      // condition rows per step, including ones still being typed
  draw();
  return wrap;
}

// ---- people & roles
PAGES.people = async () => {
  const [dir, cat] = await Promise.all([api("/console/api/directory"), catalogue()]);
  const doc = await pendingDoc("people");
  doc.roles = doc.roles || {}; doc.people = doc.people || []; doc.assignments = doc.assignments || []; doc.authority = doc.authority || [];
  const roleIds = Object.keys(doc.roles);
  const kids = (parent) => roleIds.filter((r) => (doc.roles[r]?.parent || null) === parent);
  const tree = h("div", { class: "tree" });
  const walk = (rid, depth) => {
    const people = doc.assignments.filter((a) => a.role_id === rid);
    tree.append(h("div", { class: "node", style: `padding-left:${8 + depth * 22}px` }, h("span", { class: "guide" }, depth ? "└" : ""),
      h("b", {}, doc.roles[rid]?.name || rid), h("span", { class: "mono small faint" }, rid),
      people.map((a) => h("span", { class: "chip" }, a.person_id, Object.keys(a.scope || {}).length ? ` · ${kvText(a.scope).replace(/\n/g, ", ")}` : "")),
      h("span", { class: "spacer" }),
      h("button", { class: "ghost small", onclick: () => roleForm(doc, rid) }, "Edit")));
    kids(rid).forEach((k) => walk(k, depth + 1));
  };
  kids(null).forEach((r) => walk(r, 0));
  const peopleRows = doc.people.map((p) => h("tr", { class: "click", onclick: () => personForm(doc, p.id, cat) },
    h("td", {}, h("b", {}, p.name || p.id), h("div", { class: "mono small faint" }, p.id)),
    h("td", { class: "small" }, doc.assignments.filter((a) => a.person_id === p.id).map((a) =>
      h("div", {}, a.role_id, Object.keys(a.scope || {}).length ? h("span", { class: "faint" }, ` (${kvText(a.scope).replace(/\n/g, ", ")})`) : ""))),
    h("td", { class: "small" }, (p.edges || []).join(", ") || h("span", { class: "faint" }, "default")),
    h("td", {}, p.active === false ? h("span", { class: "badge b-plain" }, "inactive") : h("span", { class: "badge b-ok" }, "active"))));
  const authRows = doc.authority.map((r, i) => h("tr", {},
    h("td", { class: "small" }, r.role_id), h("td", { class: "mono small" }, r.action),
    h("td", { class: "small" }, r.level || "approve"), h("td", { class: "small" }, r.max_amount ?? h("span", { class: "faint" }, "no limit")),
    h("td", {}, h("button", { class: "ghost danger", onclick: () => { doc.authority.splice(i, 1); recordChange("people", `removed ${r.role_id} ${r.action}`); route(); } }, "Remove"))));
  shell("people", "People & roles", dir.open_mode ? "No people configured yet: everyone can do everything (open mode)" : "Who sees which queues, and who may approve what", [
    h("button", { onclick: () => yamlEditor("people") }, "Edit as YAML"),
    h("button", { onclick: () => roleForm(doc, null) }, "Add role"),
    h("button", { class: "primary", onclick: () => personForm(doc, null, cat) }, "Add person"),
  ], [
    h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h2", {}, "Role tree"), h("div", { class: "small muted", style: "margin-bottom:8px" }, "A role sees the queues of every role below it and inherits their authority."),
        roleIds.length ? tree : h("div", { class: "empty" }, "No roles yet.")),
      h("div", { class: "card", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "People")),
        h("table", {}, h("thead", {}, h("tr", {}, ["Person", "Roles (scope)", "Channels", ""].map((t) => h("th", {}, t)))), h("tbody", {}, peopleRows)))),
    h("div", { class: "card section", style: "padding:0" },
      h("div", { class: "row", style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Approval authority"), h("span", { class: "spacer" }),
        h("button", { onclick: () => authorityForm(doc, cat) }, "Add rule")),
      h("table", {}, h("thead", {}, h("tr", {}, ["Role", "Action", "Level", "Up to amount", ""].map((t) => h("th", {}, t)))), h("tbody", {}, authRows))),
  ]);
};

function roleForm(doc, rid) {
  const r = rid ? { id: rid, ...clone(doc.roles[rid]) } : { id: "", name: "", parent: "" };
  const others = Object.keys(doc.roles).filter((x) => x !== rid);
  const id = h("input", { value: r.id, disabled: rid ? "disabled" : null, placeholder: "e.g. inventory_controller" });
  const name = h("input", { value: r.name || "" });
  let parent = r.parent || "";
  drawer(rid ? `Role ${rid}` : "Add role", h("div", {}, field("Id", id), field("Name", name),
    field("Reports to", select([["", "nobody (top of the tree)"], ...others], parent, (v) => (parent = v)))), (close) => [
    rid ? h("button", { class: "danger", style: "margin-right:auto", onclick: () => {
      delete doc.roles[rid];
      doc.assignments = doc.assignments.filter((a) => a.role_id !== rid);
      doc.authority = doc.authority.filter((a) => a.role_id !== rid);
      recordChange("people", `removed role ${rid}`); close(); route();
    } }, "Remove role") : null,
    h("button", { onclick: close }, "Cancel"),
    h("button", { class: "primary", onclick: () => {
      const key = rid || id.value.trim();
      if (!/^[a-z0-9_]+$/.test(key)) return toast("Role id: lowercase letters, digits, underscores", true);
      doc.roles[key] = { name: name.value.trim() || undefined, ...(parent ? { parent } : {}) };
      recordChange("people", rid ? `edited role ${key}` : `added role ${key}`); close(); route();
    } }, "Keep change")]);
}

function personForm(doc, pid, cat) {
  const p = pid ? clone(doc.people.find((x) => x.id === pid)) : { id: "", name: "", edges: [] };
  const mine = doc.assignments.filter((a) => a.person_id === pid).map(clone);
  const id = h("input", { value: p.id, disabled: pid ? "disabled" : null, placeholder: "e.g. priya" });
  const name = h("input", { value: p.name || "" });
  const edges = h("input", { value: (p.edges || []).join(", "), placeholder: cat.edges.join(", ") || "ask_ai, whatsapp" });
  const active = h("input", { type: "checkbox", checked: p.active !== false, style: "width:auto" });
  const LANGS = [["", "English"], ["hi", "हिन्दी Hindi"], ["ta", "தமிழ் Tamil"], ["te", "తెలుగు Telugu"], ["kn", "ಕನ್ನಡ Kannada"],
    ["mr", "मराठी Marathi"], ["bn", "বাংলা Bengali"], ["gu", "ગુજરાતી Gujarati"], ["ml", "മലയാളം Malayalam"], ["pa", "ਪੰਜਾਬੀ Punjabi"]];
  let language = p.language || "";
  const langSel = select(LANGS, language, (v) => (language = v));
  const roles = Object.keys(doc.roles);
  const list = h("div", {});
  const renderAssignments = () => list.replaceChildren(...mine.map((a, i) => h("div", { class: "row", style: "margin-bottom:6px" },
    select(roles, a.role_id, (v) => (a.role_id = v), { style: "width:auto" }),
    h("input", { value: kvText(a.scope).replace(/\n/g, ", "), placeholder: "scope, e.g. location=WH_CHN (empty = everywhere)", style: "flex:1;width:auto",
      oninput: (e) => (a.scope = parseKv(e.target.value)) }),
    h("button", { class: "ghost danger", onclick: () => { mine.splice(i, 1); renderAssignments(); } }, "✕"))),
  h("button", { onclick: () => { mine.push({ role_id: roles[0], scope: {} }); renderAssignments(); } }, "Add role"));
  renderAssignments();
  drawer(pid ? (p.name || pid) : "Add person", h("div", {}, field("Id", id, "Used in tokens and the audit trail."), field("Name", name),
    field("Roles and scope", list, "An incident outside someone's scope (e.g. another location) is not shown to them."),
    field("Channels for review cards", edges, `In order of preference. Configured: ${cat.edges.join(", ") || "none"}.`),
    field("Language for review cards", langSel, "Cards on WhatsApp, Slack, Teams, email and the phone page. The case's own text is translated by the model when one is configured."),
    h("label", { class: "row", style: "font-weight:500" }, active, " Active")), (close) => [
    h("button", { onclick: close }, "Cancel"),
    h("button", { class: "primary", onclick: () => {
      const key = pid || id.value.trim();
      if (!/^[A-Za-z0-9_.-]+$/.test(key)) return toast("Person id: letters, digits, _ . -", true);
      if (!pid && doc.people.some((x) => x.id === key)) return toast("That id is already used", true);
      const person = { id: key, name: name.value.trim() || undefined, edges: edges.value.split(",").map((s) => s.trim()).filter(Boolean) };
      if (!person.edges.length) delete person.edges;
      if (!active.checked) person.active = false;
      person.language = language || undefined;
      if (pid) {
        const merged = { ...p, ...person, ...(active.checked ? { active: undefined } : {}) };
        for (const k of Object.keys(merged)) if (merged[k] === undefined) delete merged[k];
        doc.people[doc.people.findIndex((x) => x.id === pid)] = merged;
      } else {
        if (!person.language) delete person.language;
        doc.people.push(person);
      }
      doc.assignments = doc.assignments.filter((a) => a.person_id !== key)
        .concat(mine.map((a) => ({ person_id: key, role_id: a.role_id, ...(Object.keys(a.scope || {}).length ? { scope: a.scope } : {}) })));
      recordChange("people", pid ? `edited ${key}` : `added ${key}`); close(); route();
    } }, "Keep change")]);
}

function authorityForm(doc, cat) {
  const r = { role_id: Object.keys(doc.roles)[0], action: (cat.actions[0] || {}).name, level: "approve" };
  const amount = h("input", { type: "number", min: 0, placeholder: "no limit" });
  const actions = [...cat.actions.map((a) => [a.name, `${a.name} (${a.risk})`]),
    ["__configure__", "publish configuration"], ["__promote__", "approve promotions"], ["__set_route__", "raise a route"],
    ["__kill_switch__", "lower a route (kill switch)"], ["__reverse__", "reverse a fix"], ["*", "every action"]];
  drawer("Add approval rule", h("div", {},
    field("Role", select(Object.keys(doc.roles), r.role_id, (v) => (r.role_id = v))),
    field("May", select(actions, r.action, (v) => (r.action = v))),
    field("Level", select([["approve", "approve and do it"], ["propose", "only propose (someone above approves)"]], "approve", (v) => (r.level = v))),
    field("Up to amount", amount, "For money actions (refunds): above this, it goes to a higher role.")), (close) => [
    h("button", { onclick: close }, "Cancel"),
    h("button", { class: "primary", onclick: () => {
      const rule = { role_id: r.role_id, action: r.action };
      if (r.level !== "approve") rule.level = r.level;
      if (amount.value !== "") rule.max_amount = Number(amount.value);
      doc.authority.push(rule);
      recordChange("people", `${r.role_id} may ${r.level} ${r.action}`); close(); route();
    } }, "Keep change")]);
}

// ---- YAML editor (any kind)
async function yamlEditor(kind, presetText, presetNote) {
  const cfg = await api(`/console/api/config/${kind}`);
  const ta = h("textarea", { class: "code", spellcheck: "false" }, presetText ?? cfg.text);
  const out = h("div", {});
  const note = h("input", { placeholder: "What changed and why", value: presetNote || "" });
  const check = async () => {
    const r = await api(`/console/api/config/${kind}/check`, { body: { text: ta.value } });
    out.replaceChildren(problemsList(r.problems), h("div", { style: "height:10px" }), diffView(r.diff));
    return r;
  };
  const save = async (publish) => {
    try {
      const r = await api(`/console/api/config/${kind}/drafts`, { body: { text: ta.value, note: note.value } });
      if (publish) {
        await api(`/console/api/config/versions/${r.version.id}/publish`, { body: {} });
        toast(`${kind} v${r.version.version} published`);
      } else toast(`Saved ${kind} v${r.version.version} as a draft`);
      if (kind !== "models") discard(kind);
      location.hash = `#/changes?kind=${kind}`;
    } catch (e) { showError(e); }
  };
  const title = `${KIND_LABEL[kind]} (YAML)`;
  shell({ models: "models", people: "people", connectors: "connectors", metrics: "metrics" }[kind] || "exceptions", title,
    cfg.active ? `Editing from v${cfg.active.version} (published)` : "Editing the overlay's own configuration", [
      h("button", { onclick: check }, "Check"),
      h("button", { onclick: () => save(false) }, "Save draft"),
      h("button", { class: "primary", disabled: canConfigure() ? null : "disabled", onclick: () => save(true) }, "Save and publish"),
    ], h("div", { class: "grid g2" }, h("div", {}, ta, h("div", { style: "margin-top:10px" }, field("Note", note))),
      h("div", { class: "card" }, h("h2", {}, "Check"), out)));
  check();
}

// ---- models
PAGES.models = async () => {
  const [cfg, learn] = await Promise.all([api("/console/api/config/models"), api("/console/api/learning")]);
  const usage = Object.entries(learn.models || {});
  shell("models", "Models", "Which model handles which exceptions, fallbacks, escalation and the embedder", [
    h("button", { class: "primary", onclick: () => yamlEditor("models") }, "Edit models"),
  ], h("div", { class: "grid g2" },
    h("div", { class: "card" }, h("h2", {}, cfg.active ? `Running v${cfg.active.version}` : "Running the models file given at start"),
      cfg.text ? h("pre", { class: "diff" }, cfg.text) : h("div", { class: "empty" }, "No models configured: model steps go to people. Edit models to add Claude and a local model.")),
    h("div", { class: "card" }, h("h2", {}, "Usage since this process started"),
      usage.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Task : model", "Calls", "Errors", "Avg ms", "Agreement"].map((t, i) => h("th", { class: i ? "num" : null }, t)))),
        h("tbody", {}, usage.map(([k, v]) => h("tr", {}, h("td", { class: "mono small" }, k), h("td", { class: "num" }, v.calls),
          h("td", { class: "num" }, v.errors), h("td", { class: "num" }, v.avg_latency_ms), h("td", { class: "num" }, pct(v.agreement))))))
        : h("div", { class: "empty" }, "No model calls yet."))));
};

// ---- data sources & tools
PAGES.connectors = async () => {
  const [c, cfg, tpls] = await Promise.all([api("/console/api/connectors"), api("/console/api/config/connectors"),
    api("/console/api/connector-templates").catch(() => [])]);
  const addTemplate = async (name) => {
    const t = await api(`/console/api/connector-templates/${encodeURIComponent(name)}`);
    const doc = await pendingDoc("connectors");
    const clash = [];
    for (const [sec, items] of Object.entries(t.connectors)) {
      doc[sec] = doc[sec] || {};
      for (const k of Object.keys(items)) if (k in doc[sec]) clash.push(`${sec}.${k}`);
    }
    if (clash.length) return toast(`Already there: ${clash.join(", ")}`, true);
    for (const [sec, items] of Object.entries(t.connectors)) Object.assign(doc[sec], items);
    recordChange("connectors", `added the ${t.summary.title} connector`);
    modal(`${t.summary.title} added to the draft`, h("div", {},
      h("p", {}, "Set these on the server (environment variables), then review and publish the draft:"),
      h("table", {}, h("tbody", {}, Object.entries(t.summary.settings).map(([k, v]) => h("tr", {}, h("td", { class: "mono small" }, k), h("td", { class: "small" }, v))))),
      h("p", { class: "small muted" }, `Its events (${t.summary.events.join(", ")}) need fingerprint rules and exceptions in the registry; suggested fingerprints: ${t.summary.fingerprints.map((f) => f.event_type).join(", ")}.`)),
      [(close) => h("button", { class: "primary", onclick: () => { close(); route(); } }, "OK")]);
  };
  const srcRows = c.sources.map((s) => h("tr", {},
    h("td", {}, h("b", { class: "mono" }, s.name), s.enabled ? null : h("span", { class: "badge b-plain" }, "off")),
    h("td", {}, h("span", { class: "badge b-plain" }, s.kind), s.signed ? h("span", { class: "badge b-ok" }, "signed") : null),
    h("td", { class: "small" }, s.emits.map((t) => h("span", { class: "chip" }, t))),
    h("td", { class: "small" }, s.kind === "webhook" ? h("span", { class: "mono faint" }, s.signed ? `/v1/hooks/${s.name}` : `/v1/sources/${s.name}`) : `every ${s.every_s}s`),
    h("td", { class: "small" }, s.state.last_run ? `${when(s.state.last_run)} · ${s.state.last_events ?? 0} events` : h("span", { class: "faint" }, "–"),
      s.state.last_error ? h("div", { class: "badge b-bad", title: s.state.last_error }, "last fetch failed") : null),
    h("td", {}, s.kind === "webhook"
      ? h("button", { onclick: () => tryPayload(s.name) }, "Try a payload")
      : h("button", { disabled: canConfigure() ? null : "disabled", onclick: async () => {
        try { const r = await api(`/console/api/sources/${s.name}/poll`, { body: {} }); toast(`Fetched: ${r.events} events, ${r.new} new`); route(); }
        catch (e) { toast(e.message, true); }
      } }, "Fetch now"))));
  const mcpRows = c.mcp.map((m) => h("tr", {},
    h("td", {}, h("b", { class: "mono" }, m.name)), h("td", {}, h("span", { class: "badge b-plain" }, m.transport)),
    h("td", { class: "small" }, m.tools.map((t) => h("span", { class: `chip` }, `${m.name}.${t}`, m.usable && !m.usable.includes(t) ? " ✕" : ""))),
    h("td", {}, h("button", { onclick: async () => {
      try { const r = await api(`/console/api/mcp/${m.name}/test`, { body: {} });
        modal(`MCP ${m.name}`, h("div", {}, h("p", {}, `Usable as read-only lookups: ${r.usable.join(", ") || "none"}`), problemsList(r.problems)),
          [(close) => h("button", { onclick: close }, "Close")]);
      } catch (e) { toast(e.message, true); }
    } }, "Test"))));
  shell("connectors", "Data sources & tools", "Where events come from, and which systems the model may look things up in", [
    h("button", { class: "primary", onclick: () => yamlEditor("connectors") }, "Edit connectors"),
  ], [
    h("div", { class: "card", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Data sources"),
      h("div", { class: "small muted" }, "Webhooks, polled APIs and database tables, mapped to events by configuration.",
        c.receivers.length ? ` The overlay also provides: ${c.receivers.join(", ")}.` : "")),
      c.sources.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Source", "Kind", "Raises", "Endpoint / schedule", "Last fetch", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, srcRows)) : h("div", { class: "empty", style: "margin:16px" }, "No configured sources yet. Edit connectors to add a webhook, an API to poll or a table to read.")),
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Lookup tools from MCP servers"),
      h("div", { class: "small muted" }, "Only allowlisted tools that do not change data are exposed; changes go through actions.")),
      c.mcp.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Server", "Transport", "Tools", ""].map((t) => h("th", {}, t)))), h("tbody", {}, mcpRows))
        : h("div", { class: "empty", style: "margin:16px" }, "No MCP servers configured.")),
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Actions defined here"),
      h("div", { class: "small muted" }, "HTTP calls Sentinel may make to change things in your systems. They follow the same guardrails, approvals and limits as the overlay's own actions; one with an undo can be reversed.")),
      (c.actions || []).length ? h("table", {}, h("thead", {}, h("tr", {}, ["Action", "Calls", "Params", "Risk"].map((t) => h("th", {}, t)))),
        h("tbody", {}, c.actions.map((a) => h("tr", {}, h("td", {}, h("b", { class: "mono" }, a.name), a.description ? h("div", { class: "small faint" }, a.description) : null),
          h("td", { class: "small mono" }, `${a.method} ${a.host}`), h("td", { class: "small mono" }, Object.entries(a.params).map(([k, v]) => `${k}: ${v}`).join(", ") || "–"),
          h("td", {}, h("span", { class: `badge ${a.reversible ? "b-ok" : a.safe ? "b-info" : "b-bad"}` }, a.reversible ? "reversible" : a.safe ? "safe" : "irreversible"))))))
        : h("div", { class: "empty", style: "margin:16px" }, "None: every action comes from the overlay's code. Add actions under connectors to call an API without code.")),
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Where review cards go"),
      h("div", { class: "small muted" }, "Edges deliver review cards to people (Ask AI, WhatsApp, webhooks); answers come back signed and go through the same approval rules.")),
      (c.edges || []).length ? h("table", {}, h("thead", {}, h("tr", {}, ["Edge", "Kind", "Answers arrive at", "People who prefer it"].map((t) => h("th", {}, t)))),
        h("tbody", {}, c.edges.map((e) => h("tr", {}, h("td", {}, h("b", { class: "mono" }, e.name), e.from === "overlay" ? h("span", { class: "badge b-plain" }, "overlay") : null),
          h("td", {}, h("span", { class: "badge b-plain" }, e.kind)), h("td", { class: "small mono faint" }, e.answers_at),
          h("td", { class: "small" }, e.people.join(", ") || h("span", { class: "faint" }, "–"))))))
        : h("div", { class: "empty", style: "margin:16px" }, "No edges: people work reviews in this console. Add edges under connectors to reach them on Ask AI or WhatsApp.")),
    tpls.length ? h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Ready-made connectors"),
      h("div", { class: "small muted" }, "Login, data sources, lookups and actions for common systems, added to the draft for you to review. Check the fields against your account before going live.")),
      h("table", {}, h("thead", {}, h("tr", {}, ["System", "Raises", "Lookups", "Actions", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, tpls.map((t) => h("tr", {}, h("td", {}, h("b", {}, t.title), h("div", { class: "small faint" }, t.description)),
          h("td", { class: "small" }, t.events.map((e) => h("span", { class: "chip" }, e))),
          h("td", { class: "small mono" }, t.lookups.join(", ") || "–"),
          h("td", { class: "small" }, Object.entries(t.actions).map(([n, r]) => h("div", {}, h("span", { class: "mono" }, n), " ", h("span", { class: `badge ${r === "reversible" ? "b-ok" : r === "safe" ? "b-info" : "b-bad"}` }, r)))),
          h("td", {}, canConfigure() ? h("button", { onclick: () => addTemplate(t.name).catch(showError) }, "Add to draft") : null)))))) : null,
    cfg.active ? null : h("p", { class: "small muted section" }, "Nothing published yet for connectors."),
  ]);
};

PAGES.access = async () => {
  if (!S.me.can?.__access__) {
    return shell("access", "Access", "Tokens for people and systems", null,
      h("div", { class: "card" }, h("p", {}, "Giving and revoking access needs the __access__ right. Ask whoever runs Sentinel for you.")));
  }
  const [toks, dir] = await Promise.all([api("/console/api/access/tokens"), api("/console/api/directory").catch(() => null)]);
  const people = (dir?.people || []).filter((p) => p.active !== false).map((p) => [p.id, p.name ? `${p.name} (${p.id})` : p.id]);
  const status = (t) => h("span", { class: `badge ${t.status === "active" ? "b-ok" : "b-plain"}` }, t.status);
  const rows = toks.map((t) => h("tr", {},
    h("td", {}, h("b", {}, t.principal), h("div", { class: "small faint mono" }, t.id)),
    h("td", {}, h("span", { class: "badge b-plain" }, t.kind), t.source === "sso" ? h("span", { class: "badge b-info" }, "sign-on session") : null),
    h("td", { class: "small" }, t.label || h("span", { class: "faint" }, "–")),
    h("td", { class: "small" }, `${when(t.created_at)} by ${t.created_by || "–"}`),
    h("td", { class: "small" }, t.expires_at ? when(t.expires_at) : h("span", { class: "faint" }, "never")),
    h("td", { class: "small" }, t.last_used_at ? when(t.last_used_at) : h("span", { class: "faint" }, "not yet")),
    h("td", {}, status(t)),
    h("td", {}, t.status === "active" ? h("button", { class: "danger", onclick: async () => {
      try { await api(`/console/api/access/tokens/${encodeURIComponent(t.id)}/revoke`, { body: {} }); toast(`Revoked ${t.principal}'s token`); route(); }
      catch (e) { toast(e.message, true); }
    } }, "Revoke") : null)));
  shell("access", "Access", "Tokens for people (console, reviews) and systems (sending events). Each token is shown once.", [
    h("button", { class: "primary", onclick: () => giveToken(people) }, "Give access"),
  ], h("div", { class: "card", style: "padding:0" }, toks.length
    ? h("table", {}, h("thead", {}, h("tr", {}, ["Who", "Kind", "Label", "Given", "Expires", "Last used", "Status", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows))
    : h("div", { class: "empty", style: "margin:16px" }, "No tokens given from the console yet. Tokens in the tokens file are not listed here.")));
};

function giveToken(people) {
  const f = { kind: "person", principal: people[0]?.[0] || "", label: "", days: 90 };
  const who = h("div", {});
  const drawWho = () => who.replaceChildren(f.kind === "person" && people.length
    ? field("Person", select(people, f.principal, (v) => (f.principal = v), { id: "tok-person" }))
    : field(f.kind === "person" ? "Person id" : "System name", h("input", { id: "tok-principal", value: f.principal, placeholder: f.kind === "person" ? "e.g. priya" : "e.g. shopify-webhooks", oninput: (e) => (f.principal = e.target.value) })));
  drawWho();
  const body = h("div", {},
    field("For", select([["person", "a person (console and reviews)"], ["service", "a system (sends events)"]], f.kind, (v) => {
      f.kind = v; f.principal = v === "person" ? (people[0]?.[0] || "") : ""; drawWho(); }, { id: "tok-kind" })),
    who,
    field("Label", h("input", { id: "tok-label", placeholder: "e.g. laptop, Shopify webhooks", oninput: (e) => (f.label = e.target.value) })),
    field("Expires after (days, empty for never)", h("input", { id: "tok-days", type: "number", min: 1, value: f.days, oninput: (e) => (f.days = e.target.value ? Number(e.target.value) : null) })));
  modal("Give access", body, [
    (close) => h("button", { onclick: close }, "Cancel"),
    (close) => h("button", { class: "primary", id: "tok-give", onclick: async () => {
      try {
        const t = await api("/console/api/access/tokens", { body: f });
        close();
        modal("Token for " + t.principal, h("div", {},
          h("p", {}, "Copy it now and pass it on privately. It will not be shown again."),
          h("pre", { class: "diff mono", id: "tok-value", style: "white-space:pre-wrap;word-break:break-all" }, t.token)),
          [(c2) => h("button", { onclick: () => { navigator.clipboard?.writeText(t.token).catch(() => {}); toast("Copied"); } }, "Copy"),
           (c2) => h("button", { class: "primary", onclick: () => { c2(); route(); } }, "Done")]);
      } catch (e) { toast(e.message, true); }
    } }, "Give access"),
  ]);
}

function tryPayload(name) {
  const ta = h("textarea", { class: "code", style: "min-height:180px", placeholder: '{"id": 1, ...}' });
  const out = h("div", {});
  modal(`Try a payload on ${name}`, h("div", {}, field("Webhook body (JSON)", ta), out), [
    (close) => h("button", { onclick: close }, "Close"),
    () => h("button", { class: "primary", onclick: async () => {
      let body; try { body = JSON.parse(ta.value || "{}"); } catch { return toast("The body must be valid JSON", true); }
      try {
        const r = await api(`/console/api/sources/${name}/try`, { body: { body } });
        out.replaceChildren(r.events.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Event", "Key", "Facts", "Exception"].map((t) => h("th", {}, t)))),
          h("tbody", {}, r.events.map((e) => h("tr", {}, h("td", { class: "mono small" }, e.type), h("td", { class: "mono small" }, e.key || "–"),
            h("td", {}, Object.entries(e.facts).map(([k, v]) => h("span", { class: "chip" }, `${k}=${v}`))), h("td", { class: "mono small" }, e.pattern)))))
          : h("div", { class: "empty" }, "No events: the conditions did not match this payload."));
      } catch (e) { out.replaceChildren(h("ul", { class: "problems" }, h("li", { class: "error" }, e.message))); }
    } }, "Map it (nothing is saved)"),
  ]);
}

// ---- changes (versions)
PAGES.changes = async (q) => {
  const kind = q.get("kind") || "registry";
  const cfg = await api(`/console/api/config/${kind}`);
  const detail = h("div", { class: "card" }, h("div", { class: "empty" }, "Pick a version to see what it changes."));
  const show = async (v) => {
    const r = await api(`/console/api/config/versions/${v.id}`);
    const isActive = cfg.active && cfg.active.id === v.id;
    detail.replaceChildren(
      h("div", { class: "row" }, h("h2", { style: "margin:0" }, `${kind} v${v.version}`), statusBadge(v.status), h("span", { class: "spacer" }),
        h("button", { onclick: () => yamlEditor(kind, r.text, `based on v${v.version}`) }, "Edit a copy"),
        kind === "registry" && canConfigure() && !isActive ? h("button", { onclick: () => replayView(r.text, `v${v.version}`) }, "Replay last 30 days") : null,
        v.status === "draft" && v.requested_by && v.author !== S.me?.id && canConfigure() ? h("button", { class: "primary", onclick: async () => {
          try {
            const res = await api(`/console/api/config/versions/${v.id}/approve`, { body: {} });
            toast(res.published.length ? `Approved and published` : "Approved; still waiting for more approvals");
            route();
          } catch (e) { showError(e); }
        } }, "Approve and publish") : null,
        !isActive ? h("button", { class: "primary", disabled: canConfigure() ? null : "disabled", onclick: async () => {
          try {
            const res = await api(`/console/api/config/versions/${v.id}/publish`, { body: {} });
            if (res.waiting) toast("Waiting for approval by someone else who can configure");
            else toast(v.status === "draft" ? `v${res.version.version} published` : `Rolled back: v${v.version} republished as v${res.version.version}`);
            route();
          } catch (e) { showError(e); }
        } }, v.status === "draft" ? "Publish" : "Roll back to this") : null),
      h("div", { class: "kv", style: "margin:12px 0" }, h("div", {}, "Saved by"), h("div", {}, `${v.author} · ${when(v.created_at)}`),
        h("div", {}, "Note"), h("div", {}, v.note || "–"),
        v.requested_by ? [h("div", {}, "Approval"), h("div", {}, `asked by ${v.requested_by}; approved by ${(v.approvals || []).join(", ") || "nobody yet"}`)] : null,
        v.published_by ? [h("div", {}, "Published by"), h("div", {}, `${v.published_by} · ${when(v.published_at)}`)] : null,
        h("div", {}, "Checksum"), h("div", { class: "mono" }, v.checksum)),
      h("h3", {}, "Checked against what is running now"), problemsList(r.problems),
      h("h3", { style: "margin-top:16px" }, "Compared with what is running now"), diffView(r.diff));
  };
  const rows = cfg.versions.map((v) => h("tr", { class: "click", onclick: () => show(v) },
    h("td", {}, h("b", {}, `v${v.version}`)), h("td", {}, statusBadge(v.status === "draft" && v.requested_by ? "awaiting approval" : v.status)),
    h("td", { class: "small" }, v.author), h("td", { class: "small muted" }, v.note || ""), h("td", { class: "small muted" }, when(v.created_at))));
  shell("changes", "Changes", "Every saved version; publish a draft or roll back to an earlier version", [
    h("button", { onclick: () => yamlEditor(kind) }, `New ${kind} draft`)], [
    h("div", { class: "tabs" }, ["registry", "people", "connectors", "models", "metrics"].map((k) => h("button", { class: k === kind ? "on" : null,
      onclick: () => (location.hash = `#/changes?kind=${k}`) }, KIND_LABEL[k]))),
    h("div", { class: "grid g2" },
      h("div", { class: "card", style: "padding:0" }, cfg.versions.length ? h("table", {},
        h("thead", {}, h("tr", {}, ["Version", "Status", "By", "Note", "Saved"].map((t) => h("th", {}, t)))), h("tbody", {}, rows))
        : h("div", { class: "empty", style: "margin:16px" }, "No versions yet. The overlay's own files are running.")),
      detail)]);
  const first = cfg.versions.find((v) => v.status === "draft") || cfg.versions[0];
  if (first) show(first);
};

async function replayView(text, label) {
  const body = h("div", {}, h("div", { class: "empty" }, "Running the last 30 days of cases through both versions…"));
  modal(`What ${label} would change`, body, [(close) => h("button", { onclick: close }, "Close")]);
  try {
    const r = await api("/console/api/config/registry/replay?days=30", { body: { text } });
    if (r.error) return body.replaceChildren(h("p", {}, r.error), problemsList((r.problems || []).map((m) => ({ severity: "error", message: m }))));
    body.replaceChildren(
      h("p", {}, `${r.cases} cases from the last ${r.days} days: ${r.unchanged} would go the same way, `, h("b", {}, `${r.changed} would change`), "."),
      Object.keys(r.changes).length ? h("table", {}, h("tbody", {}, Object.entries(r.changes).map(([k, n]) => h("tr", {}, h("td", { class: "num" }, n), h("td", { class: "small mono" }, k))))) : null,
      r.examples.length ? h("details", {}, h("summary", { class: "small" }, `Examples (${r.examples.length})`),
        h("table", {}, h("tbody", {}, r.examples.map((x) => h("tr", {}, h("td", {}, h("a", { href: `#/case?id=${x.incident}` }, x.incident)),
          h("td", { class: "small" }, `${x.now.pattern} / ${x.now.outcome} → ${x.draft.pattern} / ${x.draft.outcome}`)))))) : null,
      h("p", { class: "small faint" }, "Grouping, suppression and the circuit breaker depend on what was open at the time and are left out."));
  } catch (e) { body.replaceChildren(h("p", {}, e.message)); }
}

// ---- value (ROI)
PAGES.value = async (q) => {
  const days = q.get("days") || "30";
  const [v, bench] = await Promise.all([api(`/console/api/value?days=${days}`), api("/console/api/benchmark").catch(() => ({ configured: false, rows: [] }))]);
  const money = (x) => `${v.currency === "INR" ? "₹" : v.currency + " "}${Math.round(x || 0).toLocaleString("en-IN")}`;
  const t = v.total;
  const tiles = h("div", { class: "grid g4" }, stat("Saved", money(t.money_saved), `${t.hours_saved} hours of people's time`),
    stat("Resolved automatically", t.automatic, t.automation_rate === null ? "" : `${pct(t.automation_rate)} of decided cases`),
    stat("Model cost", money(t.model_cost), "estimated"), stat("Net", money(t.net), `over ${v.days} days`));
  const max = Math.max(1, ...v.trend.map((w) => w.money_saved));
  const trend = h("div", { class: "card" }, h("h3", {}, "By week"), h("div", { style: "display:flex;gap:10px;align-items:end;height:140px" },
    v.trend.map((w) => h("div", { style: "flex:1;text-align:center" },
      h("div", { title: `${money(w.money_saved)} · ${w.automatic} automatic`, style: `height:${Math.round((w.money_saved / max) * 110)}px;background:var(--info);border-radius:4px 4px 0 0;min-height:2px` }),
      h("div", { class: "small faint", style: "margin-top:4px" }, w.week_starting.slice(5))))));
  const rows = v.patterns.filter((x) => x.cases || x.automatic || x.by_people).map((x) => h("tr", {},
    h("td", {}, x.pattern), h("td", { class: "num" }, x.cases), h("td", { class: "num" }, x.automatic), h("td", { class: "num" }, x.by_people),
    h("td", { class: "num" }, pct(x.automation_rate)), h("td", { class: "num" }, x.effort_minutes),
    h("td", { class: "num" }, money(x.money_saved)), h("td", { class: "num" }, money(x.model_cost)), h("td", { class: "num" }, h("b", {}, money(x.net))),
    h("td", { class: "num small" }, (x.expired || x.cleared_at_source) ? `${x.cleared_at_source} / ${x.expired}` : "–",
      x.tune ? h("div", { class: "badge b-warn", title: "Many of its cases were left alone until they cleared or expired: narrow its match, add clear_when, or shorten its expiry" }, "tune") : null)));
  shell("value", "Value", `What automatic resolutions saved: ${v.settings.default_minutes} min a case unless an exception says, at ${money(v.settings.hourly_cost)} an hour (set under value: in the people configuration)`,
    [select([["7", "7 days"], ["30", "30 days"], ["90", "90 days"]], days, (x) => (location.hash = `#/value?days=${x}`))],
    [tiles, trend, h("div", { class: "card", style: "padding:0" }, rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "Cases", "Automatic", "By people", "Automation", "Min/case", "Saved", "Model", "Net", "Cleared / expired"].map((x, i) => h("th", { class: i ? "num" : null }, x)))), h("tbody", {}, rows)) : h("div", { class: "empty", style: "margin:16px" }, "No decided cases in this period."))]);
};

// ---- privacy (DPDP)
PAGES.privacy = async () => {
  if (!(S.me.open_mode || S.me.can?.__privacy__)) {
    return shell("privacy", "Privacy", "A person's requests about their data", null,
      h("div", { class: "card" }, "Requests about personal data need the __privacy__ right."));
  }
  const id = h("input", { placeholder: "Phone, email or customer id, as it appears in orders", style: "min-width:320px" });
  const reason = h("input", { placeholder: "Request reference / reason (kept in the audit trail)", style: "min-width:320px" });
  const out = h("div", {});
  const find = async () => {
    try {
      const r = await api("/console/api/privacy/find", { body: { identifier: id.value } });
      out.replaceChildren(h("div", { class: "card" }, h("h3", {}, `${r.cases.length} case(s) mention it`),
        r.cases.length ? h("table", {}, h("tbody", {}, r.cases.map((c) => h("tr", {}, h("td", {}, h("a", { href: `#/case?id=${c.id}` }, c.id)), h("td", {}, c.pattern), h("td", {}, statusBadge(c.state)), h("td", { class: "small muted" }, when(c.created_at)))))) : null,
        h("div", { class: "row", style: "margin-top:12px" },
          h("button", { onclick: async () => {
            try {
              const doc = await api("/console/api/privacy/access", { body: { identifier: id.value, reason: reason.value } });
              const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" })), download: "access-request.json" });
              document.body.append(a); a.click(); a.remove(); toast("Access report downloaded");
            } catch (e) { toast(e.message, true); } } }, "Download what we hold (access request)"),
          r.cases.length ? h("button", { class: "danger", onclick: () => modal("Erase this person's data?", h("div", {},
            h("p", {}, `Their identifier and personal fields are overwritten in ${r.cases.length} case(s): events, facts, decisions, reviews and the audit trail. This cannot be undone.`),
            h("p", { class: "small" }, "Cases still being worked are left alone; erase again once they close. Archives and backups age out on their own schedule.")), [
            (close) => h("button", { onclick: close }, "Cancel"),
            (close) => h("button", { class: "danger", onclick: async () => {
              try { const e = await api("/console/api/privacy/erase", { body: { identifier: id.value, reason: reason.value } }); close();
                toast(`Erased from ${e.erased_cases.length} case(s)${e.skipped_open.length ? `; ${e.skipped_open.length} still open` : ""}`); find(); }
              catch (err) { toast(err.message, true); } } }, "Erase")]) }, "Erase (erasure request)") : null)));
    } catch (e) { out.replaceChildren(h("div", { class: "card" }, e.message)); }
  };
  shell("privacy", "Privacy", "Requests from people about their data (India's DPDP Act): what we hold, and erasing it", null, [
    h("div", { class: "card" }, field("Identifier", id), field("Reason", reason), h("button", { class: "primary", onclick: find }, "Find")), out,
    h("p", { class: "small faint" }, "Personal fields can also be removed automatically from closed cases after a set time (maintenance --pii-days). The breach runbook and the data processing agreement template are in docs/privacy.")]);
};

// ---- fleet
PAGES.fleet = async () => {
  const f = await api("/console/api/fleet");
  if (!f.enabled) return shell("fleet", "Fleet", "Every site, on one page", null, h("div", { class: "card small" },
    "The fleet view runs on KBGrid's own instance: set SENTINEL_FLEET to a fleet file listing the sites (see sentinel/fleet.py)."));
  const ago = (ts) => ts ? `${Math.round((Date.now() / 1000 - ts) / 3600)} h ago` : "never";
  const rows = f.sites.map((s) => h("tr", {},
    h("td", {}, h("b", {}, s.name), s.overlay ? h("div", { class: "small faint" }, s.overlay) : null),
    h("td", { class: "mono small" }, s.version || "–"),
    h("td", {}, s.reachable ? h("span", { class: `badge ${s.health === "ok" && !(s.problems || []).length ? "b-ok" : "b-bad"}` }, s.health) : h("span", { class: "badge b-bad" }, "unreachable"),
      s.error ? h("div", { class: "small faint" }, s.error) : null),
    h("td", { class: "small" }, s.licence ? `${s.licence.state}${s.licence.valid_until ? ` · until ${s.licence.valid_until}` : ""}` : s.reachable ? "not enforced" : "–"),
    h("td", { class: "small" }, s.reachable ? ago(s.last_backup) : "–"),
    h("td", { class: "num" }, s.open_reviews ?? "–"), h("td", { class: "num" }, s.reachable ? `${s.live}/${s.patterns}` : "–"),
    h("td", { class: "small" }, (s.flags || []).map((x) => h("span", { class: "badge b-plain", style: "margin-right:4px" }, x)),
      s.upgrade ? h("details", {}, h("summary", { class: "small" }, "Upgrade commands"), h("pre", { class: "code small" }, s.upgrade.join("\n"))) : null)));
  shell("fleet", "Fleet", `${f.summary.sites} site(s), ${f.summary.attention} need attention${f.target_version ? ` · target version ${f.target_version}` : ""}`, [h("button", { onclick: route }, "Refresh")],
    h("div", { class: "card", style: "padding:0" }, h("table", {}, h("thead", {}, h("tr", {}, ["Site", "Version", "Health", "Licence", "Last backup", "Open reviews", "Live", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows))));
};

// ---- agents & oversight (ADR-003/005)
const MODE_CLASS = { OFF: "b-plain", OBSERVE: "b-info", PROPOSE: "b-warn", ACT: "b-ok" };
const scroller = (el) => h("div", { style: "overflow-x:auto;max-width:100%" }, el);   // wide tables scroll in their card
const scopeText = (sc) => Object.entries(sc || {}).filter(([, v]) => v !== null && v !== undefined && v !== "")      // never "null"
  .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(", ") || "everywhere";

PAGES.agents = async () => {
  const [a, checks, incidents] = await Promise.all([api("/console/api/agents"), api("/console/api/spot-checks"),
    api("/console/api/agent-incidents")]);
  const role = (slot, r) => slot ? h("span", {}, h("span", { class: "mono small" }, slot), " → ", h("b", {}, r || "unbound")) : (r || "–");
  const templates = h("div", { class: "card", style: "padding:0;overflow-x:auto;max-width:100%" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Template", "Owner", "Escalation", "Ceiling", "Trust", "Scale", "Open", "Oversight"].map((x) => h("th", {}, x)))),
    h("tbody", {}, a.templates.map((t) => h("tr", {},
      h("td", {}, h("b", {}, t.id), t.capability ? h("div", { class: "small faint" }, t.capability) : null),
      h("td", {}, role(t.owner_slot, t.owner_role)), h("td", {}, role(t.escalation_slot, t.escalation_role)),
      h("td", {}, badgeRoute(t.max_route), t.shadow ? h("span", { class: "badge b-info", style: "margin-left:4px" }, "shadow") : null),
      h("td", { class: "small" }, t.trust_by.length ? `by ${t.trust_by.join(", ")}${t.trust_pool_min ? ` · pooled until ${t.trust_pool_min}` : ""}` : "one"),
      h("td", { class: "small" }, t.digest_above ? `digest past ${t.digest_above}` : "cards", t.money_fact ? h("div", { class: "faint" }, `ranked by ${t.money_fact}`) : null,
        t.spot_check_rate ? h("div", { class: "faint" }, `${Math.round(t.spot_check_rate * 100)}% spot-checked`) : null,
        t.claims && t.claims.length ? h("div", { class: "faint" }, `claims ${t.claims.join("+")}`) : null),
      h("td", { class: "num" }, t.open),
      h("td", { class: "small" }, t.overseers.length ? t.overseers.join(", ") : h("span", { class: "faint" }, "none")))))));
  const bindings = Object.keys(a.slots).length || Object.keys(a.slot_bindings).length ? h("div", { class: "card" },
    h("h3", {}, "Role slots"), h("p", { class: "small muted" }, "Templates name the job; this tenant binds each job to its own role."),
    scroller(h("table", {}, h("thead", {}, h("tr", {}, ["Slot", "What it is for", "Bound to"].map((x) => h("th", {}, x)))),
      h("tbody", {}, [...new Set([...Object.keys(a.slots), ...Object.keys(a.slot_bindings)])].map((k) => h("tr", {},
        h("td", { class: "mono" }, k), h("td", { class: "small" }, a.slots[k] || ""),
        h("td", {}, a.slot_bindings[k] ? h("b", {}, a.slot_bindings[k]) : h("span", { class: "badge b-bad" }, "unbound")))))))) : null;
  const policies = h("div", { class: "card" }, h("h3", {}, "Agent modes"),
    h("p", { class: "small muted" }, "Most specific row wins: a template beats its capability beats *, then more scope, then deeper scope; on a tie the least autonomous mode."),
    a.agents.length ? scroller(h("table", {}, h("thead", {}, h("tr", {}, ["Template", "Scope", "Mode", "Grants", "When"].map((x) => h("th", {}, x)))),
      h("tbody", {}, a.agents.map((p) => h("tr", {}, h("td", { class: "mono" }, p.template || "*"), h("td", { class: "small" }, scopeText(p.scope)),
        h("td", {}, h("span", { class: `badge ${MODE_CLASS[p.mode] || "b-plain"}` }, p.mode)),
        h("td", { class: "small" }, Object.entries(p.grants || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || h("span", { class: "faint" }, "limits only")),
        h("td", { class: "small" }, p.valid_from || p.valid_to ? `${p.valid_from || "…"} → ${p.valid_to || "…"}` : "always"))))))
      : h("div", { class: "small faint" }, "No agent modes configured: every template behaves as its route and shadow settings say."));
  const pat = select(a.templates.map((t) => t.id), a.templates[0]?.id, () => {}, { "aria-label": "Template" });
  const facts = h("input", { placeholder: "store=TVM01, category=rice", "aria-label": "Scope" });
  const out = h("div", { class: "small", style: "margin-top:8px" });
  const look = async () => {
    try {
      const r = await api("/console/api/agents/effective", { body: { pattern: pat.value, facts: parseKv(facts.value) } });
      out.replaceChildren(...[h("span", { class: "mono" }, r.agent), " · ",
        r.mode ? h("span", { class: `badge ${MODE_CLASS[r.mode]}` }, r.mode) : h("span", { class: "faint" }, "no policy"), " · route ", badgeRoute(r.route),
        r.shadow ? h("span", { class: "badge b-info", style: "margin-left:4px" }, "shadow") : null].filter(Boolean));
    } catch (e) { out.replaceChildren(h("span", { style: "color:var(--bad)" }, e.message)); }
  };
  const tester = h("div", { class: "card", style: "min-width:0" }, h("h3", {}, "Which mode applies here?"),
    h("div", { class: "row", style: "flex-wrap:wrap" }, pat, facts, h("button", { onclick: look }, "Look up")), out);
  const oversight = h("div", { class: "card" }, h("h3", {}, "Oversight"),
    a.oversight.length ? h("ul", { class: "small" }, a.oversight.map((o) => h("li", {}, h("b", {}, o.role), ` oversees ${o.templates.join(", ")}`)))
      : h("div", { class: "small faint" }, "No oversight role configured. Add one that owns none of the agents (People & roles)."),
    a.stop_at.length ? h("div", { class: "small muted" }, `Escalation never goes past: ${a.stop_at.join(", ")}`) : null,
    a.can_oversee ? oversightForm(a) : null);
  const binding = a.binding ? h("div", { class: "card" }, h("h3", {}, `Domain binding · ${a.binding.domain}`),
    h("div", { class: "small" }, "Never automated here: ", a.binding.never_automate.length ? a.binding.never_automate.map((x) => h("span", { class: "badge b-bad", style: "margin-right:4px" }, x)) : h("span", { class: "faint" }, "nothing stated as forbidden")),
    h("ul", { class: "small" }, a.binding.binds.map((b) => h("li", {}, h("b", {}, b.capability), ": ", Object.entries(b.map).map(([k, v]) => `${k} = ${v}`).join(", "))))) : null;
  const BAND = { ACT: "b-ok", PROPOSE: "b-warn", OBSERVE: "b-bad" };
  const trust = a.data_trust_rule ? h("div", { class: "card", style: "min-width:0" }, h("h3", {}, "Data trust by scope"),
    h("p", { class: "small muted" }, `Below ${a.data_trust_rule.act_min} agents there only propose; below ${a.data_trust_rule.propose_min} they only observe.`),
    a.data_trust.length ? scroller(h("table", {}, h("thead", {}, h("tr", {}, ["Scope", "Score", "Allows", "Source"].map((x) => h("th", {}, x)))),
      h("tbody", {}, [...a.data_trust].sort((x, y) => x.score - y.score).map((r) => h("tr", {}, h("td", { class: "mono small" }, scopeText(r.scope)),
        h("td", { class: "num" }, r.score.toFixed(2)), h("td", {}, h("span", { class: `badge ${BAND[r.band]}` }, r.band)), h("td", { class: "small" }, r.source || "–"))))))
      : h("div", { class: "small faint" }, "No scores yet: monitoring posts them to /v1/data-trust.")) : null;
  const verdict = async (c, ok) => {
    let note = "";
    if (!ok) { note = prompt("What was wrong? (recorded; the agent's trust drops)") || ""; if (!note.trim()) return; }
    try { const r = await api(`/console/api/spot-checks/${encodeURIComponent(c.incident)}`, { body: { ok, note } });
      toast(ok ? "Checked: right" : r.reversed ? "Reversed and the agent demoted" : "Agent demoted; someone with reverse rights must undo it", !ok && !r.reversed); route(); }
    catch (e) { toast(e.message, true); }
  };
  const undoIt = async (c, keep) => {
    let note = "";
    if (keep) { note = prompt("Why does it stay as it is? (recorded)") || ""; if (!note.trim()) return; }
    try { await api(`/console/api/spot-checks/${encodeURIComponent(c.incident)}`, { body: { ok: keep, note } });
      toast(keep ? "Kept, with your reason" : "Undone"); route(); }
    catch (e) { toast(e.message, true); }
  };
  const spot = h("div", { class: "card", style: "min-width:0" }, h("h3", {}, `Spot checks${checks.length ? ` (${checks.length})` : ""}`),
    h("p", { class: "small muted" }, "Decisions agents made alone, sampled for a person to check. Wrong ones are reversed and the agent loses trust."),
    checks.length ? checks.map((c) => h("div", { class: "row", style: "flex-wrap:wrap;border-top:1px solid var(--line);padding-top:8px;margin-top:8px" },
      h("div", { style: "flex:1;min-width:200px" }, h("b", {}, c.pattern),
        c.status === "undo_pending" ? h("span", { class: "badge b-bad", style: "margin-left:6px" }, "judged wrong: undo needed") : null,
        h("div", { class: "small muted" }, `${c.actions.join(", ") || "closed"} · ${scopeText(c.facts)}`),
        c.agent ? h("div", { class: "small faint mono" }, c.agent) : null, c.note ? h("div", { class: "small faint" }, c.note) : null,
        c.status === "undo_pending" && c.can_undo === false
          ? h("div", { class: "small", style: "color:var(--bad)" }, "Nobody active may undo this template's decisions. Grant the undo right (__reverse__) in People to undo it, or keep it with a reason.") : null),
      c.status === "undo_pending"
        ? [c.can_undo === false ? null : h("button", { class: "danger", onclick: () => undoIt(c, false) }, "Undo it"), h("button", { onclick: () => undoIt(c, true) }, "Keep it…")]
        : [h("button", { onclick: () => verdict(c, true) }, "Right"), h("button", { class: "danger", onclick: () => verdict(c, false) }, "Wrong…")]))
      : h("div", { class: "small faint" }, "Nothing waiting for you."));
  const incForm = () => {
    const target = h("input", { placeholder: "template, or template@store=TVM01", "aria-label": "Agent in the incident" });
    const reason = h("input", { placeholder: "What happened (required)", "aria-label": "Incident reason" });
    const hours = h("input", { type: "number", value: "24", min: "1", style: "width:90px", "aria-label": "Hours back" });
    const undo = h("input", { type: "checkbox", style: "width:auto", "aria-label": "Undo what can be undone" });
    const go = async () => {
      if (!reason.value.trim()) return toast("Say what happened", true);
      try { const r = await api("/console/api/agent-incidents", { body: { pattern: target.value.trim(), reason: reason.value, hours: Number(hours.value) || 24, undo: undo.checked } });
        toast(`Agent stopped; ${r.decisions.length} decision(s) to re-check${r.undone.length ? `, ${r.undone.length} undone` : ""}`); route(); }
      catch (e) { toast(e.message, true); }
    };
    return h("div", { style: "margin-top:10px" }, h("div", { class: "row", style: "flex-wrap:wrap" }, target, hours, h("label", { class: "small" }, undo, " undo what can be undone")),
      h("div", { class: "row", style: "flex-wrap:wrap" }, reason, h("button", { class: "danger", onclick: go }, "Open agent incident")));
  };
  const closeInc = async (x) => {
    const pm = prompt("Post-mortem: cause and the fix (required to close)") || "";
    if (!pm.trim()) return;
    try { await api(`/console/api/agent-incidents/${encodeURIComponent(x.id)}/close`, { body: { postmortem: pm } }); toast("Closed"); route(); }
    catch (e) { toast(e.message, true); }
  };
  const inc = h("div", { class: "card", style: "min-width:0" }, h("h3", {}, "Agent incidents"),
    incidents.length ? h("ul", { class: "small" }, incidents.slice(0, 20).map((x) => h("li", {}, h("b", {}, x.pattern), ` · ${x.reason} · ${x.decisions.length} decision(s)`,
      x.undone.length ? `, ${x.undone.length} undone` : "", " · ", h("span", { class: `badge ${x.status === "open" ? "b-bad" : "b-ok"}` }, x.status),
      x.status === "open" && a.can_oversee ? h("button", { class: "ghost", style: "margin-left:6px", onclick: () => closeInc(x) }, "Close…") : null,
      x.postmortem ? h("div", { class: "faint" }, x.postmortem) : null)))
      : h("div", { class: "small faint" }, "None."),
    a.can_oversee ? incForm() : null);
  shell("agents", "Agents & oversight", "Who each agent works for, how far it may go, and who watches it", [h("button", { onclick: route }, "Refresh")],
    [templates, h("div", { class: "grid g2 section" }, bindings, policies), h("div", { class: "grid g2 section" }, tester, oversight),
      h("div", { class: "grid g2 section" }, spot, inc), trust ? h("div", { class: "section" }, trust) : null, binding]);
};

function oversightForm(a) {
  const target = h("input", { placeholder: "template, or template@store=TVM01", list: "agent-templates", "aria-label": "Agent to act on" });
  const list = h("datalist", { id: "agent-templates" }, a.templates.filter((t) => t.overseers.length).map((t) => h("option", { value: t.id })));
  const action = select([["stop", "Stop (a person decides)"], ["demote", "Demote one step"], ["cap", "Cap at…"]], "stop", (v) => { cap.style.display = v === "cap" ? "" : "none"; }, { "aria-label": "Action" });
  const cap = select([["hitl", "person"], ["llm", "model"]], "hitl", () => {}, { style: "display:none", "aria-label": "Cap" });
  const reason = h("input", { placeholder: "Why (required, recorded)", "aria-label": "Reason" });
  const go = async () => {
    if (!reason.value.trim()) return toast("Say why: it is recorded", true);
    try {
      const r = await api("/console/api/oversee", { body: { pattern: target.value.trim(), action: action.value, reason: reason.value, route: action.value === "cap" ? cap.value : null } });
      toast(`${r.states.length} state(s) now ${r.states.map((x) => x.route).join(", ")}`); route();
    } catch (e) { toast(e.message, true); }
  };
  return h("div", { style: "margin-top:10px" }, h("div", { class: "small muted" }, "You hold an oversight role. This only ever lowers autonomy."),
    h("div", { class: "row", style: "flex-wrap:wrap" }, target, list, action, cap),
    h("div", { class: "row", style: "flex-wrap:wrap" }, reason, h("button", { class: "danger", onclick: go }, "Apply")));
}

// ---- plan & usage
PAGES.plan = async () => {
  const p = await api("/console/api/plan");
  const L = p.licence;
  const STATE = { ok: ["valid", "b-ok"], grace: ["valid, with warnings", "b-info"], degraded: ["not valid: people decide every case", "b-bad"] };
  const lic = !p.enforced ? h("div", { class: "card" }, h("h3", {}, "Licence"), h("p", { class: "small" }, "Not enforced: this is an open-source install (SENTINEL_LICENCE is not set)."))
    : h("div", { class: "card" }, h("h3", {}, "Licence ", h("span", { class: `badge ${STATE[L.state][1]}` }, STATE[L.state][0])),
      L.licence ? h("div", { class: "kv" }, h("div", {}, "Licensee"), h("div", {}, L.licence.licensee), h("div", {}, "Site"), h("div", {}, L.licence.site),
        h("div", {}, "Tier"), h("div", {}, L.licence.tier), h("div", {}, "Valid"), h("div", {}, `${L.licence.valid_from} to ${L.licence.valid_until}`),
        h("div", {}, "Includes"), h("div", { class: "small" }, Object.entries(L.licence.limits || {}).filter(([, v]) => v !== null).map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join(" · ") || "–")) : null,
      L.reasons.length ? h("ul", { class: "small" }, L.reasons.map((r) => h("li", {}, r))) : null);
  const u = p.usage;
  const tenants = u ? Object.entries(u.tenants) : [];
  const use = u ? h("div", { class: "card" }, h("h3", {}, `Usage in ${p.month}`), tenants.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Tenant", "Cases", "Automatic", "By people", "Reviewers", "Reversed", "Model calls"].map((x, i) => h("th", { class: i ? "num" : null }, x)))),
      h("tbody", {}, tenants.map(([name, t]) => h("tr", {}, h("td", {}, name), h("td", { class: "num" }, t.incidents), h("td", { class: "num" }, t.resolved_automatic), h("td", { class: "num" }, t.resolved_by_people),
        h("td", { class: "num" }, t.reviewers), h("td", { class: "num" }, t.reversed), h("td", { class: "num" }, t.model.calls)))))
      : h("div", { class: "empty" }, "No cases this month yet."),
      h("p", { class: "small faint" }, "Automatic resolutions count once they are not reversed within the reversal window. The signed export for a month is final a week after it ends."),
      h("div", { class: "row" }, h("input", { id: "usage-month", value: lastMonth(), style: "width:120px" }),
        h("button", { onclick: () => downloadUsage(document.getElementById("usage-month").value) }, "Download signed export"))) : h("div", { class: "card small" }, "Usage figures need the __configure__ right.");
  shell("plan", "Plan & usage", "The licence this site runs under and what this month's bill is based on", null, [lic, use]);
};
function lastMonth() { const d = new Date(); d.setDate(1); d.setMonth(d.getMonth() - 1); return d.toISOString().slice(0, 7); }
async function downloadUsage(month) {
  try {
    const doc = await api(`/console/api/usage/${encodeURIComponent(month)}`);
    const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" })), download: `usage-${month}.json` });
    document.body.append(a); a.click(); a.remove();
    toast(doc.final ? "Downloaded (final)" : "Downloaded (not final yet: the reversal window has not passed)");
  } catch (e) { toast(e.message, true); }
}

// ---- go live
PAGES.golive = async () => {
  const g = await api("/console/api/golive");
  const icon = (ok) => ok === true ? h("span", { class: "badge b-ok" }, "ok") : ok === false ? h("span", { class: "badge b-bad" }, "fix") : h("span", { class: "badge b-plain" }, "advice");
  const AREA = { connect: "1 · Connect", people: "2 · People", patterns: "3 · Exceptions", operations: "4 · Operations" };
  const checklist = Object.entries(AREA).map(([area, label]) => {
    const rows = g.checks.filter((c) => c.area === area);
    return rows.length ? h("div", { class: "card" }, h("h3", {}, label), h("table", {}, h("tbody", {}, rows.map((c) => h("tr", {},
      h("td", { style: "width:70px" }, icon(c.ok)), h("td", {}, c.item), h("td", { class: "small muted" }, c.detail)))))) : null;
  });
  const STATE = { live: ["live", "b-ok"], ready: ["ready to go live", "b-info"], collecting: ["collecting shadow cases", "b-plain"], below_agreement: ["below agreement", "b-bad"] };
  const switchTo = async (ids, mode) => {
    try {
      const r = await api(`/console/api/golive/${mode}`, { body: { patterns: ids } });
      toast(r.waiting ? "Saved; waiting for approval by someone else who can configure" : mode === "live" ? `${ids.join(", ")} live` : `${ids.join(", ")} in shadow`);
      route();
    } catch (e) { showError(e); }
  };
  const rows = g.patterns.map((x) => h("tr", {},
    h("td", {}, h("b", {}, x.id), x.description ? h("div", { class: "small faint" }, x.description) : null),
    h("td", {}, h("span", { class: `badge ${STATE[x.state][1]}` }, STATE[x.state][0]), x.shadow_in_code ? h("div", { class: "small faint" }, "shadow set in code") : null),
    h("td", { class: "num" }, x.shadow_cases), h("td", { class: "num" }, pct(x.agreement)), h("td", {}, badgeRoute(x.route)),
    h("td", {}, !canConfigure() || x.shadow_in_code ? null : x.shadow
      ? h("button", { class: x.state === "ready" ? "primary" : null, onclick: () => {
          if (x.state === "ready") return switchTo([x.id], "live");
          modal(`Take ${x.id} live early?`, h("p", {}, `${x.id} has ${x.shadow_cases} shadow cases at ${pct(x.agreement)} agreement; the bar is ${g.thresholds.min_shadow_cases} at ${pct(g.thresholds.min_agreement)}. Live, it acts as its earned route allows.`),
            [(close) => h("button", { onclick: close }, "Keep in shadow"), (close) => h("button", { class: "danger", onclick: () => { close(); switchTo([x.id], "live"); } }, "Go live anyway")]);
        } }, "Go live")
      : h("button", { onclick: () => switchTo([x.id], "shadow") }, "Back to shadow"))));
  const ready = g.ready.length && canConfigure() ? h("button", { class: "primary", onclick: () => switchTo(g.ready, "live") }, `Take ${g.ready.length} ready exception(s) live`) : null;
  shell("golive", "Go live", `Connect, watch in shadow, then switch exceptions live once they agree with your people. ${g.blocking ? `${g.blocking} item(s) to fix.` : "Nothing blocking."}`, [ready],
    [h("div", { class: "card", style: "padding:0" }, h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "State", "Shadow cases", "Agreement", "Route", ""].map((t) => h("th", { class: ["Shadow cases", "Agreement"].includes(t) ? "num" : null }, t)))), h("tbody", {}, rows))),
     h("p", { class: "small faint" }, `In shadow Sentinel proposes and a person decides; agreement is how often they chose what it proposed. Ready means at least ${g.thresholds.min_shadow_cases} shadow cases at ${pct(g.thresholds.min_agreement)} or better. Each switch is a published change to the exceptions, so it is versioned and, with two-person approval, needs a second person.`),
     checklist]);
};

// ---- learning
PAGES.learning = async () => {
  const [pats, learn, mq] = await Promise.all([api("/console/api/patterns"), api("/console/api/learning"), api("/console/api/model-quality?days=30")]);
  const money = (x) => `${mq.currency === "INR" ? "₹" : mq.currency + " "}${Math.round(x || 0).toLocaleString("en-IN")}`;
  const mqTable = mq.patterns.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "Calls", "Errors", "Escalated", "People agreed", "Model fixes reversed", "Spend", "Per case"].map((t, i) => h("th", { class: i ? "num" : null }, t)))),
    h("tbody", {}, mq.patterns.map((x) => h("tr", {}, h("td", {}, x.pattern, h("div", { class: "small faint" }, x.models.map((m) => `${m.task}: ${m.model} (${m.calls}, ${m.latency_ms} ms)`).join(" · "))),
      h("td", { class: "num" }, x.calls), h("td", { class: "num" }, pct(x.error_rate)), h("td", { class: "num" }, pct(x.escalation_rate)),
      h("td", { class: "num" }, pct(x.agreement)), h("td", { class: "num" }, pct(x.reversal_rate)), h("td", { class: "num" }, money(x.cost)), h("td", { class: "num" }, money(x.cost_per_case))))))
    : h("div", { class: "empty" }, "No model calls in the last 30 days.");
  shell("learning", "Learning", "How each exception is earning (or losing) autonomy, and how models measure up", null, [
    h("div", { class: "card", style: "padding:0" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Exception", "Now", "Streak", "Agreement in shadow", "Fixes that held", "Reversed", "Next step"].map((t) => h("th", {}, t)))),
      h("tbody", {}, pats.map((p) => h("tr", {}, h("td", { class: "mono small" }, p.id), h("td", {}, badgeRoute(p.route)),
        h("td", { class: "num" }, p.streak), h("td", { class: "num" }, pct(p.shadow_agreement)), h("td", { class: "num" }, pct(p.outcome_held_rate)),
        h("td", { class: "num" }, p.reversals), h("td", { class: "small" }, p.pending_promotion ? h("a", { href: "#/exceptions" }, `approve ${p.pending_promotion}`) : p.route === p.ceiling ? h("span", { class: "faint" }, "at its ceiling") : h("span", { class: "faint" }, "keep earning"))))))),
    h("div", { class: "card section", style: "padding:0" }, h("div", { style: "padding:16px 18px 6px" }, h("h2", {}, "Models by exception"),
      h("div", { class: "small muted" }, `Last 30 days: ${mq.total_calls} calls, ${money(mq.total_cost)}. Agreement is how often people chose what the model proposed.`)), mqTable),
    h("div", { class: "card section" }, h("h2", {}, "Model evaluations"),
      learn.evaluations.length ? h("table", {}, h("thead", {}, h("tr", {}, ["When", "Model", "Cases", "Exact", "Ready for"].map((t) => h("th", {}, t)))),
        h("tbody", {}, learn.evaluations.map((e) => h("tr", {}, h("td", { class: "small muted" }, when(e.ts)), h("td", { class: "mono small" }, e.data.model),
          h("td", { class: "num" }, e.data.overall?.cases), h("td", { class: "num" }, pct(e.data.overall?.exact)),
          h("td", { class: "small" }, (e.data.overall?.ready_patterns || []).join(", ") || h("span", { class: "faint" }, "none yet"))))))
        : h("div", { class: "empty" }, "No evaluations yet. Run: sentinel --models models.yaml … evaluate --candidate local")),
    h("div", { class: "card section" }, h("h2", {}, "Recent learning"), learn.changes.length ? activityTable(learn.changes) : h("div", { class: "empty" }, "Nothing yet.")),
  ]);
};

// ---- insights (DuckDB)
PAGES.insights = async (q) => {
  const report = q.get("r") || "automation";
  const box = h("div", { class: "card", style: "padding:0" }, h("div", { class: "empty", style: "margin:16px" }, "Loading…"));
  shell("insights", "Insights", "Read-only reports over the full history (DuckDB)", null, [
    h("div", { class: "tabs" }, [["automation", "Automation"], ["weekly", "By week"], ["service", "Service"], ["models", "Models"], ["hotspots", "Hotspots"], ["trust", "Trust"]].map(([k, l]) =>
      h("button", { class: k === report ? "on" : null, onclick: () => (location.hash = `#/insights?r=${k}`) }, l))), box]);
  try {
    const rows = await api(`/console/api/analytics/${report}`);
    if (!rows.length) return box.replaceChildren(h("div", { class: "empty", style: "margin:16px" }, "No data yet."));
    const cols = Object.keys(rows[0]);
    box.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: typeof rows[0][c] === "number" ? "num" : null }, c.replaceAll("_", " "))))),
      h("tbody", {}, rows.map((r) => h("tr", {}, cols.map((c) => h("td", { class: typeof r[c] === "number" ? "num" : "small" },
        r[c] === null ? "–" : (c.endsWith("rate") || c === "exact" || c.endsWith("agreement")) && typeof r[c] === "number" ? pct(r[c]) : String(r[c]))))))));
  } catch (e) { box.replaceChildren(h("div", { class: "empty", style: "margin:16px" }, e.message)); }
};

// ---- cases (search, story, reverse)
const STATES = ["", "open", "awaiting_human", "resolving", "resolved", "failed", "suppressed", "dispositioned"];
PAGES.cases = async (q) => {
  const reg = await api("/console/api/config/registry/doc").catch(() => ({}));
  const f = { text: q.get("text") || "", pattern: q.get("pattern") || "", state: q.get("state") || "",
              fact: q.get("fact") || "", days: q.get("days") || "30" };
  const go = (extra = {}) => {
    const p = new URLSearchParams(Object.entries({ ...f, ...extra }).filter(([, v]) => v));
    location.hash = `#/cases?${p}`;
  };
  const text = h("input", { value: f.text, placeholder: "Order number, reference, case id…", style: "min-width:240px",
    onkeydown: (e) => { if (e.key === "Enter") { f.text = e.target.value; go(); } }, oninput: (e) => (f.text = e.target.value) });
  const fact = h("input", { value: f.fact, placeholder: "fact=value, e.g. channel=amazon", oninput: (e) => (f.fact = e.target.value) });
  const bar = h("div", { class: "card", style: "display:flex;gap:10px;flex-wrap:wrap;align-items:end" },
    field("Search", text),
    field("Exception", select([["", "any"], ...(reg.patterns || []).map((p) => [p.id, p.id])], f.pattern, (v) => (f.pattern = v))),
    field("State", select(STATES.map((x) => [x, x ? x.replaceAll("_", " ") : "any"]), f.state, (v) => (f.state = v))),
    field("Fact", fact),
    field("Within", select([["1", "a day"], ["7", "a week"], ["30", "30 days"], ["90", "90 days"], ["365", "a year"]], f.days, (v) => (f.days = v))),
    h("button", { class: "primary", onclick: () => go() }, "Search"));
  const qs = new URLSearchParams();
  for (const k of ["text", "pattern", "state", "days"]) if (f[k]) qs.set(k, f[k]);
  if (f.fact) qs.append("fact", f.fact);
  if (q.get("before")) qs.set("before", q.get("before"));
  let res;
  try { res = await api(`/console/api/cases?${qs}`); } catch (e) { res = { cases: [], error: e.message }; }
  const rows = res.cases.map((c) => h("tr", { class: "click", onclick: () => (location.hash = `#/case?id=${encodeURIComponent(c.id)}`) },
    h("td", { class: "small muted", style: "white-space:nowrap" }, when(c.created_at)),
    h("td", { class: "mono small" }, c.id),
    h("td", {}, c.pattern, c.shadow ? h("span", { class: "badge b-plain", style: "margin-left:6px" }, "shadow") : null),
    h("td", { class: "small" }, Object.entries(c.facts || {}).filter(([k]) => !["event_type", "source"].includes(k)).slice(0, 4).map(([k, v]) => `${k}=${v}`).join(" · ")),
    h("td", {}, badgeRoute(c.route)),
    h("td", {}, statusBadge(c.state)),
    h("td", { class: "small" }, c.disposition ? `${c.disposition.code} by ${c.disposition.resolver}${c.disposition.reversed ? " (reversed)" : ""}${c.disposition.outcome ? ` · ${c.disposition.outcome}` : ""}` : "–")));
  const table = res.cases.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Opened", "Case", "Exception", "Facts", "Route", "State", "Outcome"].map((x) => h("th", {}, x)))), h("tbody", {}, rows))
    : h("div", { class: "empty" }, res.error || "No cases match.");
  const more = res.next ? h("button", { onclick: () => go({ before: res.next }) }, "Older cases") : null;
  shell("cases", "Cases", "Every exception Sentinel has handled: search, open its story, reverse a wrong fix", null,
    [bar, h("div", { class: "card", style: "padding:0" }, table), more ? h("div", { style: "margin-top:10px" }, more) : null]);
};

PAGES.case = async (q) => {
  const id = q.get("id");
  const c = await api(`/console/api/cases/${encodeURIComponent(id)}`);
  const inc = c.incident;
  const facts = h("table", {}, h("tbody", {}, Object.entries(inc.facts || {}).map(([k, v]) => h("tr", {}, h("td", { class: "small muted" }, k), h("td", { class: "mono small" }, v === null ? "–" : String(v))))));
  const timeline = h("table", {}, h("tbody", {}, c.timeline.map((t) => h("tr", {},
    h("td", { class: "small muted", style: "white-space:nowrap" }, when(t.ts)),
    h("td", {}, h("span", { class: "badge b-plain" }, t.kind.replaceAll("_", " "))),
    h("td", { class: "small" }, t.what, t.data && Object.keys(t.data).length ? h("details", {}, h("summary", { class: "faint" }, "detail"), h("pre", { class: "code small" }, JSON.stringify(t.data, null, 1))) : null)))));
  const events = c.events.map((e) => h("details", {}, h("summary", { class: "small" }, `${e.type} from ${e.source} · ${when(e.occurred_at)} · ${e.id}`),
    h("pre", { class: "code small" }, JSON.stringify(e.payload, null, 1))));
  const reviews = c.reviews.map((r) => h("div", { class: "small", style: "margin-bottom:8px" },
    h("b", {}, r.role), ` · ${r.open ? "open" : "closed"} · ${r.reason}`,
    r.proposal ? h("div", { class: "faint" }, `proposed: ${(r.proposal.steps || []).map((s) => s.action).join(" → ") || "close"} (${r.proposal.source})`) : null,
    (r.deliveries || []).length ? h("div", { class: "faint" }, `sent via ${r.deliveries.map((d) => `${d.edge} to ${d.person_id || "role"} (${d.status})`).join(", ")}`) : null));
  const d = c.disposition;
  const outcome = d ? h("div", {}, h("div", {}, h("b", {}, d.code), ` by ${d.resolver}${d.actor ? ` (${d.actor})` : ""} · ${when(d.created_at)}`),
    (d.steps || []).length ? h("div", { class: "small" }, "did: ", d.steps.map((s) => `${s.action}(${Object.entries(s.params || {}).map(([k, v]) => `${k}=${v}`).join(", ")})`).join(" → ")) : null,
    d.outcome ? h("div", { class: "small" }, `outcome check: ${d.outcome}`) : null,
    d.reversed ? h("div", { class: "small", style: "color:var(--bad)" }, "reversed") : null,
    d.note ? h("div", { class: "small faint" }, d.note) : null) : h("div", { class: "faint" }, "Not resolved yet.");
  const tr = c.trace;
  const traceRow = (k, v) => h("tr", {}, h("td", { class: "small muted", style: "white-space:nowrap" }, k), h("td", { class: "small" }, v));
  const trace = tr ? h("div", { class: "card" }, h("h3", {}, "Decision trace ", tr.complete ? h("span", { class: "badge b-ok" }, "complete") : h("span", { class: "badge b-warn" }, `${tr.gaps.length} gap(s)`)),
    h("table", {}, h("tbody", {},
      traceRow("Observed", tr.observed.map((e) => `${e.type} from ${e.source}${e.correlation_id ? ` (correlation ${e.correlation_id})` : ""}`).join("; ") || "–"),
      traceRow("Capability", tr.capability || "–"),
      traceRow("Method", h("span", { class: "mono" }, `${tr.method || "–"}${tr.definition ? ` · ${tr.definition.slice(0, 8)}` : ""}${tr.config ? ` · registry ${tr.config}` : ""}`)),
      traceRow("Proposed", tr.proposal ? `${tr.proposal.actions.join(" → ") || "close"} by ${tr.proposal.source}` : "–"),
      traceRow("Decided", tr.resolved ? `${tr.resolved.code} by ${tr.resolved.resolver}${tr.resolved.actor ? ` (${tr.resolved.actor})` : ""}${tr.resolved.agreed_with_proposal === false ? ", not as proposed" : ""}` : "–"),
      traceRow("Done", tr.actions.map((a) => `${a.action}: ${a.status}`).join(", ") || "–"),
      traceRow("Outcome", tr.outcome ? tr.outcome.verdict : "–"))),
    tr.gaps.length ? h("div", { class: "small faint", style: "margin-top:6px" }, tr.gaps.join("; ")) : null) : null;
  const reverseBtn = c.can_reverse_now ? h("button", { class: "danger", onclick: () => reverseCase(id, c.reverse.note) }, "Reverse this fix") : null;
  const retrace = h("button", { onclick: () => { S.traceEvent = c.events[0] ? { type: c.events[0].type, source: c.events[0].source, payload: c.events[0].payload } : null; location.hash = "#/trace"; } }, "Trace its event again");
  shell("cases", `Case ${id}`, `${c.pattern.id}${c.pattern.description ? ` · ${c.pattern.description}` : ""}`,
    [h("button", { onclick: () => history.back() }, "Back"), retrace, reverseBtn],
    h("div", { class: "grid g2", style: "align-items:start" },
      h("div", {}, h("div", { class: "card" }, h("h3", {}, "Story"), timeline),
        h("div", { class: "card" }, h("h3", {}, `Events (${c.events_total})`), events)),
      h("div", {}, h("div", { class: "card" }, h("h3", {}, "Outcome"), outcome, c.reverse.note && c.reverse.possible ? h("div", { class: "small faint", style: "margin-top:6px" }, c.reverse.note) : null),
        trace,
        h("div", { class: "card" }, h("h3", {}, "Now"), h("div", {}, statusBadge(inc.state), " ", badgeRoute(inc.route), inc.shadow ? " shadow" : ""),
          c.parent ? h("div", { class: "small" }, "under ", h("a", { href: `#/case?id=${c.parent}` }, c.parent)) : null,
          c.children.length ? h("div", { class: "small" }, `${c.children.length} suppressed under it: `, c.children.slice(0, 10).map((x) => h("a", { href: `#/case?id=${x}`, style: "margin-right:6px" }, x))) : null),
        h("div", { class: "card" }, h("h3", {}, "Facts"), facts),
        c.reviews.length ? h("div", { class: "card" }, h("h3", {}, "Reviews"), reviews) : null)));
};

function reverseCase(id, warn) {
  const note = h("textarea", { placeholder: "What was wrong? (kept with the case and used for learning)", style: "min-height:70px;width:100%" });
  modal("Reverse this fix", h("div", {}, h("p", {}, "Sentinel undoes what can be undone, records the mistake, and the exception loses the trust it earned."),
    warn ? h("p", { class: "small" }, warn) : null, note), [
    (close) => h("button", { onclick: close }, "Cancel"),
    (close) => h("button", { class: "danger", onclick: async () => {
      try { await api(`/console/api/cases/${encodeURIComponent(id)}/reverse`, { body: { note: note.value } }); close(); toast("Reversed"); route(); }
      catch (e) { toast(e.message, true); } } }, "Reverse")]);
}

// ---- trace an event (read-only)
PAGES.trace = async () => {
  const doc = await api("/console/api/config/registry/doc").catch(() => ({}));
  const pre = S.traceEvent || null;
  S.traceEvent = null;
  const types = (doc.fingerprints || []).map((f) => f.event_type);
  const ev = { type: pre?.type || types[0] || "", source: pre?.source || "trace" };
  const payload = h("textarea", { class: "code", style: "min-height:160px;width:100%" }, JSON.stringify(pre?.payload || {}, null, 2));
  const typeIn = h("input", { value: ev.type, list: "evtypes", oninput: (e) => (ev.type = e.target.value) });
  const lookups = h("input", { type: "checkbox", style: "width:auto" });
  const draft = h("input", { type: "checkbox", style: "width:auto" });
  const hasDraft = !!S.pending.registry;
  const out = h("div", {});
  const run = async () => {
    let body;
    try { body = JSON.parse(payload.value || "{}"); } catch { return toast("The payload is not valid JSON", true); }
    const req = { event: { type: ev.type, source: ev.source, payload: body }, run_lookups: lookups.checked };
    if (draft.checked && hasDraft) req.registry = await pendingYaml();
    try { out.replaceChildren(traceView(await api("/console/api/trace", { body: req }))); }
    catch (e) { out.replaceChildren(h("div", { class: "card" }, e.message)); }
  };
  const form = h("div", { class: "card" },
    h("datalist", { id: "evtypes" }, types.map((t) => h("option", { value: t }))),
    h("div", { class: "grid g2" }, field("Event type", typeIn), field("Source", h("input", { value: ev.source, oninput: (e) => (ev.source = e.target.value) }))),
    field("Payload (JSON)", payload, "Paste the body of a real event, or start from a case: open it and choose Trace its event again."),
    canConfigure() ? h("label", { class: "small", style: "display:flex;gap:6px;align-items:center" }, lookups, "Run the playbook's read-only lookups (calls your systems to read)") : null,
    canConfigure() && hasDraft ? h("label", { class: "small", style: "display:flex;gap:6px;align-items:center" }, draft, "Use my unsaved exception changes") : null,
    h("button", { class: "primary", onclick: run }, "Trace"));
  shell("trace", "Trace an event", "What Sentinel would do with this event now, and why. Nothing is stored, nothing runs, no model is asked.", null, [form, out]);
  if (pre) run();
};

async function pendingYaml() {
  const r = await api("/console/api/config/registry/check", { body: { doc: S.pending.registry } }).catch(() => null);
  return r?.text || jsyaml(S.pending.registry);
}
function jsyaml(o) { return JSON.stringify(o); }     // JSON is valid YAML

function traceView(t) {
  if (t.error) return h("div", { class: "card" }, h("b", {}, t.error), problemsList((t.problems || []).map((m) => ({ severity: "error", message: m }))));
  const OUT = { automatic: "Resolved automatically", person: "A person decides", model: "The model proposes", grouped: "Added to an open case", suppressed: "Suppressed under a parent case", duplicate: "Ignored: already received" };
  const steps = h("ol", { class: "small" }, t.steps.map((s) => h("li", {}, s)));
  const cands = (t.candidates || []).length ? h("table", {}, h("thead", {}, h("tr", {}, ["Exception", "Matches", "Why"].map((x) => h("th", {}, x)))),
    h("tbody", {}, t.candidates.map((c) => h("tr", {}, h("td", {}, c.pattern, c.pattern === t.pattern.id ? h("span", { class: "badge b-plain", style: "margin-left:6px" }, "chosen") : null),
      h("td", {}, c.matches ? "yes" : "no"),
      h("td", { class: "small" }, c.clauses.length ? c.clauses.map((k) => h("div", { style: k.ok ? null : "color:var(--bad)" },
        `${k.fact}: wants ${JSON.stringify(k.want)}${k.got !== undefined && k.fact !== "all" && k.fact !== "any" && k.fact !== "not" ? `, has ${k.present === false ? "nothing" : JSON.stringify(k.got)}` : ""}`)) : "matches every event of this type"))))) : null;
  const walk = (t.playbook?.steps || []).length ? h("table", {}, h("tbody", {}, t.playbook.steps.map((s) => h("tr", {},
    h("td", { class: "small muted" }, s.step), h("td", {}, `${s.kind} ${s.name}`), h("td", { class: "small" }, s.result,
      s.params ? h("div", { class: "mono faint" }, JSON.stringify(s.params)) : null, s.value !== undefined ? h("div", { class: "mono faint" }, JSON.stringify(s.value).slice(0, 300)) : null))))) : null;
  const who = t.reviewers ? h("div", { class: "small" }, `Goes to ${t.reviewers.role}`, t.reviewers.people ? `: ${t.reviewers.people.map((p) => `${p.id}${p.edge ? ` via ${p.edge}` : ""}`).join(", ") || "nobody active in scope"}` : "") : null;
  return h("div", {},
    h("div", { class: "card" }, h("h3", {}, OUT[t.outcome] || t.outcome, t.draft ? h("span", { class: "badge b-plain", style: "margin-left:8px" }, "draft registry") : null),
      h("div", {}, `Exception: ${t.pattern.id}`, t.route ? [" · ", badgeRoute(t.route.route)] : null), who,
      t.incident ? h("div", { class: "small" }, "into ", h("a", { href: `#/case?id=${t.incident}` }, t.incident)) : null,
      t.parent ? h("div", { class: "small" }, "under ", h("a", { href: `#/case?id=${t.parent}` }, t.parent)) : null),
    h("div", { class: "card" }, h("h3", {}, "Step by step"), steps),
    cands ? h("div", { class: "card", style: "padding:0" }, h("h3", { style: "margin:14px 16px 0" }, "Which exception"), cands) : null,
    walk ? h("div", { class: "card" }, h("h3", {}, "Playbook"), walk) : null,
    h("div", { class: "card" }, h("h3", {}, "Facts"), h("pre", { class: "code small" }, JSON.stringify(t.facts, null, 1))));
}

// ---- activity
PAGES.activity = async () => {
  const rows = await api("/console/api/activity?limit=200");
  shell("activity", "Activity", "The audit trail: every decision, action, learning step and configuration change", null,
    h("div", { class: "card", style: "padding:0" }, activityTable(rows)));
};

// ---- setup wizard
PAGES.setup = async (q) => {
  const step = Number(q.get("step") || 1);
  const W = (S.wizard = S.wizard || { template: null, registry: null, people: null });
  const steps = h("div", { class: "steps" }, ["Choose a template", "People & roles", "Exceptions", "Check and publish"].map((s, i) =>
    h("div", { class: i + 1 === step ? "on" : i + 1 < step ? "done" : null }, s)));
  const go = (n) => (location.hash = `#/setup?step=${n}`);
  if (step === 1) {
    const [list, packs] = await Promise.all([api("/console/api/templates"), api("/console/api/packs").catch(() => ({ configured: false, packs: [] }))]);
    const packCard = packs.configured ? h("div", { class: "card section", style: "padding:0" },
      h("div", { style: "padding:16px 18px 6px" }, h("h2", { style: "margin:0" }, "Domain packs in the catalogue"),
        h("div", { class: "small muted" }, "Exceptions, actions and tools for an industry, versioned and tested. Add one on the server with: sentinel pack add <id> --packs-file packs.yaml (nothing is granted until you say so).")),
      packs.packs.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Pack", "Industry", "Version", "Exceptions", "Needs access to", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, packs.packs.map((e) => h("tr", {}, h("td", {}, h("b", {}, e.title), h("div", { class: "mono small faint" }, e.id)), h("td", {}, e.industry || "–"),
          h("td", { class: "mono small" }, e.version), h("td", { class: "small" }, e.exceptions.join(", ") || "–"),
          h("td", { class: "small" }, e.capabilities.join(", ") || "nothing"),
          h("td", {}, e.installed ? h("span", { class: "badge b-ok" }, `installed ${e.installed}`) : e.fits ? null : h("span", { class: "badge b-warn" }, "needs a newer Sentinel"))))))
        : h("div", { class: "empty", style: "margin:16px" }, "The catalogue is empty.")) : null;
    const cards = h("div", { class: "grid g3" },
      h("div", { class: `card tpl ${W.template === "__current" ? "on" : ""}`, onclick: async () => {
        W.template = "__current";
        W.registry = (await api("/console/api/config/registry")).text;
        W.people = (await api("/console/api/config/people")).text;
        go(2);
      } }, h("h2", {}, "Start from what is running"), h("div", { class: "small muted" }, "Edit the current exceptions and people of this overlay.")),
      list.map((t) => h("div", { class: `card tpl ${W.template === t.name ? "on" : ""}`, onclick: async () => {
        const full = await api(`/console/api/templates/${t.name}`);
        W.template = t.name; W.registry = full.registry; W.people = full.people; W.missing = full.missing;
        go(2);
      } }, h("h2", {}, t.title), h("div", { class: "small muted" }, t.description),
        h("div", { class: "small", style: "margin-top:8px" }, `${t.patterns} exceptions · ${t.roles} roles · ${t.event_types.length} event types`),
        h("div", { class: "small faint", style: "margin-top:4px" }, `Needs actions: ${t.needs.actions.join(", ")}`))));
    shell("setup", "Set up from a template", "Data sources and actions come from the overlay; everything else is configured here", null,
      [steps, h("p", { class: "muted" }, "Pick a starting point. Nothing changes until you publish in the last step."), cards, packCard]);
    return;
  }
  if (!W.registry) return go(1);
  const editorStep = (kind, title, help, next) => {
    const ta = h("textarea", { class: "code", spellcheck: "false", oninput: (e) => (W[kind] = e.target.value) }, W[kind]);
    shell("setup", "Set up from a template", title, null, [steps,
      W.missing && kind === "registry" && W.missing.actions.length ? h("ul", { class: "problems" }, h("li", { class: "warning" },
        `This overlay does not implement yet: ${W.missing.actions.join(", ")}${W.missing.verifiers.length ? `; verifiers ${W.missing.verifiers.join(", ")}` : ""}. Remove those exceptions or actions here, or have the overlay add them.`)) : null,
      h("p", { class: "muted" }, help), ta,
      h("div", { class: "row", style: "margin-top:12px" }, h("button", { onclick: () => go(step - 1) }, "Back"), h("span", { class: "spacer" }),
        h("button", { class: "primary", onclick: () => go(next) }, "Next"))]);
  };
  if (step === 2) return editorStep("people", "People & roles", "Replace the placeholder person with your team, assign roles (with a location or channel scope if needed) and set approval limits. Give at least one person __configure__.", 3);
  if (step === 3) return editorStep("registry", "Exceptions", "Each exception: which events raise it, who owns it, how it is handled now and how far it may go. Start everything at a person or the model; automation is earned.", 4);
  const res = await api("/console/api/config-set/check", { body: { items: { people: { text: W.people }, registry: { text: W.registry } } } });
  const errs = ["people", "registry"].some((k) => res[k].problems.some((p) => p.severity === "error"));
  const note = h("input", { value: W.template && W.template !== "__current" ? `set up from template ${W.template}` : "set up" });
  shell("setup", "Set up from a template", "Check and publish", null, [steps,
    h("div", { class: "grid g2" }, ["people", "registry"].map((k) => h("div", { class: "card" },
      h("h2", {}, { people: "People & roles", registry: "Exceptions" }[k]), problemsList(res[k].problems),
      h("details", { style: "margin-top:10px" }, h("summary", { class: "small" }, "What changes"), diffView(res[k].diff))))),
    h("div", { class: "section" }, field("Note", note)),
    h("div", { class: "row" }, h("button", { onclick: () => go(3) }, "Back"), h("span", { class: "spacer" }),
      h("button", { onclick: () => saveSet(["people", "registry"], { people: { text: W.people }, registry: { text: W.registry } }, note.value, false) }, "Save as drafts"),
      h("button", { class: "primary", disabled: errs || !canConfigure() ? "disabled" : null,
        onclick: async () => { if (await saveSet(["people", "registry"], { people: { text: W.people }, registry: { text: W.registry } }, note.value, true)) { S.wizard = null; location.hash = "#/overview"; } } },
        "Publish both"))]);
};

// ---------------------------------------------------------------- router
async function route() {
  if (!S.token) return signIn();
  if (!S.me) {
    try { S.me = await api("/console/api/me"); } catch { return signIn(); }
  }
  const [path, qs] = (location.hash.slice(2) || "overview").split("?");
  const page = PAGES[path] || PAGES.overview;
  try { await page(new URLSearchParams(qs || "")); }
  catch (e) { shell(path, "Something went wrong", null, null, h("div", { class: "card" }, h("p", {}, e.message), h("button", { onclick: route }, "Try again"))); }
}
window.addEventListener("hashchange", route);
route();
