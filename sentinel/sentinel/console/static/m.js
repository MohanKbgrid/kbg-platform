// Mobile review page: the cases waiting for this person, with big Approve / Close buttons. Same API and rules
// as the console; no build step, no external requests.
const $ = (id) => document.getElementById(id);
const app = $("m-app");
let token = sessionStorage.getItem("sentinel_token") || localStorageGet();

function localStorageGet() { try { return localStorage.getItem("sentinel_m_token") || ""; } catch { return ""; } }
function remember(t) { try { localStorage.setItem("sentinel_m_token", t); } catch { /* private mode */ } }
function forget() { try { localStorage.removeItem("sentinel_m_token"); } catch { /* ignore */ } sessionStorage.removeItem("sentinel_token"); }

let STR = {};                                   // words in the person's language (from /console/api/me)
function L(key, vars = {}) {
  const fallback = { approve: "Approve", close: "Close", close_as: "Close as {code}", suggested: "Suggested", sure: "{n}% sure",
    due: "due", nothing: "Nothing waiting for you.", done: "Done", waiting: "{n} waiting", then: ", then ", sign_out: "Sign out" };
  return (STR[key] || fallback[key] || key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");
}

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}
function toast(msg, bad = false) {
  document.querySelectorAll(".m-toast").forEach((x) => x.remove());
  const t = el("div", { class: `m-toast ${bad ? "bad" : ""}`, role: "status" }, msg);
  document.body.append(t); setTimeout(() => t.remove(), 3500);
}
async function api(path, body) {
  const res = await fetch(path, { method: body ? "POST" : "GET",
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined });
  let data = null; try { data = await res.json(); } catch { /* empty */ }
  if (res.status === 401) { forget(); token = ""; signIn("Please sign in again"); throw new Error("signed out"); }
  if (!res.ok) { const e = new Error(typeof data?.detail === "string" ? data.detail : `Request failed (${res.status})`); e.data = data; throw e; }
  return data;
}

function signIn(msg) {
  const input = el("input", { type: "password", placeholder: "Your Sentinel token", autocomplete: "current-password" });
  const keep = el("input", { type: "checkbox", id: "m-keep", style: "width:auto;min-height:0;margin:0 8px 0 0" });
  app.replaceChildren(el("div", { class: "m-card m-signin" }, el("h3", {}, "Sign in"), msg ? el("div", { class: "m-meta" }, msg) : null, input,
    el("label", { for: "m-keep", class: "m-meta" }, keep, "Keep me signed in on this phone (only on your own phone)"),
    el("button", { onclick: async () => { token = input.value.trim(); sessionStorage.setItem("sentinel_token", token); if (keep.checked) remember(token); await load(); } }, "Sign in"),
    el("a", { href: "/console/sso/login" }, "Sign in with your company account")));
}

function card(c) {
  const close = c.disposition_codes || [];
  const code = el("select", { "aria-label": L("close") }, close.map((x) => el("option", { value: x }, L("close_as", { code: x.replaceAll("_", " ") }))));
  if (close.includes("no_action")) code.value = "no_action";
  const decide = async (body, btn) => {
    btn.disabled = true;
    try { await api(`/v1/reviews/${encodeURIComponent(c.review_id)}/decision`, body); toast(L("done")); await load(); }
    catch (e) { btn.disabled = false; toast(e.data?.escalate_to ? `${e.message} (${e.data.escalate_to} can)` : e.message, true); }
  };
  const steps = c.proposal_steps || [];
  const ok = steps.length ? el("button", { class: "ok", onclick: (e) => decide({ kind: "approve", disposition_code: c.proposal_code }, e.target) }, L("approve")) : null;
  const no = el("button", { onclick: (e) => decide({ kind: "reject", disposition_code: code.value }, e.target) }, L("close"));
  return el("div", { class: "m-card" },
    el("h3", {}, c.title),
    el("div", { class: "m-meta" }, `${c.reason} · ${L("due")} ${new Date(c.due_at).toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}`),
    el("div", { class: "m-facts" }, Object.entries(c.facts).filter(([k]) => !["event_type", "source"].includes(k)).map(([k, v]) => el("span", {}, `${k}: ${v}`))),
    steps.length ? el("div", { class: "m-prop" }, `${L("suggested")}: `, el("b", {}, steps.map((s) => s.action.replaceAll("_", " ")).join(L("then"))),
      c.proposal_confidence != null ? ` (${L("sure", { n: Math.round(c.proposal_confidence * 100) })})` : "") : null,
    el("div", { class: "m-actions" }, ok || el("span"), no, close.length ? code : null));
}

async function load() {
  if (!token) return signIn();
  try {
    if (!STR.approve) {
      const me = await api("/console/api/me");
      STR = me.strings || {};
      document.documentElement.lang = me.language || "en";
    }
    const cards = await api("/console/api/reviews?localise=true");
    $("m-count").textContent = cards.length ? L("waiting", { n: cards.length }) : "";
    app.replaceChildren(...(cards.length ? cards.map(card) : [el("div", { class: "m-empty" }, L("nothing"))]),
      el("div", { class: "m-empty" }, el("a", { href: "#", onclick: (e) => { e.preventDefault(); forget(); token = ""; STR = {}; signIn(); } }, L("sign_out"))));
  } catch (e) { if (e.message !== "signed out") app.replaceChildren(el("div", { class: "m-empty" }, e.message)); }
}
$("m-refresh").addEventListener("click", load);
load();
