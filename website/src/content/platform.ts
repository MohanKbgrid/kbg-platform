// Source: kbg-platform canon (surfaces + doctrines), bases/core README, kbg-sentinel README.

export const thesis =
  "With AI as the engineering team, code is cheap to port but expensive to trust. So the asset we carry between products is the contract and its gate tests, not a shared library.";

export const surfaces = [
  { n: 1, wave: "Identity & config", name: "Tenancy", text: "Every record is stamped with a tenant. Companies are standalone, with their own modules and reports." },
  { n: 2, wave: "Identity & config", name: "Config", text: "Credentials and per-tenant settings held as data, read by RBAC and Integration." },
  { n: 3, wave: "Identity & config", name: "RBAC", text: "Every write is authorised. Deny by default, from the first endpoint." },
  { n: 4, wave: "Work & evidence", name: "Workflow", text: "Routing, approval, escalation, and the queue that is the application." },
  { n: 5, wave: "Work & evidence", name: "Documents", text: "Required evidence blocks progress until it is present." },
  { n: 6, wave: "Work & evidence", name: "Experience", text: "The data-table contract, the eight states, export and print." },
  { n: 7, wave: "The outside world", name: "Integration", text: "Code mapping, an outbox, and the gate that stops a dev box writing to production." },
  { n: 8, wave: "The outside world", name: "Runtime AI", text: "Grounded-or-nothing drafting. A draft never becomes a posted document without a named human." },
  { n: 9, wave: "Money, last", name: "Accounting", text: "Control accounts and dimensional sub-ledgers. Corrections are new documents, never edits." },
];

export const doctrines = [
  "Deny by default",
  "Append-only on anything financial or evidentiary",
  "Idempotency by source id, not by server id",
  "Missing data is a finding, never a licence to invent",
  "Config is data, not code",
  "Prove newness, not liveness",
  "A control that can report a false result is worse than no control",
  "Held is not blocked",
  "Route to a position, never to a person",
  "Timestamps are capture time, not sync time",
  "One engine, channel-resolved input",
  "State the denominator",
];

export const primitives = [
  { name: "result", rule: "Missing data is a finding. A caller cannot read a value without handling its absence." },
  { name: "authority", rule: "Deny by default. One function drives both the disabled button and the 403." },
  { name: "versioned", rule: "Append-only. Changing a value supersedes it; it never updates in place." },
  { name: "outbox", rule: "Non-production environments hold events instead of pretending to send them." },
  { name: "idem", rule: "Idempotency by a client-minted source id." },
  { name: "testkit", rule: "Prove the control controls. Refuses to run against a non-fixture database." },
];

export const pipeline = [
  "Event",
  "Fingerprint",
  "Group & inhibit",
  "Registry match",
  "Route: auto · model · person",
  "Guarded action",
  "Disposition",
  "Learning",
];

export const guarantees = [
  { k: "No event processed twice", v: "An inbox table with a unique dedupe key per event." },
  { k: "No side effect executed twice", v: "Every action step claims an idempotency key; re-drives skip completed steps." },
  { k: "Irreversible actions need a person", v: "Only reversible or safe actions run unattended." },
  { k: "The model can't go rogue", v: "Allowed actions only, schema-checked parameters, read-only tools, a step cap, then a person." },
  { k: "Trust is earned slowly, lost instantly", v: "Promotion needs a track record and a person's sign-off; any reversal demotes at once." },
  { k: "Personal data stays out of models", v: "Masked before every model call and restored only for the action." },
  { k: "Full audit", v: "Every decision, attempt, compensation and reversal goes to an append-only log." },
  { k: "Blast radius capped", v: "Per-pattern circuit breakers and kill switches." },
];

export const openStack = [
  ["System of record, queue, learning", "PostgreSQL with pgvector"],
  ["Analytics", "DuckDB, read-only"],
  ["Frontier model", "Claude (optional)"],
  ["Small model + embeddings", "Ollama on a shared host"],
  ["API, workers, console", "FastAPI, Python, plain HTML/JS"],
  ["Sign-in", "Tokens or any OpenID Connect provider"],
  ["Monitoring", "Prometheus + Grafana"],
  ["Packaging", "Docker Compose with nightly backups"],
];

export type Intel = {
  slug: string;
  name: string;
  line: string;
  body: string[];
  points: { k: string; v: string }[];
};

export const intelligence: Intel[] = [
  {
    slug: "ask-ai",
    name: "Ask AI",
    line: "Ask your business a question, or ask it to act.",
    body: [
      "A conversational assistant inside the product. It answers from live data, turns documents into drafts a person only has to check, and can take actions on a person's request.",
      "It follows the Runtime AI contract: it asserts only what is present in its source, shows confidence per field, and never posts anything without a named human.",
    ],
    points: [
      { k: "Answers from live data", v: "Natural-language questions answered over the product's own data and analytics." },
      { k: "Drafts, not decisions", v: "Reads invoices, photos and notes into a draft; a person accepts, edits or rejects." },
      { k: "Acts on request", v: "Approved tools such as creating an entry or sending a mail, always through guardrails." },
      { k: "Measured", v: "Every invocation is recorded, and acceptance rate per capability is visible." },
    ],
  },
  {
    slug: "ask-ui",
    name: "Ask UI",
    line: "The interface where people review, approve and decide.",
    body: [
      "Review cards, approvals and structured results rendered inside the conversation, and reachable on WhatsApp, so a decision never needs a separate tool.",
      "Reviews route to the right people by role and scope, with approval limits, escalation on SLA and an audit trail of every decision.",
    ],
    points: [
      { k: "Cards in context", v: "A case, its facts and the proposed action in one card." },
      { k: "Role-routed", v: "Work goes to a position, never to a named person." },
      { k: "Signed decisions", v: "Every approval is attributed, limited and audited." },
      { k: "Where people are", v: "In the console, in Ask AI, or on WhatsApp." },
    ],
  },
  {
    slug: "sentinel",
    name: "Sentinel",
    line: "Agents that handle exceptions and earn autonomy.",
    body: [
      "An event-driven framework. Business transactions raise events; Sentinel recognises what kind of incident each is, decides whether to resolve it automatically, ask a model, or hand it to a person, records the outcome, and learns from it.",
      "The framework is domain-free. Each product adds an overlay: a registry of exception patterns plus its own actions, read-only tools and receivers.",
    ],
    points: [
      { k: "Recognise and route", v: "Signed webhooks, polled APIs and database tables become fingerprinted cases." },
      { k: "Resolve safely", v: "Playbooks, models with read-only tools, and people, all through guarded, idempotent actions." },
      { k: "Learn with sign-off", v: "Trust is promoted per pattern only when a person approves." },
      { k: "Run without code", v: "A console edits exceptions, people, roles and connectors as versioned configuration." },
    ],
  },
];

export const adoption = [
  { name: "Greenfield", text: "A new product born on the canon. The first commit already carries tenancy, config, RBAC, workflow, documents and accounting." },
  { name: "Retrofit", text: "An existing codebase adopts the surfaces one at a time, in coupling order, with no big-bang rewrite." },
];
