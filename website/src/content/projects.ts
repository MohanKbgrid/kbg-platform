// Projects are anonymised: capabilities only, no client names.
// `shipped` lists the intelligence layers verified in the repos today; every project is
// designed to plug into all three.

export type Status = "Live" | "In build" | "Design phase" | "Scaffold" | "Phase 1";
export type Layer = "Ask AI" | "Sentinel";

export type Project = {
  slug: string;
  name: string;
  domain: string; // domain slug
  status: Status;
  line: string;
  capabilities: string[];
  stack: string;
  shipped: Layer[];
};

export const projects: Project[] = [
  {
    slug: "nextgen-fulfilment",
    name: "NextGen",
    domain: "retail-commerce",
    status: "Live",
    line: "A warehouse operating system for multichannel order fulfilment.",
    capabilities: [
      "Multichannel order capture into one canonical model",
      "Pick, pack and ship with courier labels and SLA tracking",
      "Reconciliation of settlements against what was owed, per order",
      "GST, e-invoicing and ledger posting",
      "Per-brand portals with a margin firewall",
      "Stock availability aware of combos and marketplace-held stock",
      "Returns and fraud detection, daily exception signals, procurement suggestions",
    ],
    stack: "Next.js · Postgres (Supabase) · Vercel",
    shipped: ["Ask AI"],
  },
  {
    slug: "ecommerce-operations",
    name: "E-commerce Operations Agents",
    domain: "retail-commerce",
    status: "In build",
    line: "A Sentinel domain pack for a direct-to-consumer brand.",
    capabilities: [
      "Finance and MIS monitors: reconciliation breaks, overdue settlements, missing or duplicate invoices, forecast variance",
      "Order-fulfilment exceptions with reversible automatic fixes",
      "Replenishment rules that never run out and never buy dead stock early",
      "KPIs that act: a case opens when a KPI misses and closes when it recovers",
      "Data checks first: monitors act on nothing while their data is failing",
    ],
    stack: "Python · Postgres · Sentinel overlay",
    shipped: ["Sentinel", "Ask AI"],
  },
  {
    slug: "retail-pos",
    name: "Retail POS",
    domain: "retail-commerce",
    status: "Design phase",
    line: "An omnichannel point of sale, multi-tenant from day one.",
    capabilities: [
      "Tills, handhelds, self-checkout and customer displays that sell under a store-node lease and keep a signed, hash-chained journal",
      "One limits table for price, discount, return and cash, enforced by tills and automated inside by Sentinel",
      "An integration hub that moves and proves data but never decides",
      "Incentives calculated as transactions happen",
      "WhatsApp-first customer messages",
    ],
    stack: "Layered services · per-layer databases · analytics in MotherDuck",
    shipped: [],
  },
  {
    slug: "hospital-management",
    name: "Hospital Management",
    domain: "healthcare",
    status: "In build",
    line: "A reimagined hospital management product on Postgres and Python.",
    capabilities: [
      "An extractor that reads legacy design metadata and emits per-screen manifests, a layered specification and an integration manifest",
      "A generator that builds the product from that specification, with clean build provenance",
      "Coverage reporting where every unknown is flagged, never dropped",
    ],
    stack: "Python · Postgres · generated from specification",
    shipped: [],
  },
  {
    slug: "finance-accounting",
    name: "Finance & Accounting",
    domain: "healthcare",
    status: "In build",
    line: "A separate finance application with its own login and workspaces.",
    capabilities: [
      "Twelve accounting modules: accounts, general ledger, payables, receivables, fixed assets, payroll, cash and bank",
      "Role-scoped workspaces and a faithful set of voucher and master screens",
      "Trial balance, day book, ledger, profit and loss, balance sheet and receivables reports",
      "Cross-product posting reconciled to the paisa",
    ],
    stack: "React · FastAPI · Postgres",
    shipped: [],
  },
  {
    slug: "dairy-supply-chain",
    name: "Dairy Supply Chain",
    domain: "supply-chain",
    status: "In build",
    line: "A suite of operational apps on one shared platform, integrated with the ERP.",
    capabilities: [
      "Apps across operations, quality, procurement, CRM, shop, admin, POS, finance and fleet",
      "A catalogue of data objects with who verified them and when, so facts are queried, not re-derived",
      "Integration workspace for the ERP's function modules and master data",
      "Management information packs sequenced by data readiness",
    ],
    stack: "Python 3.12 · FastAPI · React · Postgres",
    shipped: [],
  },
  {
    slug: "p2p",
    name: "P2P · Procure to Pay",
    domain: "supply-chain",
    status: "In build",
    line: "Replenishment, purchasing and inbound receipt, with exceptions escalated by Sentinel.",
    capabilities: [
      "Replenishment and purchase orders driven from stock and sales data",
      "Contracts and info records with gate tests on every rule",
      "Inbound receipt matched to the order, with stale-data and exception escalation",
    ],
    stack: "Python · Postgres · Sentinel overlay",
    shipped: ["Sentinel"],
  },
  {
    slug: "fabrication-erp",
    name: "AuraFab",
    domain: "industrial",
    status: "Scaffold",
    line: "Multi-tenant ERP for fabrication and manufacturing, engineer-to-order.",
    capabilities: [
      "Tenant isolation enforced in the database with row-level security",
      "Project-centred data model for engineer-to-order work",
      "Service-layer architecture ready for the full requirement register",
    ],
    stack: "FastAPI · Postgres · React · Vite",
    shipped: [],
  },
  {
    slug: "fixed-assets",
    name: "Fixed Asset Management",
    domain: "industrial",
    status: "Scaffold",
    line: "A multi-tenant fixed-asset register with barcoding.",
    capabilities: [
      "Asset register adapted to a full requirement document",
      "Row-level-security multi-tenancy and cookie sessions",
      "Same proven stack as the fabrication ERP",
    ],
    stack: "FastAPI · Postgres · React · Docker",
    shipped: [],
  },
  {
    slug: "mining-blast-safety",
    name: "Blast Safety",
    domain: "industrial",
    status: "Phase 1",
    line: "Predicts peak vibration at a protected structure and gives a go or no-go.",
    capabilities: [
      "Compares the prediction against the applicable statutory threshold and returns the maximum safe charge per delay",
      "Map tool that discovers and ranks every surrounding structure from a blast point",
      "Calibration workspace that turns trial-blast records into gated, validated site constants",
      "An assumptions ledger separating established, statutory and constructed content",
    ],
    stack: "Single-file browser tool · Python calibration",
    shipped: [],
  },
  {
    slug: "nonprofit-erp",
    name: "Foundation Management",
    domain: "social-sector",
    status: "Live",
    line: "A legacy desktop ERP migrated to the web for a foundation.",
    capabilities: [
      "Vouchers, receipts, purchase orders, bank realisation and printed documents",
      "Ask AI assistant, smart voucher entry and natural-language analytics",
      "Document attachments in cloud storage, payment and accounting-package connectors",
      "Semantic search through a local model",
    ],
    stack: ".NET 9 · Postgres · React · Azure",
    shipped: ["Ask AI"],
  },
];

export const statusClass: Record<Status, string> = {
  Live: "live",
  "In build": "build",
  "Design phase": "design",
  Scaffold: "early",
  "Phase 1": "early",
};
