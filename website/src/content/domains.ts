export type Domain = {
  slug: string;
  name: string;
  line: string;
  problem: string;
  capabilities: string[];
  projects: string[]; // project slugs
};

export const domains: Domain[] = [
  {
    slug: "healthcare",
    name: "Healthcare",
    line: "Hospital operations and the finance behind them.",
    problem: "Hospitals run on decades-old systems that are costly to change and risky to replace.",
    capabilities: [
      "Hospital management reimagined from the extracted specification of the legacy system",
      "Faithful finance and accounting with role-scoped workspaces",
      "Migration with audit by construction: every screen's behaviour is either filled in or explicitly flagged",
    ],
    projects: ["hospital-management", "finance-accounting"],
  },
  {
    slug: "retail-commerce",
    name: "Retail & commerce",
    line: "From the till to the warehouse to the marketplace.",
    problem: "Every added channel multiplies the ways things go wrong: orders, stock, fees and tax.",
    capabilities: [
      "Multichannel order fulfilment and reconciliation",
      "Offline-safe omnichannel point of sale with central limits",
      "Agents for finance, stock and fulfilment exceptions",
    ],
    projects: ["nextgen-fulfilment", "retail-pos", "ecommerce-operations"],
  },
  {
    slug: "supply-chain",
    name: "Supply chain",
    line: "Food and dairy distribution, from procurement to portal.",
    problem: "Data lives in the ERP, in spreadsheets and in people's heads, and integration is where programmes stall.",
    capabilities: [
      "A suite of operational apps on one shared platform",
      "ERP integration with a verified catalogue of what feeds what",
      "Management information packs sequenced by data readiness",
    ],
    projects: ["dairy-supply-chain"],
  },
  {
    slug: "industrial",
    name: "Industrial",
    line: "Fabrication, assets and safety-critical engineering.",
    problem: "Project-driven businesses need multi-tenant systems that fit how they actually build and track things.",
    capabilities: [
      "ERP for engineer-to-order fabrication",
      "Fixed-asset register with barcoding",
      "Predictive safety tooling with every assumption made visible",
    ],
    projects: ["fabrication-erp", "fixed-assets", "mining-blast-safety"],
  },
  {
    slug: "social-sector",
    name: "Social sector",
    line: "Foundation and temple management.",
    problem: "Charities need real accounting, receipts and compliance without enterprise cost.",
    capabilities: [
      "Vouchers, receipts, purchase orders and reports",
      "Legacy desktop system migrated to the web",
      "An in-app assistant for questions and entry",
    ],
    projects: ["nonprofit-erp"],
  },
];
