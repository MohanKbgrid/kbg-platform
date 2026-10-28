import { Cta, PageHero } from "@/components/Bits";

export const metadata = { title: "Trust" };

const items = [
  { k: "Deny by default", v: "Every write is authorised, and refusals are audited." },
  { k: "Tenant isolation", v: "Records are stamped with a tenant and, where products use it, isolated in the database with row-level security." },
  { k: "Personal data and models", v: "Masked before any model call and restored only for the approved action." },
  { k: "Full audit trail", v: "Decisions, attempts, reversals and learning changes go to an append-only log with secrets redacted." },
  { k: "Recoverable", v: "Nightly backups checked against a manifest, with restores re-checked before acceptance." },
  { k: "Open-source licensing", v: "Runtime dependencies of the agent framework must carry an approved open-source licence, checked in CI." },
];

export default function Trust() {
  return (
    <>
      <PageHero
        eyebrow="Trust"
        title="Safe by construction."
        lede="The controls that sit under every product. Product-level certifications are not claimed on this page."
      />
      <section className="blk">
        <div className="wrap hair g2">
          {items.map((i) => (
            <div key={i.k}>
              <h3>{i.k}</h3>
              <p>{i.v}</p>
            </div>
          ))}
        </div>
      </section>
      <Cta />
    </>
  );
}
