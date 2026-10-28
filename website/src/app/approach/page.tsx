import { Cta, PageHero, SectionHead } from "@/components/Bits";

export const metadata = { title: "Approach" };

const items = [
  { k: "Migrate or reimagine", v: "Some systems must be reproduced faithfully, others redesigned. We decide per product, and make the choice explicit." },
  { k: "Audit by construction", v: "Every behaviour is filled in or explicitly marked as none. Unknowns are flagged, never dropped." },
  { k: "Requirements you can trace", v: "Each requirement maps to a layer, a decision and a test, so progress is measurable." },
  { k: "Gate-tested delivery", v: "A control that can report a false result is worse than none, so every rule ships with a test that tries to break it." },
  { k: "Clean provenance", v: "Generated products are built from an extracted specification, kept separate from analysis scratch work." },
  { k: "Human sign-off on autonomy", v: "AI proposes; a named person approves anything consequential. Autonomy is earned on results." },
];

export default function Approach() {
  return (
    <>
      <PageHero
        eyebrow="Approach"
        title="How we deliver."
        lede="Disciplines carried from large programmes into AI-assisted engineering."
      />
      <section className="blk">
        <div className="wrap">
          <SectionHead idx="PRINCIPLES" title="Six habits." />
          <div className="hair g2">
            {items.map((i) => (
              <div key={i.k}>
                <h3>{i.k}</h3>
                <p>{i.v}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
      <Cta />
    </>
  );
}
