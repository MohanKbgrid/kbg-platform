import { Cta, PageHero, SectionHead, SubNav } from "@/components/Bits";
import { primitives } from "@/content/platform";

export const metadata = { title: "Core & UI kit" };

export default function Core() {
  return (
    <>
      <PageHero
        eyebrow="Platform · Core"
        title="Small primitives. Hard to get wrong."
        lede="The handful of mechanisms every product would otherwise re-implement, where re-implementing them differently is the bug."
      >
        <SubNav active="/platform/core/" />
      </PageHero>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="PLATFORM CORE" title="Domain-free, by design.">
            No models, migrations, ledger adapters or framework glue. Anything that must know what a control account is stops being code and
            becomes a spec.
          </SectionHead>
          <table className="table">
            <thead>
              <tr>
                <th>Module</th>
                <th>What it makes hard to violate</th>
              </tr>
            </thead>
            <tbody>
              {primitives.map((p) => (
                <tr key={p.name}>
                  <td>{p.name}</td>
                  <td>{p.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="UI KIT" title="One visual language, product-owned values.">
            Products share a token role vocabulary, the eight interface states and the table contract. The values behind the tokens belong to
            each product, so a hospital and a warehouse do not have to look alike.
          </SectionHead>
        </div>
      </section>
      <Cta />
    </>
  );
}
