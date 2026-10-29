import Link from "next/link";
import { Cta, PageHero, SectionHead, SubNav } from "@/components/Bits";
import { thesis } from "@/content/platform";

export const metadata = { title: "Platform" };

export default function Platform() {
  return (
    <>
      <PageHero
        eyebrow="Platform"
        title="The foundation every product inherits."
        lede="Primitives and levers every application sits on: KBG-Platform, KBG-Sentinel and Ask AI (DuckDB, pgvector, A2UI)."
      >
        <SubNav active="/platform/" />
      </PageHero>

      <section className="blk">
        <div className="wrap">
          <div className="band">
            {thesis}
            <small>THE PLATFORM THESIS</small>
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="THE LAYERS" title="Primitives and levers." />
          <div className="grid g2">
            <div className="card">
              <span className="tag">Levers</span>
              <h3>KBG-Sentinel · Ask AI</h3>
              <p>Insight to action and insight to strategy: agents that handle exceptions, and an assistant on DuckDB, pgvector and A2UI cards.</p>
              <Link href="/platform/intelligence/ask-ai/" className="more">
                Explore &rarr;
              </Link>
            </div>
            <div className="card">
              <span className="tag">Primitives</span>
              <h3>KBG-Platform: Canon · Core · UI kit</h3>
              <p>The contracts, gate tests, primitives and visual language that make everything above it safe to rely on.</p>
              <Link href="/platform/canon/" className="more">
                Explore &rarr;
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="HOW IT TRAVELS" title="Vendor the base. Propagate the gate.">
            A product copies a base in and owns it. What spreads between products is the rule and its test, so a bug found once is not
            rediscovered in every codebase. The contract is common; the binding is specific to each product and tenant.
          </SectionHead>
          <Link href="/platform/adoption/" className="btn btn-ghost">
            How a product adopts the platform &rarr;
          </Link>
        </div>
      </section>
      <Cta />
    </>
  );
}
