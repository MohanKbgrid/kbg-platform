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
        lede="A trust layer of contracts and gate tests, and an intelligence layer of Ask AI, Ask UI and Sentinel, plugged into every product."
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
          <SectionHead idx="THE LAYERS" title="Two layers, one foundation." />
          <div className="grid g2">
            <div className="card">
              <span className="tag">Intelligence layer</span>
              <h3>Ask AI · Ask UI · Sentinel</h3>
              <p>The assistant, the interface where people decide, and the agents that handle exceptions. Built to plug into every product.</p>
              <Link href="/platform/intelligence/ask-ai/" className="more">
                Explore &rarr;
              </Link>
            </div>
            <div className="card">
              <span className="tag">Trust layer</span>
              <h3>Canon · Core · UI kit</h3>
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
