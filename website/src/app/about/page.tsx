import { Cta, PageHero } from "@/components/Bits";

export const metadata = { title: "About" };

export default function About() {
  return (
    <>
      <PageHero
        eyebrow="About"
        title="A platform company, built with AI."
        lede="KB Grid builds a shared AI foundation and the domain products that run on it."
      />
      <section className="blk">
        <div className="wrap grid g2">
          <div className="card">
            <h3>What we believe</h3>
            <p>
              With AI as the engineering team, writing code is cheap and trusting it is expensive. We invest in contracts, gate tests and
              human sign-off, so every product we ship is something its owners can rely on.
            </p>
          </div>
          <div className="card">
            <h3>What we do</h3>
            <p>
              We maintain the platform canon, the core primitives, the UI kit and the intelligence layer, and apply them to healthcare,
              retail and commerce, supply chain, industrial and social-sector products.
            </p>
          </div>
        </div>
        {/* TODO(founder): add company story, team and location. */}
      </section>
      <Cta />
    </>
  );
}
