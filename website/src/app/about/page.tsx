import { Cta, PageHero, SectionHead } from "@/components/Bits";
import { team } from "@/content/team";

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
        {/* TODO(founder): add company story and location. */}
      </section>
      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="THE TEAM" title="Who designs and builds it." />
          <div className="grid g2">
            {team.map((m) => (
              <div className="card" key={m.name}>
                <h3>{m.name}</h3>
                <span className="tag">{m.role}</span>
                <p>{m.bio}</p>
              </div>
            ))}
            <div className="card">
              <h3>Claude, built in</h3>
              <p>AI is part of every step: design, the traceability register and an independent tester that checks each change against its requirements.</p>
            </div>
          </div>
        </div>
      </section>
      <Cta />
    </>
  );
}
