import Link from "next/link";
import { Cta, ProjectCard, SectionHead } from "@/components/Bits";
import { doctrines, intelligence, thesis } from "@/content/platform";
import { domains } from "@/content/domains";
import { projects } from "@/content/projects";

export default function Home() {
  const featured = projects.filter((p) => ["nextgen-fulfilment", "ecommerce-operations", "nonprofit-erp"].includes(p.slug));
  return (
    <>
      <section className="hero">
        <div className="wrap hero-grid">
          <div>
            <span className="eyebrow">AI-native business software</span>
            <h1>
              One trusted AI foundation. <span className="hl">Every domain built on it.</span>
            </h1>
            <p className="lede">
              Every KB Grid product ships with an assistant that answers, an agent that acts, and a human who signs off.
            </p>
            <div className="cta-row">
              <Link href="/platform/" className="btn btn-primary">
                Explore the platform &rarr;
              </Link>
              <Link href="/projects/" className="btn btn-ghost">
                See what we build
              </Link>
            </div>
          </div>

          <div className="stack" aria-label="Platform layers">
            <div className="stack-label">
              <span>kb grid · platform</span>
              <span>plugged into every product</span>
            </div>
            <div className="layer intel">
              <div className="stack-label">
                <span>Intelligence layer</span>
              </div>
              <div className="layer-chips">
                <span className="chip">Ask AI</span>
                <span className="chip">Ask UI</span>
                <span className="chip">Sentinel</span>
              </div>
            </div>
            <div className="pipe">▲ ▼</div>
            <div className="layer trust">
              <div className="stack-label">
                <span>Trust layer</span>
              </div>
              <div className="layer-chips">
                <span className="chip">Platform Canon</span>
                <span className="chip">Core</span>
                <span className="chip">UI Kit</span>
              </div>
            </div>
            <div className="pipe">▲ ▼</div>
            <div className="layer">
              <div className="stack-label">
                <span>Domain products</span>
              </div>
              <div className="layer-chips">
                {domains.map((d) => (
                  <span key={d.slug} className="chip">
                    {d.name}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="01 — THE IDEA" title="Contract over library.">
            {thesis}
          </SectionHead>
          <div className="grid g3">
            <div className="card">
              <span className="tag">Trust layer</span>
              <h3>Platform Canon</h3>
              <p>Nine cross-cutting surfaces and {doctrines.length} doctrines, each with the gate tests that prove it.</p>
              <Link href="/platform/canon/" className="more">
                Read the canon &rarr;
              </Link>
            </div>
            <div className="card">
              <span className="tag">Trust layer</span>
              <h3>Core &amp; UI kit</h3>
              <p>Small domain-free primitives and a shared visual language, copied into each product and owned there.</p>
              <Link href="/platform/core/" className="more">
                See the primitives &rarr;
              </Link>
            </div>
            <div className="card">
              <span className="tag">Intelligence layer</span>
              <h3>Ask AI · Ask UI · Sentinel</h3>
              <p>The assistant, the interface and the agents, built to plug into every product.</p>
              <Link href="/platform/intelligence/sentinel/" className="more">
                Meet the intelligence layer &rarr;
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="02 — INTELLIGENCE" title="An assistant that answers, an agent that acts, a human who signs off.">
            AI proposes. People approve. Only safe, reversible actions run unattended, and trust is earned on results.
          </SectionHead>
          <div className="grid g3">
            {intelligence.map((i) => (
              <Link key={i.slug} href={`/platform/intelligence/${i.slug}/`} className="card">
                <h3>{i.name}</h3>
                <p>{i.line}</p>
                <span className="more">Learn more &rarr;</span>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="03 — DOMAINS" title="The same foundation, specialised.">
            Domain capability is the platform applied to a specific kind of business.
          </SectionHead>
          <div className="grid g3">
            {domains.map((d) => (
              <Link key={d.slug} href={`/domains/${d.slug}/`} className="card">
                <h3>{d.name}</h3>
                <p>{d.line}</p>
                <span className="more">Explore &rarr;</span>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="04 — PROJECTS" title="Built on the platform.">
            A selection of what we are building and running.
          </SectionHead>
          <div className="grid g3">
            {featured.map((p) => (
              <ProjectCard key={p.slug} p={p} />
            ))}
          </div>
        </div>
      </section>

      <Cta />
    </>
  );
}
