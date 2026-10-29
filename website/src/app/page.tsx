import Link from "next/link";
import { Cta, ProjectCard, SectionHead } from "@/components/Bits";
import { projects } from "@/content/projects";

const flagship = ["retail-pos", "p2p", "fabrication-erp"];

export default function Home() {
  const apps = projects.filter((p) => flagship.includes(p.slug));
  const others = projects.filter((p) => !flagship.includes(p.slug));
  return (
    <>
      <section className="hero">
        <div className="wrap hero-grid">
          <div>
            <span className="eyebrow">AI-native business software</span>
            <h1>
              One trusted AI foundation. <span className="hl">Every application on top of it.</span>
            </h1>
            <p className="lede">
              Every KB Grid application ships with an assistant that answers, an agent that acts, and a human who signs off.
            </p>
            <div className="cta-row">
              <Link href="/platform/" className="btn btn-primary">
                Explore the platform &rarr;
              </Link>
              <Link href="/projects/" className="btn btn-ghost">
                See the applications
              </Link>
            </div>
          </div>

          <div className="stack" aria-label="Platform layers">
            <div className="layer">
              <div className="stack-label">
                <span>Applications</span>
                <span>sit on top</span>
              </div>
              <div className="layer-chips">
                <span className="chip">POS</span>
                <span className="chip">P2P</span>
                <span className="chip">AuraFab</span>
                <span className="chip">+ more</span>
              </div>
            </div>
            <div className="pipe">▲ ▼</div>
            <div className="layer intel">
              <div className="stack-label">
                <span>Insight to action · insight to strategy</span>
              </div>
              <div className="layer-chips">
                <span className="chip">KBG-Sentinel</span>
                <span className="chip">Ask AI</span>
                <span className="chip">DuckDB</span>
                <span className="chip">pgvector</span>
                <span className="chip">A2UI</span>
              </div>
            </div>
            <div className="pipe">▲ ▼</div>
            <div className="layer trust">
              <div className="stack-label">
                <span>Platform primitives</span>
              </div>
              <div className="layer-chips">
                <span className="chip">KBG-Platform</span>
                <span className="chip">Canon</span>
                <span className="chip">Core</span>
                <span className="chip">UI Kit</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="THE PLATFORM" title="Primitives and levers, built in." />
          <div className="grid g3">
            <Link href="/platform/canon/" className="card">
              <span className="tag">Primitive</span>
              <h3>KBG-Platform</h3>
              <p>Canon, core and UI kit: contracts and gate tests that travel between products.</p>
            </Link>
            <Link href="/platform/intelligence/sentinel/" className="card">
              <span className="tag">Insight to action</span>
              <h3>KBG-Sentinel</h3>
              <p>Agents that recognise exceptions, resolve what is safe and hand the rest to a person.</p>
            </Link>
            <Link href="/platform/intelligence/ask-ai/" className="card">
              <span className="tag">Insight to strategy</span>
              <h3>Ask AI</h3>
              <p>Ask the business a question. DuckDB analytics, pgvector retrieval and A2UI review cards.</p>
            </Link>
          </div>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="APPLICATIONS" title="Built on the platform." />
          <div className="grid g3">
            {apps.map((p) => (
              <ProjectCard key={p.slug} p={p} />
            ))}
          </div>
          <p className="stack-line" style={{ marginTop: 18 }}>
            Also on the platform:{" "}
            {others.map((p, i) => (
              <span key={p.slug}>
                {i > 0 && " · "}
                <Link href={`/projects/${p.slug}/`}>{p.name}</Link>
              </span>
            ))}
          </p>
        </div>
      </section>

      <Cta />
    </>
  );
}
