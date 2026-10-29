import Link from "next/link";
import { notFound } from "next/navigation";
import { Cta, PageHero, ProjectCard, SectionHead } from "@/components/Bits";
import { domains } from "@/content/domains";
import { projects } from "@/content/projects";

export function generateStaticParams() {
  return domains.map((d) => ({ slug: d.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return { title: domains.find((d) => d.slug === slug)?.name ?? "Domain" };
}

export default async function DomainPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const d = domains.find((x) => x.slug === slug);
  if (!d) notFound();
  const list = projects.filter((p) => d.projects.includes(p.slug));

  return (
    <>
      <PageHero eyebrow={`Domain · ${d.name}`} title={d.name} lede={d.line} />

      <section className="blk">
        <div className="wrap grid g2">
          <div className="card">
            <span className="tag">The problem</span>
            <p style={{ fontSize: 17 }}>{d.problem}</p>
          </div>
          <div className="card">
            <span className="tag">Capabilities</span>
            <ul className="bullets">
              {d.capabilities.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="ON THE PLATFORM" title="Ask AI and Sentinel included.">
            Every product in this domain is built to plug into the intelligence layer, on top of the same canon and core.
          </SectionHead>
          <Link href="/platform/" className="btn btn-ghost">
            See the platform &rarr;
          </Link>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="PROJECTS" title={`Projects in ${d.name.toLowerCase()}`} />
          <div className="grid g3">
            {list.map((p) => (
              <ProjectCard key={p.slug} p={p} />
            ))}
          </div>
        </div>
      </section>
      <Cta />
    </>
  );
}
