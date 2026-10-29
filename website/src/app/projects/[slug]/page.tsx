import Link from "next/link";
import { notFound } from "next/navigation";
import { Cta, PageHero } from "@/components/Bits";
import { domains } from "@/content/domains";
import { projects } from "@/content/projects";

export function generateStaticParams() {
  return projects.map((p) => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return { title: projects.find((p) => p.slug === slug)?.name ?? "Project" };
}

export default async function ProjectPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const p = projects.find((x) => x.slug === slug);
  if (!p) notFound();
  const domain = domains.find((d) => d.slug === p.domain);

  return (
    <>
      <PageHero eyebrow={`Project · ${domain?.name ?? ""}`} title={p.name} lede={p.line}>
        <div className="row" style={{ marginTop: 22 }}>
          {p.shipped.map((l) => (
            <span key={l} className="badge layer">
              {l} shipped
            </span>
          ))}
        </div>
      </PageHero>

      <section className="blk">
        <div className="wrap grid g2">
          <div className="card">
            <span className="tag">Capabilities</span>
            <ul className="bullets">
              {p.capabilities.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
          <div className="card">
            <span className="tag">Built on the platform</span>
            <p>
              Designed on the Platform Canon and Core, with Ask AI and Sentinel built to plug in.
              {p.shipped.length ? ` Already shipped here: ${p.shipped.join(", ")}.` : ""}
            </p>
            <span className="tag" style={{ marginTop: 12 }}>
              Stack
            </span>
            <p className="stack-line">{p.stack}</p>
            <Link href="/platform/" className="more">
              About the platform &rarr;
            </Link>
          </div>
        </div>
      </section>
      <Cta />
    </>
  );
}
