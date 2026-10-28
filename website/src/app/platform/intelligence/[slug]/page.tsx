import { notFound } from "next/navigation";
import { Cta, PageHero, SectionHead, SubNav } from "@/components/Bits";
import { guarantees, intelligence, openStack, pipeline } from "@/content/platform";

export function generateStaticParams() {
  return intelligence.map((i) => ({ slug: i.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const item = intelligence.find((i) => i.slug === slug);
  return { title: item?.name ?? "Intelligence" };
}

export default async function IntelPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const item = intelligence.find((i) => i.slug === slug);
  if (!item) notFound();

  return (
    <>
      <PageHero eyebrow="Platform · Intelligence" title={item.name} lede={item.line}>
        <SubNav active={`/platform/intelligence/${item.slug}/`} />
      </PageHero>

      <section className="blk">
        <div className="wrap">
          <div className="grid g2">
            <div style={{ display: "grid", gap: 16 }}>
              {item.body.map((b) => (
                <p key={b} style={{ fontSize: 17, color: "var(--ink-2)", lineHeight: 1.65 }}>
                  {b}
                </p>
              ))}
            </div>
            <div className="hair">
              {item.points.map((p) => (
                <div key={p.k}>
                  <h3>{p.k}</h3>
                  <p>{p.v}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {item.slug === "sentinel" && (
        <>
          <section className="blk alt">
            <div className="wrap">
              <SectionHead idx="THE PIPELINE" title="From event to learning." />
              <div className="row" style={{ gap: 10 }}>
                {pipeline.map((s, i) => (
                  <span key={s} className="badge layer" style={{ fontSize: 12, padding: "8px 14px" }}>
                    {String(i + 1).padStart(2, "0")} · {s}
                  </span>
                ))}
              </div>
            </div>
          </section>
          <section className="blk">
            <div className="wrap">
              <SectionHead idx="WHAT IS GUARANTEED" title="Autonomy with a ceiling." />
              <div className="hair g2">
                {guarantees.map((g) => (
                  <div key={g.k}>
                    <h3>{g.k}</h3>
                    <p>{g.v}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
          <section className="blk alt">
            <div className="wrap">
              <SectionHead idx="OPEN-SOURCE STACK" title="Self-hosts anywhere.">
                Everything runs on open-source components. The frontier model is optional.
              </SectionHead>
              <table className="table">
                <tbody>
                  {openStack.map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ color: "var(--ink-2)", fontFamily: "var(--sans)" }}>{k}</td>
                      <td>{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {item.slug === "ask-ai" && (
        <section className="blk alt">
          <div className="wrap">
            <SectionHead idx="THE RULES IT FOLLOWS" title="Grounded or nothing.">
              The Runtime AI contract: a draft asserts only what is in its source, shows confidence per field, and has no path to a posted
              document that skips a named human. A disabled capability is absent, and a stubbed provider says so.
            </SectionHead>
          </div>
        </section>
      )}
      <Cta />
    </>
  );
}
