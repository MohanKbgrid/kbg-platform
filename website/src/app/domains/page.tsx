import Link from "next/link";
import { Cta, PageHero } from "@/components/Bits";
import { domains } from "@/content/domains";

export const metadata = { title: "Domains" };

export default function Domains() {
  return (
    <>
      <PageHero
        eyebrow="Domains"
        title="The platform, applied."
        lede="Each domain is the same foundation specialised for a kind of business, with Ask AI, Ask UI and Sentinel built to plug in."
      />
      <section className="blk">
        <div className="wrap grid g2">
          {domains.map((d) => (
            <Link key={d.slug} href={`/domains/${d.slug}/`} className="card">
              <h3>{d.name}</h3>
              <p>{d.line}</p>
              <ul className="bullets" style={{ marginTop: 6 }}>
                {d.capabilities.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
              <span className="more">Explore &rarr;</span>
            </Link>
          ))}
        </div>
      </section>
      <Cta />
    </>
  );
}
