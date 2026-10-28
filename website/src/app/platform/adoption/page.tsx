import { Cta, PageHero, SectionHead, SubNav } from "@/components/Bits";
import { adoption, surfaces } from "@/content/platform";

export const metadata = { title: "Adopting the platform" };

export default function Adoption() {
  return (
    <>
      <PageHero
        eyebrow="Platform · Adoption"
        title="Born on it, or moved onto it."
        lede="Two paths onto the platform, both surface by surface and gate by gate."
      >
        <SubNav active="/platform/adoption/" />
      </PageHero>
      <section className="blk">
        <div className="wrap">
          <div className="grid g2">
            {adoption.map((a) => (
              <div key={a.name} className="card">
                <h3>{a.name}</h3>
                <p>{a.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="ORDER" title="Nine surfaces, in this order.">
            {surfaces.map((s) => s.name).join(" → ")}
          </SectionHead>
        </div>
      </section>
      <Cta />
    </>
  );
}
