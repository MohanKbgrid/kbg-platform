import { Cta, PageHero, SectionHead, SubNav } from "@/components/Bits";
import { doctrines, surfaces } from "@/content/platform";

export const metadata = { title: "Platform Canon" };

export default function Canon() {
  return (
    <>
      <PageHero
        eyebrow="Platform · Canon"
        title="Nine surfaces. Twelve doctrines."
        lede="The cross-cutting needs every business application has and keeps rebuilding badly, written as contracts with acceptance gates."
      >
        <SubNav active="/platform/canon/" />
      </PageHero>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="THE SURFACES" title="Adopted in coupling order.">
            Each wave depends on the one before it. Money comes last, deliberately.
          </SectionHead>
          <div className="hair g3">
            {surfaces.map((s) => (
              <div key={s.n}>
                <div className="num">{String(s.n).padStart(2, "0")}</div>
                <span className="tag mono" style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--ink-3)" }}>
                  {s.wave}
                </span>
                <h3 style={{ marginTop: 6 }}>{s.name}</h3>
                <p>{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="blk alt">
        <div className="wrap">
          <SectionHead idx="THE DOCTRINES" title="Each one exists because something went wrong.">
            They are not style. Breaking one produces a specific, observed class of bug.
          </SectionHead>
          <div className="hair g2">
            {doctrines.map((d, i) => (
              <div key={d}>
                <div className="num">D{i + 1}</div>
                <h3>{d}</h3>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="blk">
        <div className="wrap">
          <SectionHead idx="COMMON VS SPECIFIC" title="The contract is common. The binding is not.">
            Accounting, integration and UI exist as shared patterns only. Chart of accounts, connectors and palette values are specific to each
            product or tenant, and Config is what carries that difference.
          </SectionHead>
        </div>
      </section>
      <Cta />
    </>
  );
}
