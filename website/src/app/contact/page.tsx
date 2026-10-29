import { PageHero } from "@/components/Bits";
import { site } from "@/content/site";

export const metadata = { title: "Contact" };

export default function Contact() {
  return (
    <>
      <PageHero
        eyebrow="Contact"
        title="Tell us about your domain."
        lede="We will show you how the platform and the intelligence layer fit."
      />
      <section className="blk">
        <div className="wrap">
          <div className="card" style={{ maxWidth: 560 }}>
            <span className="tag">Email</span>
            <h3>
              <a href={`mailto:${site.contactEmail}`} style={{ color: "var(--accent)" }}>
                {site.contactEmail}
              </a>
            </h3>
            <p>Tell us your domain and what you want to run on the platform. We reply personally.</p>
          </div>
        </div>
      </section>
    </>
  );
}
