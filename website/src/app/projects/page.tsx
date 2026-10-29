import { Cta, PageHero, ProjectCard } from "@/components/Bits";
import { domains } from "@/content/domains";
import { projects } from "@/content/projects";

export const metadata = { title: "Projects" };

export default function Projects() {
  return (
    <>
      <PageHero
        eyebrow="Projects"
        title="What we build on the platform."
        lede="Applications grouped by domain. Badges show the intelligence already shipped; every application is designed to plug into Ask AI and Sentinel."
      />
      {domains.map((d, i) => {
        const list = projects.filter((p) => p.domain === d.slug);
        if (!list.length) return null;
        return (
          <section key={d.slug} className={`blk${i % 2 ? " alt" : ""}`} style={{ paddingTop: 24, paddingBottom: 24 }}>
            <div className="wrap">
              <h2 style={{ fontSize: 24, marginBottom: 12 }}>{d.name}</h2>
              <div className="grid g3">
                {list.map((p) => (
                  <ProjectCard key={p.slug} p={p} />
                ))}
              </div>
            </div>
          </section>
        );
      })}
      <Cta />
    </>
  );
}
