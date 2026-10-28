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
        lede="Capabilities and projects, grouped by domain. Badges show the intelligence layers already shipped; every project is designed to plug into all three."
      />
      {domains.map((d, i) => {
        const list = projects.filter((p) => p.domain === d.slug);
        if (!list.length) return null;
        return (
          <section key={d.slug} className={`blk${i % 2 ? " alt" : ""}`} style={{ paddingTop: 56, paddingBottom: 56 }}>
            <div className="wrap">
              <h2 style={{ fontSize: 24, marginBottom: 20 }}>{d.name}</h2>
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
