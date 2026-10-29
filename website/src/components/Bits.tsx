import Link from "next/link";
import type { ReactNode } from "react";
import { statusClass, type Project } from "@/content/projects";

export function SectionHead({ idx, title, children }: { idx?: string; title: string; children?: ReactNode }) {
  return (
    <div className="sec-head">
      {idx && <span className="idx">{idx}</span>}
      <h2>{title}</h2>
      {children && <p>{children}</p>}
    </div>
  );
}

export function PageHero({ eyebrow, title, lede, children }: { eyebrow: string; title: string; lede: string; children?: ReactNode }) {
  return (
    <section className="page-hero">
      <div className="wrap">
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p className="lede">{lede}</p>
        {children}
      </div>
    </section>
  );
}

export function Cta({ title = "Build on a foundation you can trust.", text = "Tell us about your domain and we will show you how the platform fits." }: { title?: string; text?: string }) {
  return (
    <section className="cta">
      <div className="wrap">
        <span className="eyebrow">Next step</span>
        <h2>{title}</h2>
        <p>{text}</p>
        <Link href="/contact/" className="btn btn-primary">
          Talk to us &rarr;
        </Link>
      </div>
    </section>
  );
}

export function ProjectCard({ p }: { p: Project }) {
  return (
    <Link href={`/projects/${p.slug}/`} className="card">
      <div className="row">
        <span className={`badge ${statusClass[p.status]}`}>{p.status}</span>
        {p.shipped.map((l) => (
          <span key={l} className="badge layer">
            {l}
          </span>
        ))}
      </div>
      <h3>{p.name}</h3>
      <p>{p.line}</p>
      <span className="more">View project &rarr;</span>
    </Link>
  );
}

export function SubNav({ active }: { active: string }) {
  const items = [
    ["/platform/", "Overview"],
    ["/platform/canon/", "Canon"],
    ["/platform/core/", "Core & UI kit"],
    ["/platform/intelligence/ask-ai/", "Ask AI"],
    ["/platform/intelligence/sentinel/", "Sentinel"],
    ["/platform/adoption/", "Adoption"],
  ];
  return (
    <div className="subnav">
      {items.map(([href, label]) => (
        <Link key={href} href={href} className={href === active ? "on" : ""}>
          {label}
        </Link>
      ))}
    </div>
  );
}
