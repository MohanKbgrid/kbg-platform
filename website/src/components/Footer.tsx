import Link from "next/link";
import { site } from "@/content/site";

export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="wrap">
        <div className="foot">
          <div>
            <div className="brand">
              <span className="mark" />
              {site.name}
            </div>
            <p className="foot-tag">{site.tagline}</p>
          </div>
          <div className="foot-links">
            <div className="foot-col">
              <h4>Platform</h4>
              <Link href="/platform/canon/">Canon</Link>
              <Link href="/platform/core/">Core</Link>
              <Link href="/platform/intelligence/ask-ai/">Ask AI</Link>
              <Link href="/platform/intelligence/sentinel/">Sentinel</Link>
            </div>
            <div className="foot-col">
              <h4>Explore</h4>
              <Link href="/domains/">Domains</Link>
              <Link href="/projects/">Projects</Link>
              <Link href="/approach/">Approach</Link>
            </div>
            <div className="foot-col">
              <h4>Company</h4>
              <Link href="/about/">About</Link>
              <Link href="/trust/">Trust</Link>
              <Link href="/contact/">Contact</Link>
            </div>
          </div>
        </div>
        <div className="foot-bottom">&copy; {new Date().getFullYear()} {site.name}</div>
      </div>
    </footer>
  );
}
