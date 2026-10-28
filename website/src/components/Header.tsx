"use client";

import Link from "next/link";
import { useState } from "react";
import { site } from "@/content/site";
import ThemeToggle from "./ThemeToggle";

export default function Header() {
  const [open, setOpen] = useState(false);
  return (
    <header className="site-header">
      <div className="wrap nav">
        <Link href="/" className="brand" aria-label={`${site.name} home`}>
          <span className="mark" />
          {site.name}
        </Link>
        <nav className={`navlinks${open ? " open" : ""}`}>
          {site.nav.map((n) => (
            <Link key={n.href} href={n.href} className="nl" onClick={() => setOpen(false)}>
              {n.label}
            </Link>
          ))}
          <ThemeToggle />
          <Link href="/contact/" className="btn btn-primary">
            Talk to us
          </Link>
          <button className="theme-toggle menu-btn" aria-label="Menu" onClick={() => setOpen(!open)}>
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M2 4h12M2 8h12M2 12h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </nav>
      </div>
    </header>
  );
}
