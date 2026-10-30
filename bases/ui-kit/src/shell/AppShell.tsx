// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * AppShell - one chrome for every screen of an app: skip link, top bar, grouped navigation, main.
 *
 * Router-agnostic on purpose. Navigation entries carry an `href`; the shell renders plain anchors
 * unless the app passes `renderLink`, which is where a client-side router plugs in. The shell never
 * imports one, so a product's choice of router is never forced by the kit.
 *
 *   top bar    [menu button < 768px]  brand ......... slots: sync, search, account
 *   sidebar    grouped sections, each collapsible; the current entry carries aria-current="page"
 *   widths     >= 768 sidebar beside the content; < 768 off-canvas behind the menu button
 *   floor      every control is at least --kbg-touch-min tall (see tokens.css)
 *
 * Collapse state and "which entry is current" are owned by the caller (`currentKey`) or by native
 * <details>; the shell keeps only the open/closed state of the small-screen menu.
 */
import { useId, useState, type ReactNode } from 'react';

export interface NavEntry {
  key: string;
  label: string;
  href: string;
  /** A count shown beside the label (e.g. waiting items). 0 or undefined shows nothing. */
  badge?: number;
  /** Group heading; entries without one sit at the top level. */
  group?: string;
}

export interface NavLinkProps {
  href: string;
  className: string;
  'aria-current'?: 'page';
  onClick?: () => void;
  children: ReactNode;
}

export interface AppShellProps {
  appName: string;
  nav: NavEntry[];
  currentKey: string;
  /** Plug a router's link in here; the default is a plain anchor. */
  renderLink?: (entry: NavEntry, props: NavLinkProps) => ReactNode;
  /** Header slots. Put a SyncIndicator in `status`: it must never be hidden when healthy. */
  status?: ReactNode;
  search?: ReactNode;
  account?: ReactNode;
  children: ReactNode;
}

/** Group entries preserving first-seen order of groups and of entries within them. */
export function groupNav(nav: NavEntry[]): { group: string | null; entries: NavEntry[] }[] {
  const out: { group: string | null; entries: NavEntry[] }[] = [];
  for (const e of nav) {
    const g = e.group ?? null;
    let bucket = out.find((b) => b.group === g);
    if (!bucket) { bucket = { group: g, entries: [] }; out.push(bucket); }
    bucket.entries.push(e);
  }
  return out;
}

const defaultLink = (_e: NavEntry, p: NavLinkProps) => <a {...p} />;

export function AppShell({
  appName, nav, currentKey, renderLink = defaultLink, status, search, account, children,
}: AppShellProps) {
  const [open, setOpen] = useState(false);
  const navId = useId();
  const mainId = `${navId}-main`;
  const close = () => setOpen(false);

  const link = (e: NavEntry) => {
    const current = e.key === currentKey;
    const inner = (
      <>
        <span className="kbg-shell__label">{e.label}</span>
        {e.badge && e.badge > 0 ? (
          <span className="kbg-shell__badge" aria-label={`${e.badge} waiting`}>{e.badge}</span>
        ) : null}
      </>
    );
    return renderLink(e, {
      href: e.href,
      className: `kbg-shell__link${current ? ' kbg-shell__link--current' : ''}`,
      'aria-current': current ? 'page' : undefined,
      onClick: close,
      children: inner,
    });
  };

  return (
    <div className="kbg-shell" data-menu-open={open ? 'true' : 'false'}>
      <a className="kbg-shell__skip" href={`#${mainId}`}>Skip to content</a>
      <header className="kbg-shell__bar">
        <button
          type="button" className="kbg-shell__menu" aria-controls={navId} aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          <span className="kbg-sr-only">{open ? 'Close menu' : 'Open menu'}</span>
          <span aria-hidden="true">{open ? '✕' : '☰'}</span>
        </button>
        <span className="kbg-shell__brand">{appName}</span>
        <span className="kbg-shell__spacer" />
        {status && <div className="kbg-shell__slot kbg-shell__status">{status}</div>}
        {search && <div className="kbg-shell__slot">{search}</div>}
        {account && <div className="kbg-shell__slot">{account}</div>}
      </header>
      <div className="kbg-shell__body">
        <nav id={navId} className="kbg-shell__nav" aria-label={`${appName} navigation`}>
          {groupNav(nav).map((b) =>
            b.group === null ? (
              <ul key="__top" className="kbg-shell__list">
                {b.entries.map((e) => <li key={e.key}>{link(e)}</li>)}
              </ul>
            ) : (
              <details key={b.group} className="kbg-shell__group" open>
                <summary>{b.group}</summary>
                <ul className="kbg-shell__list">
                  {b.entries.map((e) => <li key={e.key}>{link(e)}</li>)}
                </ul>
              </details>
            ),
          )}
        </nav>
        <main id={mainId} className="kbg-shell__main" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}
