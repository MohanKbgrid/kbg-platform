/**
 * The eight states most software forgets — Experience surface, canon §06.
 *
 * These are components rather than guidance because guidance loses. Every project agrees an empty
 * state should be helpful and then ships `{rows.length === 0 && <p>No data</p>}` under deadline.
 * A component that REQUIRES the useful props makes the helpful version the path of least
 * resistance.
 *
 * The two that matter most, and are most often wrong:
 *
 *   DeniedState  — a denied action is VISIBLE with its reason, never hidden. Hiding teaches users
 *                  the feature does not exist and generates support load; showing it disabled with
 *                  "requires Plant Manager" teaches them how the organisation works. `reason` is
 *                  required by the type, so a silent denial does not compile.
 *
 *   PartialState — never fail a whole page because one widget's data did not load. Show what
 *                  arrived and NAME what did not.
 */
import type { ReactNode } from 'react';

const cls = (...xs: (string | false | undefined)[]) => xs.filter(Boolean).join(' ');

/* ── 1. Loading ─────────────────────────────────────────────────────────────────────────── */
/** A skeleton in the SHAPE of the content, not a spinner over a blank page — a spinner tells the
 *  user to wait; a skeleton tells them what is coming and stops the layout jumping when it does. */
export function LoadingState({ rows = 5, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="kbg-state kbg-state--loading" role="status" aria-live="polite" aria-busy="true">
      <span className="kbg-sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="kbg-skeleton-row" aria-hidden="true" />
      ))}
    </div>
  );
}

/* ── 2. Empty — never had data ──────────────────────────────────────────────────────────── */
/** `whatWouldFillThis` is REQUIRED. "No records found" is not an empty state; it is a shrug. */
export function EmptyState({
  title, whatWouldFillThis, action,
}: { title: string; whatWouldFillThis: string; action?: ReactNode }) {
  return (
    <div className="kbg-state kbg-state--empty">
      <p className="kbg-state__title">{title}</p>
      <p className="kbg-state__body">{whatWouldFillThis}</p>
      {action && <div className="kbg-state__action">{action}</div>}
    </div>
  );
}

/* ── 3. Empty — filtered to nothing ─────────────────────────────────────────────────────── */
/** Names the filter that caused it and offers to clear THAT one. A generic "clear all" makes the
 *  user rebuild a filter set they spent a minute on. */
export function FilteredEmptyState({
  activeFilters, onClearFilter, onClearAll,
}: {
  activeFilters: { key: string; label: string }[];
  onClearFilter: (key: string) => void;
  onClearAll?: () => void;
}) {
  return (
    <div className="kbg-state kbg-state--empty-filtered">
      <p className="kbg-state__title">Nothing matches these filters</p>
      <ul className="kbg-state__filters">
        {activeFilters.map((f) => (
          <li key={f.key}>
            {f.label}
            <button type="button" onClick={() => onClearFilter(f.key)}>clear</button>
          </li>
        ))}
      </ul>
      {onClearAll && activeFilters.length > 1 && (
        <button type="button" onClick={onClearAll}>Clear all filters</button>
      )}
    </div>
  );
}

/* ── 4. Denied ──────────────────────────────────────────────────────────────────────────── */
/**
 * ⛔ The single most-violated rule in the canon.
 *
 * `reason` is not optional. If your authority layer cannot supply one, that is the bug — fix it
 * there, do not hide the control here. `whoCan` turns a dead end into an instruction.
 *
 * Feed this from the SAME decision the API enforces with, so the disabled control and the 403 can
 * never disagree (canon RBAC §3).
 */
export function DeniedState({
  action, reason, whoCan, inline = false,
}: { action: string; reason: string; whoCan?: string; inline?: boolean }) {
  return (
    <div
      className={cls('kbg-state', 'kbg-state--denied', inline && 'kbg-state--inline')}
      role="note"
    >
      <p className="kbg-state__title">{action} is not available to you</p>
      <p className="kbg-state__body">{reason}</p>
      {whoCan && <p className="kbg-state__who">Who can: <strong>{whoCan}</strong></p>}
    </div>
  );
}

/* ── 5. Partial failure ─────────────────────────────────────────────────────────────────── */
export function PartialState({
  loaded, failed, onRetry,
}: { loaded: ReactNode; failed: { label: string; reason?: string }[]; onRetry?: () => void }) {
  return (
    <>
      {loaded}
      <div className="kbg-state kbg-state--partial" role="alert">
        <p className="kbg-state__title">Some of this did not load</p>
        <ul>
          {failed.map((f) => (
            <li key={f.label}>{f.label}{f.reason ? ` — ${f.reason}` : ''}</li>
          ))}
        </ul>
        {onRetry && <button type="button" onClick={onRetry}>Retry those</button>}
      </div>
    </>
  );
}

/* ── 6. Stale / offline ─────────────────────────────────────────────────────────────────── */
/** States WHEN the data is from. "Offline" alone leaves the user guessing whether it is minutes
 *  or days old, which is the decision they actually need to make. */
export function StaleState({
  asOf, isOffline, queuedCount,
}: { asOf: Date | string; isOffline?: boolean; queuedCount?: number }) {
  const when = typeof asOf === 'string' ? asOf : asOf.toLocaleString();
  return (
    <div className="kbg-state kbg-state--stale" role="status">
      {isOffline ? 'Offline. ' : ''}Showing data as of <strong>{when}</strong>. It may have moved.
      {typeof queuedCount === 'number' && queuedCount > 0 && (
        <> <strong>{queuedCount}</strong> change{queuedCount === 1 ? '' : 's'} waiting to sync.</>
      )}
    </div>
  );
}

/* ── 7. Too much ────────────────────────────────────────────────────────────────────────── */
/** Above a threshold, insist on a filter rather than rendering 40,000 rows. Refusing is kinder
 *  than a frozen tab, and honest about why. */
export function TooMuchState({
  matched, threshold, suggestion,
}: { matched: number; threshold: number; suggestion?: ReactNode }) {
  return (
    <div className="kbg-state kbg-state--too-much">
      <p className="kbg-state__title">{matched.toLocaleString()} rows match</p>
      <p className="kbg-state__body">
        That is more than this view renders at once ({threshold.toLocaleString()}). Narrow it and
        the full set stays available to export.
      </p>
      {suggestion && <div className="kbg-state__action">{suggestion}</div>}
    </div>
  );
}

/* ── 8. Error ───────────────────────────────────────────────────────────────────────────── */
/** `reference` is required: a user reporting "it broke" costs an hour; a user reporting a
 *  reference costs a query. */
export function ErrorState({
  whatHappened, whatToDo, reference, onRetry,
}: { whatHappened: string; whatToDo: string; reference: string; onRetry?: () => void }) {
  return (
    <div className="kbg-state kbg-state--error" role="alert">
      <p className="kbg-state__title">{whatHappened}</p>
      <p className="kbg-state__body">{whatToDo}</p>
      <p className="kbg-state__ref">Reference: <code>{reference}</code></p>
      {onRetry && <button type="button" onClick={onRetry}>Try again</button>}
    </div>
  );
}
