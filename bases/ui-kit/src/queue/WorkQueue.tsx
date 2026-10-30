// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * WorkQueue - one inbox of the decisions waiting on the signed-in person.
 *
 * PRESENTATION ONLY. Routing, risk ordering, who may act and why not are all computed by the
 * server; this component renders the answer. Two consequences, both deliberate:
 *
 *   - It never re-sorts. `items` arrive in the server's priority order and are shown in that order,
 *     with `orderNote` saying what the order means.
 *   - Every action carries the server's own decision. A refused action is shown disabled WITH the
 *     server's kind and reason (AccessControl), never hidden and never given a reason invented here.
 */
import type { ReactNode } from 'react';
import { AccessControl } from '../access/AccessControl.js';
import type { AccessDecision } from '../access/denial.js';
import { StatusChip, type ChipTone } from '../StatusChip.js';
import { EmptyState, ErrorState, LoadingState } from '../states/States.js';
import type { TableError } from '../table/ServerDataTable.js';

export interface WorkItem {
  id: string;
  /** One readable line, written by the server: what needs deciding. */
  summary: string;
  /** Plain-words category, e.g. "Purchase approval". */
  typeLabel: string;
  status: string;
  /** ISO timestamp the item is due, if it has a deadline. */
  dueAt?: string | null;
  overdue?: boolean;
  /** Server-computed ranking score; shown, never recomputed. */
  riskScore?: number;
  raisedBy?: string | null;
  /** Decision per action key, e.g. { claim, approve, reassign }. */
  actions: Record<string, AccessDecision>;
}

export interface WorkQueueProps {
  title?: string;
  items: WorkItem[];
  loading?: boolean;
  error?: TableError | null;
  onRetry?: () => void;
  /** Says what the order means, e.g. "Most overdue first". Required so the order is never a mystery. */
  orderNote: string;
  onAction: (itemId: string, actionKey: string) => void;
  /** Display names per action key; the key itself is shown when none is given. */
  actionLabels?: Record<string, string>;
  statusTones?: Record<string, ChipTone>;
  /** Shown when the queue is empty because the person holds no position yet. */
  unbound?: boolean;
  /** Formats a due date for display. Defaults to a fixed UTC form so output never varies by locale. */
  formatDue?: (iso: string) => string;
  header?: ReactNode;
}

export function defaultFormatDue(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return `${new Date(t).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

const humanise = (k: string) => k.charAt(0).toUpperCase() + k.slice(1).replace(/_/g, ' ');

export function WorkQueue({
  title = 'My queue', items, loading, error, onRetry, orderNote, onAction, actionLabels,
  statusTones, unbound, formatDue = defaultFormatDue, header,
}: WorkQueueProps) {
  let body: ReactNode;
  if (error) body = <ErrorState {...error} onRetry={onRetry} />;
  else if (loading) body = <LoadingState label="Loading your queue" />;
  else if (unbound) {
    body = (
      <EmptyState
        title="Your login is not linked to a position yet"
        whatWouldFillThis="Work is routed to positions. Once an administrator links yours, items addressed to it appear here."
      />
    );
  } else if (items.length === 0) {
    body = (
      <EmptyState
        title="Nothing is waiting on you"
        whatWouldFillThis="Items appear here when someone raises a request that needs your decision."
      />
    );
  } else {
    body = (
      <ol className="kbg-queue__list">
        {items.map((it) => (
          <li key={it.id} className="kbg-queue__item" data-overdue={it.overdue ? 'true' : undefined}>
            <div className="kbg-queue__head">
              <span className="kbg-queue__type">{it.typeLabel}</span>
              <StatusChip value={it.status} toneMap={statusTones} />
              {it.overdue && <StatusChip value="overdue" />}
            </div>
            <p className="kbg-queue__summary">{it.summary}</p>
            <p className="kbg-queue__meta">
              {it.raisedBy ? <>Raised by {it.raisedBy}. </> : null}
              {it.dueAt ? <>Due <time dateTime={it.dueAt}>{formatDue(it.dueAt)}</time>. </> : null}
              {typeof it.riskScore === 'number' ? <>Priority score {it.riskScore}.</> : null}
            </p>
            <div className="kbg-queue__actions">
              {Object.entries(it.actions).map(([key, decision]) => {
                const label = actionLabels?.[key] ?? humanise(key);
                return (
                  <AccessControl key={key} action={label} decision={decision}>
                    <button type="button" onClick={() => onAction(it.id, key)}>{label}</button>
                  </AccessControl>
                );
              })}
            </div>
          </li>
        ))}
      </ol>
    );
  }
  return (
    <section className="kbg-queue" aria-label={title}>
      <h2 className="kbg-queue__title">{title}</h2>
      {header}
      {!loading && !error && items.length > 0 && <p className="kbg-queue__order">{orderNote}</p>}
      {body}
    </section>
  );
}
