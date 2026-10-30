// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * AuditLog - "who did what, to what, when, and was it allowed".
 *
 * PRESENTATION ONLY: the caller fetches. The log records allowed and denied decisions alike, so the
 * result column always prints its word ("allowed" / "denied") - a log that only showed refusals
 * could not answer "who COULD have done this". Request bodies are never in these rows by design;
 * this component has nowhere to show one.
 *
 * Reading the log is itself an authority question. Pass `access` and a person without it sees a
 * denial with its reason rather than an empty table that looks like "nothing happened".
 */
import type { ReactNode } from 'react';
import type { AccessDecision } from '../access/denial.js';
import { PermissionGate } from '../access/AccessControl.js';
import { StatusChip, type ChipTone } from '../StatusChip.js';
import { ServerDataTable, type ServerColumn, type TableError } from '../table/ServerDataTable.js';
import type { ActiveFilter } from '../table/DataTable.js';

export interface AuditRow {
  id: string;
  /** ISO timestamp. */
  at: string;
  actor: string | null;
  /** If the actor acted on someone's behalf, who that was. Both identities are shown. */
  actedFor?: string | null;
  action: string;
  objectType?: string | null;
  objectRef?: string | null;
  allowed: boolean;
  /** Why it was refused, when it was. */
  reason?: string | null;
}

export interface AuditGroup { key: string; count: number; denied: number }

export interface AuditLogProps {
  title?: string;
  rows: AuditRow[];
  totalCount: number;
  page: number;
  pageSize: number;
  onPageChange: (p: number) => void;
  onPageSizeChange?: (n: number) => void;
  /** Optional per-group counts shown above the table; selecting one is the caller's filter. */
  groups?: AuditGroup[];
  groupLabel?: string;
  activeGroup?: string | null;
  onSelectGroup?: (key: string | null) => void;
  actorFilter?: string;
  onActorFilterChange?: (v: string) => void;
  loading?: boolean;
  error?: TableError | null;
  onRetry?: () => void;
  /** Decision for reading the log at all. Omit it when the caller has already gated the screen. */
  access?: AccessDecision;
  formatAt?: (iso: string) => string;
  activeFilters?: ActiveFilter[];
  onClearFilter?: (key: string) => void;
  footnote?: ReactNode;
}

export function defaultFormatAt(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return `${new Date(t).toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

const RESULT_TONES: Record<string, ChipTone> = { allowed: 'good', denied: 'critical' };

export function AuditLog(p: AuditLogProps) {
  const {
    title = 'Audit log', groups, groupLabel = 'Group', activeGroup, onSelectGroup,
    actorFilter, onActorFilterChange, formatAt = defaultFormatAt, access,
  } = p;

  const columns: ServerColumn<AuditRow>[] = [
    { key: 'at', header: 'When', nowrap: true, render: (r) => <time dateTime={r.at}>{formatAt(r.at)}</time> },
    {
      key: 'actor', header: 'Who',
      render: (r) => (
        <>
          {r.actor ?? <i>not signed in</i>}
          {r.actedFor ? <span className="kbg-audit__for"> (acting for {r.actedFor})</span> : null}
        </>
      ),
    },
    { key: 'action', header: 'Action', render: (r) => [r.action, r.objectType, r.objectRef].filter(Boolean).join(' ') },
    {
      key: 'result', header: 'Result',
      render: (r) => (
        <>
          <StatusChip value={r.allowed ? 'allowed' : 'denied'} toneMap={RESULT_TONES} />
          {!r.allowed && r.reason ? <span className="kbg-audit__why"> {r.reason}</span> : null}
        </>
      ),
    },
  ];

  const content = (
    <>
      {groups && groups.length > 0 && (
        <table className="kbg-table kbg-table--compact kbg-audit__groups">
          <caption className="kbg-sr-only">Activity by {groupLabel.toLowerCase()}</caption>
          <thead><tr><th scope="col">{groupLabel}</th><th scope="col">Actions</th><th scope="col">Denied</th></tr></thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.key}>
                <td>
                  <button
                    type="button" aria-pressed={activeGroup === g.key}
                    onClick={() => onSelectGroup?.(activeGroup === g.key ? null : g.key)}
                  >
                    {g.key}
                  </button>
                </td>
                <td>{g.count}</td>
                <td>{g.denied}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {onActorFilterChange && (
        <label className="kbg-audit__filter">
          Filter by person{' '}
          <input type="search" value={actorFilter ?? ''} onChange={(e) => onActorFilterChange(e.target.value)} />
        </label>
      )}
      <ServerDataTable<AuditRow>
        caption={title}
        columns={columns}
        rows={p.rows}
        getRowKey={(r) => r.id}
        totalCount={p.totalCount}
        page={p.page}
        pageSize={p.pageSize}
        onPageChange={p.onPageChange}
        onPageSizeChange={p.onPageSizeChange}
        loading={p.loading}
        error={p.error}
        onRetry={p.onRetry}
        activeFilters={p.activeFilters}
        onClearFilter={p.onClearFilter}
        empty={{
          title: 'No activity in this window',
          whatWouldFillThis: 'Every change made through the system is recorded here as it happens.',
        }}
      />
      {p.footnote && <p className="kbg-audit__note">{p.footnote}</p>}
    </>
  );

  return (
    <section className="kbg-audit" aria-label={title}>
      <h2 className="kbg-audit__title">{title}</h2>
      {access === undefined ? content : <PermissionGate action={title} decision={access}>{content}</PermissionGate>}
    </section>
  );
}
