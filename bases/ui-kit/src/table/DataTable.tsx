// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * DataTable - the plain table every list reuses instead of re-coding <table> per screen.
 *
 * It renders the rows it is GIVEN, in the order it is given them. It never sorts or filters:
 * for anything that can outgrow one page, use ServerDataTable, where the server ranks the whole
 * matched set and only then pages it. A table that re-sorted the current page would quietly break
 * that contract (canon Experience, table rule 1).
 *
 * The empty state is a required prop, not an afterthought: "No rows" is a shrug, not a state.
 */
import type { KeyboardEvent, ReactNode } from 'react';
import { EmptyState, FilteredEmptyState, LoadingState } from '../states/States.js';

export type Density = 'compact' | 'comfortable';

export interface Column<T> {
  key: string;
  header: ReactNode;
  align?: 'left' | 'right' | 'center';
  /** Custom cell; without it the cell shows `row[key]`. */
  render?: (row: T) => ReactNode;
  width?: number | string;
  nowrap?: boolean;
}

export interface EmptyCopy {
  title: string;
  whatWouldFillThis: string;
  action?: ReactNode;
}

export interface ActiveFilter { key: string; label: string }

export interface DataTableProps<T> {
  /** Accessible name of the table; also shown as its caption for screen readers. */
  caption: string;
  columns: Column<T>[];
  rows: T[];
  getRowKey: (row: T, index: number) => string | number;
  empty: EmptyCopy;
  /** When rows is empty AND filters are active the empty state names the filter instead. */
  activeFilters?: ActiveFilter[];
  onClearFilter?: (key: string) => void;
  onClearAll?: () => void;
  loading?: boolean;
  density?: Density;
  /** Keys of the columns to show, in order. Undefined shows every column. */
  visibleColumns?: string[];
  /** Whole-row click; the row also becomes keyboard-operable (Enter / Space). */
  onRowClick?: (row: T) => void;
  rowClassName?: (row: T) => string | undefined;
}

export function pickColumns<T>(columns: Column<T>[], visible?: string[]): Column<T>[] {
  if (!visible) return columns;
  const byKey = new Map(columns.map((c) => [c.key, c]));
  return visible.map((k) => byKey.get(k)).filter((c): c is Column<T> => c !== undefined);
}

export function cellValue<T>(c: Column<T>, row: T): ReactNode {
  if (c.render) return c.render(row);
  const v = (row as Record<string, unknown>)[c.key];
  return v === null || v === undefined ? '' : (v as ReactNode);
}

export function DataTable<T>({
  caption, columns, rows, getRowKey, empty, activeFilters, onClearFilter, onClearAll,
  loading, density = 'compact', visibleColumns, onRowClick, rowClassName,
}: DataTableProps<T>) {
  if (loading) return <LoadingState label={`Loading ${caption}`} />;
  if (rows.length === 0) {
    if (activeFilters && activeFilters.length > 0) {
      return (
        <FilteredEmptyState
          activeFilters={activeFilters}
          onClearFilter={onClearFilter ?? (() => undefined)}
          onClearAll={onClearAll}
        />
      );
    }
    return <EmptyState title={empty.title} whatWouldFillThis={empty.whatWouldFillThis} action={empty.action} />;
  }

  const cols = pickColumns(columns, visibleColumns);
  const keyActivate = (row: T) => (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick?.(row); }
  };
  return (
    <div className="kbg-table-wrap">
      <table className={`kbg-table kbg-table--${density}`}>
        <caption className="kbg-sr-only">{caption}</caption>
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c.key} scope="col" style={{ width: c.width, textAlign: c.align }}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={getRowKey(row, i)}
              className={rowClassName?.(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              onKeyDown={onRowClick ? keyActivate(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              data-clickable={onRowClick ? 'true' : undefined}
            >
              {cols.map((c) => (
                <td key={c.key} style={{ textAlign: c.align, whiteSpace: c.nowrap ? 'nowrap' : undefined }}>
                  {cellValue(c, row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
