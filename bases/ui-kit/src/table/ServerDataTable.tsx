// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * ServerDataTable - the table contract for lists that can outgrow a page.
 *
 *   1. Sort, filter and page happen on the SERVER, over the WHOLE matched set, ranked BEFORE
 *      limited. Limiting first silently drops the highest-priority row at scale.
 *   2. The count shown is the count of ALL matching rows ("26-50 of 4,213 matching"), never "of 50".
 *   3. Above `tooMuchThreshold` matches the table refuses to render and asks for a filter.
 *   4. The totals footer says what it covers.
 *
 * DELIBERATELY NOT SMART. It holds no state and calls no API. Sort, page and page size are props and
 * changes are reported through callbacks. A component that sorted the page it was handed would
 * violate the contract it exists to satisfy, so it renders `rows` in exactly the order received.
 */
import { Fragment, type ReactNode } from 'react';
import { ErrorState, LoadingState, TooMuchState } from '../states/States.js';
import {
  cellValue, pickColumns, DataTable,
  type ActiveFilter, type Column, type Density, type EmptyCopy,
} from './DataTable.js';

export interface ServerColumn<T> extends Column<T> {
  /** Present: the header is a button that reports a sort request under this key. */
  sortKey?: string;
}

export interface TableError { whatHappened: string; whatToDo: string; reference: string }

export interface ServerDataTableProps<T> {
  caption: string;
  columns: ServerColumn<T>[];
  rows: T[];
  getRowKey: (row: T, index: number) => string | number;
  empty: EmptyCopy;
  /** Count of ALL rows matching the current filter, not the rows on this page. */
  totalCount: number;
  /** 0-based. */
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
  sort?: string;
  sortDir?: 'asc' | 'desc';
  onSortChange?: (sort: string, dir: 'asc' | 'desc') => void;
  loading?: boolean;
  error?: TableError | null;
  onRetry?: () => void;
  activeFilters?: ActiveFilter[];
  onClearFilter?: (key: string) => void;
  onClearAll?: () => void;
  /** Above this many matches, render the too-much state instead of rows. */
  tooMuchThreshold?: number;
  tooMuchSuggestion?: ReactNode;
  density?: Density;
  visibleColumns?: string[];
  onRowClick?: (row: T) => void;
  /** Cells for a distinct row below the data; the caller says what they cover. */
  totalsFooter?: ReactNode;
  /** Rendered directly after a row, e.g. a subtotal when that row closes a group. */
  afterRow?: (row: T, index: number) => ReactNode;
}

export function pageRange(page: number, pageSize: number, total: number, onPage: number) {
  if (total === 0 || onPage === 0) return { from: 0, to: 0 };
  const from = page * pageSize + 1;
  return { from, to: from + onPage - 1 };
}

export function ServerDataTable<T>(props: ServerDataTableProps<T>) {
  const {
    caption, columns, rows, getRowKey, empty, totalCount, page, pageSize, onPageChange, onPageSizeChange,
    pageSizeOptions = [25, 50, 100, 200], sort, sortDir = 'asc', onSortChange, loading, error, onRetry,
    activeFilters, onClearFilter, onClearAll, tooMuchThreshold, tooMuchSuggestion,
    density = 'compact', visibleColumns, onRowClick, totalsFooter, afterRow,
  } = props;

  if (error) return <ErrorState {...error} onRetry={onRetry} />;
  if (loading) return <LoadingState label={`Loading ${caption}`} />;
  if (tooMuchThreshold !== undefined && totalCount > tooMuchThreshold) {
    return <TooMuchState matched={totalCount} threshold={tooMuchThreshold} suggestion={tooMuchSuggestion} />;
  }
  if (rows.length === 0) {
    return (
      <DataTable
        caption={caption} columns={columns} rows={[]} getRowKey={getRowKey} empty={empty}
        activeFilters={activeFilters} onClearFilter={onClearFilter} onClearAll={onClearAll}
      />
    );
  }

  const cols = pickColumns(columns, visibleColumns) as ServerColumn<T>[];
  const { from, to } = pageRange(page, pageSize, totalCount, rows.length);
  const lastPage = Math.max(0, Math.ceil(totalCount / pageSize) - 1);
  return (
    <div className="kbg-table-wrap">
      <table className={`kbg-table kbg-table--${density}`}>
        <caption className="kbg-sr-only">{caption}</caption>
        <thead>
          <tr>
            {cols.map((c) => {
              const sorted = c.sortKey !== undefined && sort === c.sortKey;
              const sortable = c.sortKey !== undefined && onSortChange !== undefined;
              return (
                <th
                  key={c.key} scope="col" style={{ width: c.width, textAlign: c.align }}
                  aria-sort={sortable ? (sorted ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}
                >
                  {sortable ? (
                    <button
                      type="button" className="kbg-table__sort"
                      onClick={() => onSortChange!(c.sortKey!, sorted && sortDir === 'asc' ? 'desc' : 'asc')}
                    >
                      {c.header}
                      <span aria-hidden="true">{sorted ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}</span>
                    </button>
                  ) : c.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <Fragment key={getRowKey(row, i)}>
              <tr
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={onRowClick ? (e) => {
                  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(row); }
                } : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                data-clickable={onRowClick ? 'true' : undefined}
              >
                {cols.map((c) => (
                  <td key={c.key} style={{ textAlign: c.align, whiteSpace: c.nowrap ? 'nowrap' : undefined }}>
                    {cellValue(c, row)}
                  </td>
                ))}
              </tr>
              {afterRow?.(row, i)}
            </Fragment>
          ))}
          {totalsFooter && <tr className="kbg-table__totals">{totalsFooter}</tr>}
        </tbody>
      </table>
      <nav className="kbg-pager" aria-label={`${caption} pages`}>
        <span className="kbg-pager__range">
          {from.toLocaleString('en-US')}-{to.toLocaleString('en-US')} of {totalCount.toLocaleString('en-US')} matching
        </span>
        {onPageSizeChange && (
          <label className="kbg-pager__size">
            Rows per page{' '}
            <select value={pageSize} onChange={(e) => onPageSizeChange(Number(e.target.value))}>
              {pageSizeOptions.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
        )}
        <button type="button" disabled={page <= 0} onClick={() => onPageChange(page - 1)}>Previous</button>
        <button type="button" disabled={page >= lastPage} onClick={() => onPageChange(page + 1)}>Next</button>
      </nav>
    </div>
  );
}
