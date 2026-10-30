// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * NOTE ON THE `.js` IMPORT EXTENSIONS BELOW — do not "tidy" them away.
 * TypeScript resolves './states/States.js' to States.tsx at compile time, and emits the specifier
 * unchanged. Node's ESM resolver REQUIRES the extension, so dropping it produces a package that
 * type-checks, builds, and then fails at import in every consumer with ERR_MODULE_NOT_FOUND.
 * That exact failure was caught here by the consumer smoke test, not by tsc.
 *
 * @kbg/ui-kit — the KBG visual and behavioural language.
 *
 * Artifact 3 of the Platform Surfaces canon. Read `docs/canon/surfaces/06-experience.md` first:
 * this package is that spec made executable, not a general component library.
 *
 * Import the tokens once, at your app root:
 *     import '@kbg/ui-kit/tokens.css';
 */
export {
  LoadingState, EmptyState, FilteredEmptyState, DeniedState,
  PartialState, StaleState, TooMuchState, ErrorState,
} from './states/States.js';

export { SyncIndicator, deriveSyncState } from './SyncIndicator.js';
export type { SyncState, SyncIndicatorProps } from './SyncIndicator.js';

export {
  DENIAL_KINDS, DENIAL_COPY, DEFAULT_DENIAL_KIND, isDenialKind, assertReason, plainDenyReason,
} from './access/denial.js';
export type { DenialKind, DenialCopy, AccessDecision } from './access/denial.js';
export { AccessControl, PermissionGate } from './access/AccessControl.js';
export type { AccessControlProps, PermissionGateProps } from './access/AccessControl.js';

export { StatusChip, toneFor, DEFAULT_TONES } from './StatusChip.js';
export type { StatusChipProps, ChipTone } from './StatusChip.js';

export { DataTable, pickColumns, cellValue } from './table/DataTable.js';
export type {
  Column, DataTableProps, Density, EmptyCopy, ActiveFilter,
} from './table/DataTable.js';
export { ServerDataTable, pageRange } from './table/ServerDataTable.js';
export type { ServerColumn, ServerDataTableProps, TableError } from './table/ServerDataTable.js';

export { WorkQueue, defaultFormatDue } from './queue/WorkQueue.js';
export type { WorkItem, WorkQueueProps } from './queue/WorkQueue.js';
export { AuditLog, defaultFormatAt } from './queue/AuditLog.js';
export type { AuditRow, AuditGroup, AuditLogProps } from './queue/AuditLog.js';

export { ErrorBoundary, makeReference } from './ErrorBoundary.js';
export type { CapturedError, ErrorBoundaryProps } from './ErrorBoundary.js';
export { useDraftPersist, readDraft, writeDraft, removeDraft } from './useDraftPersist.js';
export type { DraftStorage } from './useDraftPersist.js';

export { AppShell, groupNav } from './shell/AppShell.js';
export type { AppShellProps, NavEntry, NavLinkProps } from './shell/AppShell.js';
