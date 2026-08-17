/**
 * The sync indicator — Experience surface §7, and a direct application of D7.
 *
 * Canon: *"Persistent header indicator: synced, or n queued with a value. NEVER HIDDEN."*
 *
 * Two failures this component is shaped to prevent, both observed:
 *
 *  1. **A green tick that lies.** An indicator that shows "synced" whenever it is not actively
 *     erroring will report synced with a full queue behind it. So `state` is DERIVED from the
 *     queue here, not passed in — a caller cannot claim synced while `queuedCount > 0`.
 *
 *  2. **Hiding when healthy.** Tempting, and wrong: a rep who never sees the indicator has no
 *     mental model of it, so when it finally appears they do not know what it means. It is always
 *     rendered — quietly when synced, loudly when not.
 *
 * The VALUE matters as much as the count. "12 queued" is abstract; "12 queued · ₹48,300" tells a
 * rep whether to go and find signal before they leave the market.
 */
import type { ReactNode } from 'react';

export type SyncState = 'synced' | 'queued' | 'syncing' | 'error';

export interface SyncIndicatorProps {
  queuedCount: number;
  /** Total business value sitting in the queue, pre-formatted by the caller (currency is theirs). */
  queuedValue?: string;
  isSyncing?: boolean;
  lastSyncedAt?: Date | string | null;
  error?: string | null;
  onRetry?: () => void;
  children?: ReactNode;
}

/** Derivation is exported so a test can assert the states directly — including the one that
 *  matters: a non-empty queue can never read as synced. */
export function deriveSyncState(
  queuedCount: number, isSyncing?: boolean, error?: string | null,
): SyncState {
  if (error) return 'error';
  if (isSyncing) return 'syncing';
  if (queuedCount > 0) return 'queued';
  return 'synced';
}

const LABEL: Record<SyncState, string> = {
  synced: 'All saved',
  syncing: 'Saving…',
  queued: 'Waiting to save',
  error: 'Could not save',
};

export function SyncIndicator({
  queuedCount, queuedValue, isSyncing, lastSyncedAt, error, onRetry,
}: SyncIndicatorProps) {
  const state = deriveSyncState(queuedCount, isSyncing, error);
  const when = lastSyncedAt
    ? (typeof lastSyncedAt === 'string' ? lastSyncedAt : lastSyncedAt.toLocaleTimeString())
    : null;

  return (
    <div
      className={`kbg-sync kbg-sync--${state}`}
      role="status"
      aria-live={state === 'error' ? 'assertive' : 'polite'}
      data-queued={queuedCount}
    >
      <span className="kbg-sync__dot" aria-hidden="true" />
      <span className="kbg-sync__label">{LABEL[state]}</span>

      {queuedCount > 0 && (
        <span className="kbg-sync__count">
          {queuedCount}
          {queuedValue ? ` · ${queuedValue}` : ''}
        </span>
      )}

      {state === 'synced' && when && (
        <span className="kbg-sync__when">{when}</span>
      )}

      {state === 'error' && (
        <>
          <span className="kbg-sync__error">{error}</span>
          {onRetry && (
            <button type="button" className="kbg-sync__retry" onClick={onRetry}>Retry</button>
          )}
        </>
      )}
    </div>
  );
}
