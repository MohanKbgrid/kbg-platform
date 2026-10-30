// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * useDraftPersist - keep an in-progress form value in storage so a dropped connection, a tab
 * switch or an interrupted submit never loses what the person typed ("never a lost entry").
 *
 *  - On mount (and when `key` changes) a stored draft, if any, is handed to `restore` once.
 *  - Every change to `value` is written, debounced.
 *  - `key: null` disables persistence (e.g. no dialog open).
 *  - `clearDraft()` after a successful submit so the next use starts blank.
 *
 * Storage is best-effort by design: a full, blocked or missing storage must never break the form,
 * so every access is guarded. Note what is stored is the typed value in the browser, in clear; do
 * not persist secrets.
 */
import { useEffect, useRef } from 'react';

export const DEFAULT_DEBOUNCE_MS = 300;

/** The slice of the Web Storage API used here; any object with these three methods works. */
export interface DraftStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function defaultStorage(): DraftStorage | null {
  try { return typeof localStorage === 'undefined' ? null : localStorage; } catch { return null; }
}

/** Read and parse a draft; a corrupt entry is removed and reported as absent. */
export function readDraft<T>(storage: DraftStorage | null, key: string): { found: boolean; value?: T } {
  if (!storage) return { found: false };
  let raw: string | null;
  try { raw = storage.getItem(key); } catch { return { found: false }; }
  if (raw == null) return { found: false };
  try {
    return { found: true, value: JSON.parse(raw) as T };
  } catch {
    try { storage.removeItem(key); } catch { /* nothing more to do */ }
    return { found: false };
  }
}

export function writeDraft(storage: DraftStorage | null, key: string, value: unknown): boolean {
  if (!storage) return false;
  try { storage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
}

export function removeDraft(storage: DraftStorage | null, key: string): void {
  if (!storage) return;
  try { storage.removeItem(key); } catch { /* best effort */ }
}

export function useDraftPersist<T>(
  key: string | null,
  value: T,
  restore: (draft: T) => void,
  debounceMs: number = DEFAULT_DEBOUNCE_MS,
  storage?: DraftStorage | null,
): { clearDraft: () => void } {
  const restoreRef = useRef(restore);
  restoreRef.current = restore;
  const store = storage === undefined ? defaultStorage() : storage;
  const storeRef = useRef(store);
  storeRef.current = store;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!key) return;
    const r = readDraft<T>(storeRef.current, key);
    if (r.found) restoreRef.current(r.value as T);
  }, [key]);

  useEffect(() => {
    if (!key) return;
    const t = setTimeout(() => { timer.current = null; writeDraft(storeRef.current, key, value); }, debounceMs);
    timer.current = t;
    return () => { clearTimeout(t); if (timer.current === t) timer.current = null; };
  }, [key, value, debounceMs]);

  // Cancel a pending write too, or a draft cleared on submit would be re-saved a moment later.
  const clearDraft = () => {
    if (timer.current) { clearTimeout(timer.current); timer.current = null; }
    if (key) removeDraft(storeRef.current, key);
  };
  return { clearDraft };
}
