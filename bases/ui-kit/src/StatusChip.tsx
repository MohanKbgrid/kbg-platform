// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * StatusChip - a status as a pill, where the WORD carries the meaning and the colour only helps.
 *
 * Colour is never the sole signal (about one man in twelve cannot tell the tones apart), so the
 * chip always prints the status text. Tones use the semantic tokens, not the brand accent.
 */

export type ChipTone = 'good' | 'warn' | 'critical' | 'info' | 'neutral';

/** Statuses that recur in almost every product. A screen passes `toneMap` to add or override. */
export const DEFAULT_TONES: Record<string, ChipTone> = {
  active: 'good', approved: 'good', done: 'good', completed: 'good', ok: 'good', live: 'good',
  paid: 'good', received: 'good', delivered: 'good',
  pending: 'warn', waiting: 'warn', on_hold: 'warn', overdue: 'warn', queued: 'warn',
  in_progress: 'info', processing: 'info', submitted: 'info',
  rejected: 'critical', failed: 'critical', error: 'critical', cancelled: 'critical', denied: 'critical',
  draft: 'neutral', planned: 'neutral', inactive: 'neutral', closed: 'neutral',
};

export interface StatusChipProps {
  value: string | null | undefined;
  toneMap?: Record<string, ChipTone>;
  /** Overrides the printed text; the default is the value with underscores read as spaces. */
  label?: string;
}

/** Resolve a tone; a value nobody mapped is neutral, never guessed to be good or bad. */
export function toneFor(value: string, toneMap?: Record<string, ChipTone>): ChipTone {
  return toneMap?.[value] ?? DEFAULT_TONES[value] ?? 'neutral';
}

export function StatusChip({ value, toneMap, label }: StatusChipProps) {
  if (!value) return null;
  const tone = toneFor(value, toneMap);
  return (
    <span className={`kbg-chip kbg-chip--${tone}`} data-status={value} data-tone={tone}>
      {label ?? value.replace(/_/g, ' ')}
    </span>
  );
}
