// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * The denial KIND (canon RBAC §3, rule R4) and what each kind tells the user.
 *
 * "Not allowed" covers seven different situations, and each needs a different next step. A screen
 * that shows the same grey sentence for all of them teaches users to ignore it. The kind is a
 * CLOSED list: a caller cannot invent an eighth, so a product's screens and its API agree on the
 * vocabulary.
 *
 * `COMPLETED` is the one kind that is not a refusal at all - the work is already done. It is
 * rendered as a quiet confirmation, never as an error.
 */

export const DENIAL_KINDS = [
  'AUTHORITY', 'STATE_GATE', 'CONFIG_GATE', 'PRECONDITION', 'READINESS',
  'APPROVAL_PENDING', 'COMPLETED',
] as const;

export type DenialKind = typeof DENIAL_KINDS[number];

/** AUTHORITY is the default: a decision that does not say why is assumed to be about authority. */
export const DEFAULT_DENIAL_KIND: DenialKind = 'AUTHORITY';

export interface DenialCopy {
  /** Builds the heading from the name of the action. */
  title: (action: string) => string;
  /** The generic next step for this kind; `whoCan` refines AUTHORITY only. */
  nextStep: (whoCan?: string) => string;
  /** `waiting` and `done` are not errors; `blocked` is a refusal the user can act on. */
  tone: 'blocked' | 'waiting' | 'done';
}

export const DENIAL_COPY: Record<DenialKind, DenialCopy> = {
  AUTHORITY: {
    title: (a) => `${a} is not available to you`,
    nextStep: (who) => (who ? `Ask someone who can: ${who}.` : 'Ask an administrator to review your access.'),
    tone: 'blocked',
  },
  STATE_GATE: {
    title: (a) => `${a} is not possible in the current state`,
    nextStep: () => 'Move the item to a state that allows it, then come back.',
    tone: 'blocked',
  },
  CONFIG_GATE: {
    title: (a) => `${a} is switched off in this setup`,
    nextStep: () => 'An administrator can turn it on in the configuration.',
    tone: 'blocked',
  },
  PRECONDITION: {
    title: (a) => `${a} is waiting on an earlier step`,
    nextStep: () => 'Complete the step named above, then try again.',
    tone: 'blocked',
  },
  READINESS: {
    title: (a) => `${a} is not ready yet`,
    nextStep: () => 'This is temporary. Nothing is wrong with your access; try again shortly.',
    tone: 'waiting',
  },
  APPROVAL_PENDING: {
    title: (a) => `${a} is waiting for approval`,
    nextStep: () => 'Nothing to do until the approver decides; you will see the outcome here.',
    tone: 'waiting',
  },
  COMPLETED: {
    title: (a) => `${a} is already done`,
    nextStep: () => 'Nothing more is needed here.',
    tone: 'done',
  },
};

export function isDenialKind(x: unknown): x is DenialKind {
  return typeof x === 'string' && (DENIAL_KINDS as readonly string[]).includes(x);
}

/**
 * The decision an authority layer hands to the UI. It is a union so that a refusal WITHOUT a reason
 * does not type-check; `assertReason` repeats the check at run time for callers that cast.
 */
export type AccessDecision =
  | { allowed: true }
  | { allowed: false; reason: string; kind?: DenialKind; whoCan?: string };

/** Throws when a refusal has no usable reason. A silent denial is the bug this exists to stop. */
export function assertReason(reason: unknown, where: string): string {
  if (typeof reason !== 'string' || reason.trim() === '') {
    throw new Error(`${where}: a denied control must carry a reason (canon RBAC rule 3)`);
  }
  return reason;
}

/**
 * Make an engine's raw reason readable: remove "kind:identifier" scope references and source file
 * paths, which belong in logs. The raw string is returned alongside so a support view can show it.
 * This is deliberately generic; mapping permission codes to plain words is the product's job.
 */
export function plainDenyReason(raw: string | null | undefined): { message: string; raw: string } {
  const original = raw ?? '';
  const message = original
    .replace(/\b[a-z_]+:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/gi, 'the requested scope')
    .replace(/\b[\w./-]+\.(?:py|tsx?|jsx?|sql)\b/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
  return { message: message || 'This action was not allowed. Ask your supervisor why.', raw: original };
}
