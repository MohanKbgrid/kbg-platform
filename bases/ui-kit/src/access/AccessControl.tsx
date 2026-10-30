// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * AccessControl and PermissionGate - a denied control stays VISIBLE, with its kind and reason.
 *
 * Hiding a control teaches users the feature does not exist and generates support load; showing it
 * disabled, with why and what to do next, teaches them how the organisation works (canon RBAC
 * rule 3). Both components take the SAME `AccessDecision` the API enforces with, so a disabled
 * button and a 403 cannot disagree.
 *
 * Neither component looks at a role name. "Is this person a Manager" is not a question the UI may
 * ask (RBAC rule 1); it asks the authority layer for a decision and renders the answer.
 *
 * A refusal with no reason throws at render. That is intentional: a missing reason is a defect in
 * the authority layer, and a screen that quietly swallowed it would ship the silent denial.
 */
import { useId, type ReactNode } from 'react';
import { DeniedState } from '../states/States.js';
import { LoadingState } from '../states/States.js';
import {
  DEFAULT_DENIAL_KIND, DENIAL_COPY, assertReason, type AccessDecision,
} from './denial.js';

export interface AccessControlProps {
  /** Human name of the action, e.g. "Approve order". Used for the disabled button and the title. */
  action: string;
  decision: AccessDecision;
  /** The live control, rendered only when the decision allows it. */
  children: ReactNode;
}

export function AccessControl({ action, decision, children }: AccessControlProps) {
  const id = useId();
  if (decision.allowed) return <>{children}</>;

  const reason = assertReason(decision.reason, `AccessControl(${action})`);
  const kind = decision.kind ?? DEFAULT_DENIAL_KIND;
  const done = DENIAL_COPY[kind].tone === 'done';
  return (
    <span className="kbg-access kbg-access--denied" data-denial-kind={kind}>
      <button
        type="button"
        className="kbg-access__button"
        disabled
        aria-disabled="true"
        aria-describedby={id}
      >
        {action}
      </button>
      <span id={id} className="kbg-access__why">
        <DeniedState
          action={action}
          reason={reason}
          whoCan={decision.whoCan}
          kind={kind}
          inline
        />
      </span>
      {done && <span className="kbg-sr-only">Completed</span>}
    </span>
  );
}

export interface PermissionGateProps {
  action: string;
  /** `undefined` means the decision has not arrived yet: a skeleton, never a flash of the content. */
  decision: AccessDecision | undefined;
  /** Replaces the default denial panel. It must still say why, so prefer to leave it unset. */
  fallback?: ReactNode;
  children: ReactNode;
}

/**
 * Gate a whole view or section. Not a security boundary - the API is - but it makes sure a person
 * who cannot use a view is told so, with the reason, instead of meeting a blank page.
 */
export function PermissionGate({ action, decision, fallback, children }: PermissionGateProps) {
  if (decision === undefined) return <LoadingState rows={2} label={`Checking access to ${action}`} />;
  if (decision.allowed) return <>{children}</>;
  const reason = assertReason(decision.reason, `PermissionGate(${action})`);
  if (fallback !== undefined) return <>{fallback}</>;
  return <DeniedState action={action} reason={reason} whoCan={decision.whoCan} kind={decision.kind} />;
}
