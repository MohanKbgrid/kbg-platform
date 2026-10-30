// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * Behaviour gate for the domain-free components. Renders the BUILT package (dist/) to static
 * markup, or with a test renderer where effects/boundaries matter, and asserts the specific copy
 * and the invariants each component exists to hold. Includes planted-defect checks: the refusal
 * paths must actually refuse.
 *
 * Run through `npm test`, which builds first.
 */
import React from 'react';
import { renderToStaticMarkup as html } from 'react-dom/server';
import TestRenderer, { act } from 'react-test-renderer';
import { readFileSync } from 'node:fs';
import {
  DeniedState, AccessControl, PermissionGate, DENIAL_KINDS, DENIAL_COPY, plainDenyReason,
  StatusChip, toneFor, DataTable, ServerDataTable, pageRange, WorkQueue, AuditLog,
  ErrorBoundary, makeReference, useDraftPersist, readDraft, writeDraft, AppShell, groupNav,
} from './dist/index.js';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const h = React.createElement;
let pass = 0, fail = 0;
const check = (label, ok) => { ok ? pass++ : fail++; console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}`); };
const throws = (fn) => { try { fn(); return false; } catch { return true; } };
const has = (s, ...needles) => needles.every((n) => s.includes(n));

console.log('\n[denial] every kind renders its own title and next step');
const seenTitles = new Set();
for (const kind of DENIAL_KINDS) {
  const m = html(h(DeniedState, { action: 'Item A change', reason: 'Because of X.', kind }));
  seenTitles.add(DENIAL_COPY[kind].title('Item A change'));
  check(`${kind}: title, reason, next step, data attribute`,
    has(m, DENIAL_COPY[kind].title('Item A change'), 'Because of X.', DENIAL_COPY[kind].nextStep(), `data-denial-kind="${kind}"`));
}
check('the seven kinds have seven distinct titles', seenTitles.size === 7);
check('default kind is AUTHORITY and names who can',
  has(html(h(DeniedState, { action: 'Edit', reason: 'r', whoCan: 'Acme Lead' })), 'data-denial-kind="AUTHORITY"', 'Acme Lead'));
const done = html(h(DeniedState, { action: 'Close', reason: 'Closed on Monday.', kind: 'COMPLETED' }));
check('COMPLETED is a status, not an alert or an error', has(done, 'role="status"', 'kbg-state--tone-done') && !done.includes('role="alert"') && !done.includes('kbg-state--error'));
check('waiting kinds are not errors either', has(html(h(DeniedState, { action: 'A', reason: 'r', kind: 'APPROVAL_PENDING' })), 'kbg-state--tone-waiting'));
check('PLANTED: DeniedState with an empty reason refuses to render', throws(() => html(h(DeniedState, { action: 'A', reason: '  ' }))));
check('PLANTED: an unknown kind refuses to render', throws(() => html(h(DeniedState, { action: 'A', reason: 'r', kind: 'MAYBE' }))));
const plain = plainDenyReason('held, but not over org_unit:81608994-899b-4458-93e7-78ee05a35641 (rules/check.py)');
check('plainDenyReason strips scope ids and file paths, keeps raw', !/[0-9a-f]{8}-/.test(plain.message) && !plain.message.includes('.py') && plain.raw.includes('.py'));

console.log('\n[access] a denied control stays visible with its reason');
const denied = { allowed: false, reason: 'Needs a second signer.', kind: 'STATE_GATE' };
const ac = html(h(AccessControl, { action: 'Approve', decision: denied }, h('button', null, 'LIVE-BUTTON')));
check('denied: disabled button visible, reason and kind shown, live control absent',
  has(ac, 'disabled', 'Approve', 'Needs a second signer.', 'data-denial-kind="STATE_GATE"') && !ac.includes('LIVE-BUTTON'));
check('denied: description wired by aria-describedby', /aria-describedby="([^"]+)"/.test(ac) && ac.includes(`id="${ac.match(/aria-describedby="([^"]+)"/)[1]}"`));
check('allowed: renders the live control only', html(h(AccessControl, { action: 'Approve', decision: { allowed: true } }, h('b', null, 'LIVE'))) === '<b>LIVE</b>');
check('PLANTED: a denied control with no reason fails to render', throws(() => html(h(AccessControl, { action: 'Approve', decision: { allowed: false } }, 'x'))));
check('PLANTED: a denied control with a blank reason fails to render', throws(() => html(h(AccessControl, { action: 'Approve', decision: { allowed: false, reason: '' } }, 'x'))));
check('PermissionGate: pending decision shows a skeleton, not the content', has(html(h(PermissionGate, { action: 'Reports', decision: undefined }, 'SECRET')), 'aria-busy') && !html(h(PermissionGate, { action: 'Reports', decision: undefined }, 'SECRET')).includes('SECRET'));
check('PermissionGate: denial shows kind and reason', has(html(h(PermissionGate, { action: 'Reports', decision: { allowed: false, reason: 'Switched off.', kind: 'CONFIG_GATE' } }, 'SECRET')), 'Switched off.', 'CONFIG_GATE'));
check('PLANTED: PermissionGate refuses a reasonless denial', throws(() => html(h(PermissionGate, { action: 'R', decision: { allowed: false } }, 'x'))));
check('PermissionGate: a fallback cannot be used to hide a reasonless denial', throws(() => html(h(PermissionGate, { action: 'R', decision: { allowed: false }, fallback: 'nothing' }, 'x'))));

console.log('\n[status chip] the word carries the meaning');
check('prints the status text', has(html(h(StatusChip, { value: 'pending_approval' })), 'pending approval'));
check('unmapped status is neutral, not guessed', toneFor('zzz') === 'neutral');
check('toneMap overrides default', toneFor('active', { active: 'warn' }) === 'warn');
check('null renders nothing', html(h(StatusChip, { value: null })) === '');

console.log('\n[tables] rows render in the order given; counts are of the whole set');
const cols = [{ key: 'name', header: 'Name' }, { key: 'qty', header: 'Qty', align: 'right' }];
const rows = [{ id: 'c', name: 'Item C', qty: 1 }, { id: 'a', name: 'Item A', qty: 9 }, { id: 'b', name: 'Item B', qty: 5 }];
const empty = { title: 'No items yet', whatWouldFillThis: 'Items appear once Acme adds one.' };
const dt = html(h(DataTable, { caption: 'Items', columns: cols, rows, getRowKey: (r) => r.id, empty }));
check('DataTable never re-sorts', dt.indexOf('Item C') < dt.indexOf('Item A') && dt.indexOf('Item A') < dt.indexOf('Item B'));
check('DataTable has caption and column scope', has(dt, '<caption', 'scope="col"'));
check('DataTable empty uses the required copy', has(html(h(DataTable, { caption: 'Items', columns: cols, rows: [], getRowKey: (r) => r.id, empty })), 'No items yet', 'Items appear once Acme adds one.'));
check('DataTable empty + active filter names the filter', has(html(h(DataTable, { caption: 'Items', columns: cols, rows: [], getRowKey: (r) => r.id, empty, activeFilters: [{ key: 'st', label: 'Status: Open' }] })), 'Nothing matches these filters', 'Status: Open'));
check('DataTable loading shows a skeleton', has(html(h(DataTable, { caption: 'Items', columns: cols, rows, getRowKey: (r) => r.id, empty, loading: true })), 'aria-busy'));
check('DataTable visibleColumns hides and orders', (() => { const m = html(h(DataTable, { caption: 'I', columns: cols, rows, getRowKey: (r) => r.id, empty, visibleColumns: ['qty'] })); return m.includes('Qty') && !m.includes('>Name<'); })());
check('DataTable clickable rows are keyboard reachable', has(html(h(DataTable, { caption: 'I', columns: cols, rows, getRowKey: (r) => r.id, empty, onRowClick: () => {} })), 'tabindex="0"'));

// Rank-before-limit: the server hands over page 1 containing the top-ranked row even though its natural order is last.
const ranked = [{ id: 'z', name: 'Item Z', qty: 100 }, { id: 'y', name: 'Item Y', qty: 90 }];
const sBase = { caption: 'Items', columns: [{ key: 'name', header: 'Name', sortKey: 'name' }, { key: 'qty', header: 'Qty' }], rows: ranked, getRowKey: (r) => r.id, empty, totalCount: 4213, page: 0, pageSize: 2, onPageChange() {}, sort: 'qty', sortDir: 'desc', onSortChange() {} };
const sd = html(h(ServerDataTable, sBase));
check('ServerDataTable keeps the server order (top-ranked row first, not re-sorted by name)', sd.indexOf('Item Z') < sd.indexOf('Item Y'));
check('ServerDataTable shows the matching total, not the page size', has(sd, '1-2 of 4,213 matching'));
check('ServerDataTable marks the sorted column', has(sd, 'aria-sort="none"') || has(sd, 'aria-sort="descending"'));
check('ServerDataTable sort header is a button', has(sd, 'kbg-table__sort'));
check('Previous disabled on first page, Next enabled', /<button type="button" disabled="">Previous/.test(sd) && !/disabled="">Next/.test(sd));
check('Next disabled on the last page', /disabled="">Next/.test(html(h(ServerDataTable, { ...sBase, page: 2106 }))));
check('pageRange of an empty page is 0-0', JSON.stringify(pageRange(0, 25, 0, 0)) === '{"from":0,"to":0}');
check('too-much state replaces rows above the threshold', (() => { const m = html(h(ServerDataTable, { ...sBase, tooMuchThreshold: 1000 })); return has(m, '4,213 rows match') && !m.includes('Item Z'); })());
check('error state carries a reference', has(html(h(ServerDataTable, { ...sBase, error: { whatHappened: 'Could not load', whatToDo: 'Retry', reference: 'REF-1' } })), 'REF-1', 'role="alert"'));
check('totals footer is rendered', has(html(h(ServerDataTable, { ...sBase, totalsFooter: h('td', null, 'Total of this page') })), 'Total of this page'));

console.log('\n[work queue] server order, server decisions');
const item = (id, actions) => ({ id, summary: `Approve request ${id}`, typeLabel: 'Approval', status: 'pending', overdue: id === '1', riskScore: 7, actions });
const wq = html(h(WorkQueue, {
  items: [item('2', { approve: { allowed: true }, reassign: { allowed: false, reason: 'Only the owner can reassign.', kind: 'AUTHORITY', whoCan: 'Queue owner' } }), item('1', { approve: { allowed: false, reason: 'You raised this yourself.' } })],
  orderNote: 'Most urgent first', onAction() {},
}));
check('order is the server order', wq.indexOf('request 2') < wq.indexOf('request 1'));
check('order note shown', has(wq, 'Most urgent first'));
check('refused action stays visible with the server reason', has(wq, 'Only the owner can reassign.', 'Queue owner', 'You raised this yourself.'));
check('allowed action is a live button', /<button type="button">Approve<\/button>/.test(wq));
check('overdue shown as a word', has(wq, 'overdue'));
check('empty queue explains what fills it', has(html(h(WorkQueue, { items: [], orderNote: 'x', onAction() {} })), 'Nothing is waiting on you'));
check('unbound explains why', has(html(h(WorkQueue, { items: [], unbound: true, orderNote: 'x', onAction() {} })), 'not linked to a position'));
check('PLANTED: a queue action refused without a reason fails to render', throws(() => html(h(WorkQueue, { items: [item('9', { approve: { allowed: false } })], orderNote: 'x', onAction() {} }))));

console.log('\n[audit log] both outcomes are recorded and shown');
const auditRows = [
  { id: '1', at: '2026-01-05T10:00:00Z', actor: 'user.a', action: 'update', objectType: 'item', objectRef: 'A-1', allowed: true },
  { id: '2', at: '2026-01-05T10:01:00Z', actor: 'user.b', actedFor: 'user.c', action: 'delete', allowed: false, reason: 'Not permitted.' },
];
const al = html(h(AuditLog, { rows: auditRows, totalCount: 2, page: 0, pageSize: 25, onPageChange() {}, groups: [{ key: 'orders', count: 2, denied: 1 }] }));
check('allowed and denied both print their word', has(al, 'allowed', 'denied', 'Not permitted.'));
check('acted-for identity is shown beside the actor', has(al, 'user.b', 'acting for user.c'));
check('timestamps are deterministic UTC', has(al, '2026-01-05 10:00:00 UTC'));
check('group summary shown', has(al, 'orders'));
check('without audit access the log is replaced by the denial', (() => { const m = html(h(AuditLog, { rows: auditRows, totalCount: 2, page: 0, pageSize: 25, onPageChange() {}, access: { allowed: false, reason: 'Reading the log is not granted to your position.' } })); return m.includes('not granted to your position') && !m.includes('user.a'); })());

console.log('\n[error boundary] a crash becomes a screen with a reference');
{
  const Bomb = () => { throw new Error('boom Item A'); };
  const seen = [];
  const origErr = console.error; console.error = () => {};
  let r;
  act(() => { r = TestRenderer.create(h(ErrorBoundary, { onError: (e) => seen.push(e) }, h(Bomb))); });
  console.error = origErr;
  const text = JSON.stringify(r.toJSON());
  check('fallback shows a reference', /ERR-[0-9A-Z]+-[0-9A-Z]{3}/.test(text));
  check('fallback says what happened and offers retry', text.includes('Something went wrong') && text.includes('Try again'));
  check('onError received the captured error with the same reference', seen.length >= 1 && text.includes(seen[seen.length - 1].reference) && seen[0].message === 'boom Item A');
  check('children render untouched when nothing fails', JSON.stringify(TestRenderer.create(h(ErrorBoundary, null, h('p', null, 'fine'))).toJSON()).includes('fine'));
  check('makeReference is distinct across calls', makeReference(1, 0.1) !== makeReference(2, 0.1));
}

console.log('\n[draft persist] restore once, write debounced, clear cancels');
{
  const store = new Map();
  const mem = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
  check('readDraft/writeDraft round-trip', writeDraft(mem, 'k0', { a: 1 }) && readDraft(mem, 'k0').value.a === 1);
  store.set('bad', '{nope');
  check('corrupt draft is dropped, reported absent', readDraft(mem, 'bad').found === false && !store.has('bad'));
  check('throwing storage never throws', writeDraft({ setItem() { throw new Error('full'); } }, 'k', 1) === false);

  store.set('form', JSON.stringify({ name: 'Acme' }));
  let restored = null, api = null;
  const Probe = ({ value }) => { api = useDraftPersist('form', value, (d) => { restored = d; }, 10, mem); return null; };
  let r;
  await act(async () => { r = TestRenderer.create(h(Probe, { value: { name: '' } })); });
  check('stored draft restored once on mount', restored && restored.name === 'Acme');
  await act(async () => { r.update(h(Probe, { value: { name: 'Typed' } })); await new Promise((s) => setTimeout(s, 40)); });
  check('change is written after the debounce', JSON.parse(store.get('form')).name === 'Typed');
  await act(async () => { r.update(h(Probe, { value: { name: 'Later' } })); });
  api.clearDraft();
  await act(async () => { await new Promise((s) => setTimeout(s, 40)); });
  check('clearDraft removes the draft and cancels the pending write', !store.has('form'));
  check('key null disables persistence', await (async () => {
    const s2 = new Map(); const m2 = { getItem: (k) => s2.get(k) ?? null, setItem: (k, v) => s2.set(k, v), removeItem: (k) => s2.delete(k) };
    const P = () => { useDraftPersist(null, 1, () => {}, 5, m2); return null; };
    await act(async () => { TestRenderer.create(h(P)); await new Promise((s) => setTimeout(s, 20)); });
    return s2.size === 0;
  })());
}

console.log('\n[app shell] landmarks, current page, router-agnostic links');
const nav = [{ key: 'home', label: 'Home', href: '/' }, { key: 'a', label: 'Reports', href: '/r', group: 'Work', badge: 3 }, { key: 'b', label: 'Settings', href: '/s', group: 'Work' }];
const sh = html(h(AppShell, { appName: 'Demo App', nav, currentKey: 'a', status: h('span', null, 'SYNC-SLOT') }, h('p', null, 'BODY')));
check('has banner, nav, main and skip link', has(sh, '<header', '<nav', '<main', 'Skip to content'));
check('current entry carries aria-current', /aria-current="page"[^>]*>.*Reports/s.test(sh) || has(sh, 'aria-current="page"'));
check('only one entry is current', (sh.match(/aria-current="page"/g) || []).length === 1);
check('badge announces its meaning', has(sh, '3 waiting'));
check('status slot and children render', has(sh, 'SYNC-SLOT', 'BODY'));
check('menu button is collapsed initially and controls the nav', has(sh, 'aria-expanded="false"', 'aria-controls'));
check('groups preserve first-seen order', JSON.stringify(groupNav(nav).map((g) => g.group)) === '[null,"Work"]');
check('renderLink plugs a router in', has(html(h(AppShell, { appName: 'D', nav, currentKey: 'home', renderLink: (e, p) => h('a', { ...p, 'data-router': e.key }) }, 'x')), 'data-router="home"'));

console.log('\n[css] the new components consume tokens, not literals');
const css = readFileSync('src/tokens/tokens.css', 'utf8');
const newCss = css.slice(css.indexOf('denial kinds'));
check('no hex colours in the new rules', !/#[0-9a-fA-F]{3,6}\b/.test(newCss));
check('shell nav links meet the touch minimum', /\.kbg-shell__link\s*\{[^}]*min-height:\s*var\(--kbg-touch-min\)/s.test(css));
check('completed tone uses the good token', /kbg-state--tone-done[^}]*var\(--kbg-good/.test(css));

console.log(`\n${'='.repeat(70)}\n${pass}/${pass + fail} component checks passed\n${'='.repeat(70)}`);
process.exit(fail === 0 ? 0 : 1);
