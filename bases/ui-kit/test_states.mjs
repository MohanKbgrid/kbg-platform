/**
 * Gate for @kbg/ui-kit's one testable invariant.
 *
 * The components are markup and are proven by the consuming app's screen tests. `deriveSyncState`
 * is not markup — it is the rule that stops the indicator lying, so it is exported separately and
 * asserted here. Canon D7: a control that can report a false result is worse than none, and a
 * green "synced" over a full queue is exactly that.
 */
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

// Tiny extraction so this runs with no build step and no test runner.
const src = readFileSync('src/SyncIndicator.tsx', 'utf8');
const body = src.slice(src.indexOf('export function deriveSyncState'));
const fnSrc = body.slice(body.indexOf('{', body.indexOf(')')), body.indexOf('\n}') + 2);
const derive = new Function('queuedCount', 'isSyncing', 'error', fnSrc.replace(/:\s*SyncState/g, ''));

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}: got=${got} want=${want}`);
};

console.log('\n[D7] the sync indicator cannot report a false green');
check('an empty queue is synced', derive(0, false, null), 'synced');
check('⛔ a NON-EMPTY queue can never read as synced', derive(12, false, null), 'queued');
check('...not even while syncing', derive(12, true, null), 'syncing');
check('an error wins over everything', derive(0, true, 'network down'), 'error');
check('...including over a queue', derive(5, false, 'network down'), 'error');

console.log('\n[tokens] the floor-layer minimum is a token, so a lint can assert it');
const css = readFileSync('src/tokens/tokens.css', 'utf8');
check('--kbg-touch-min is defined', /--kbg-touch-min:\s*44px/.test(css), true);
check('floor controls consume it', /\.kbg-floor[^}]*min-height:\s*var\(--kbg-touch-min\)/s.test(css), true);
check('semantic colour is separate from the brand accent',
  /--kbg-critical:/.test(css) && /--kbg-accent:/.test(css) && !/--kbg-critical:\s*var\(--kbg-accent\)/.test(css), true);
check('dark theme redefines tokens, not components',
  /\[data-kbg-theme="dark"\]/.test(css), true);
check('reduced motion is respected', /prefers-reduced-motion/.test(css), true);

console.log(`\n${'='.repeat(70)}\n${pass}/${pass + fail} checks passed\n${'='.repeat(70)}`);
process.exit(fail === 0 ? 0 : 1);
