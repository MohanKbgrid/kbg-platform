/**
 * The gate that matters for a LIBRARY: pack the tarball npm would publish, install THAT into a
 * throwaway project, and import it by name.
 *
 * Typechecking and unit tests both passed on a version of this package that no consumer could
 * import — `src/index.ts` used extensionless specifiers, tsc emitted them unchanged, and Node's
 * ESM resolver rejected every one with ERR_MODULE_NOT_FOUND. Nothing inside the package could
 * have caught that. Only installing it could.
 *
 * Packing also proves the `files` allowlist and the `exports` map are right — a path install
 * would silently pass by reaching into src/, which a published install cannot do.
 *
 * Run: node verify_consumable.mjs
 */
import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const pkgDir = resolve('.');
const work = mkdtempSync(join(tmpdir(), 'kbg-consumer-'));
const run = (cmd, cwd) => execSync(cmd, { cwd, stdio: 'pipe', encoding: 'utf8' });

let ok = 0, bad = 0;
const t = (l, c, d = '') => { c ? ok++ : bad++; console.log(`  [${c ? 'PASS' : 'FAIL'}] ${l}${d ? ' — ' + d : ''}`); };

try {
  console.log('\n[library] pack the published artifact and install it as a consumer would');
  const packed = run('npm pack --pack-destination "' + work + '" --silent', pkgDir).trim().split('\n').pop();
  const tarball = join(work, packed);
  t('npm pack produced a tarball', existsSync(tarball), packed);

  writeFileSync(join(work, 'package.json'),
    JSON.stringify({ name: 'consumer', private: true, type: 'module', version: '0.0.0' }, null, 2));
  run(`npm install "${tarball}" react --no-audit --no-fund --silent`, work);

  const installed = join(work, 'node_modules', '@kbg', 'ui-kit');
  t('installed under its package name', existsSync(installed));
  t('the tarball ships dist, NOT src (files allowlist honoured)',
    existsSync(join(installed, 'dist')) && !existsSync(join(installed, 'src')));

  writeFileSync(join(work, 'probe.mjs'), `
    import { deriveSyncState, DeniedState, SyncIndicator, EmptyState } from '@kbg/ui-kit';
    import { createRequire } from 'node:module';
    const req = createRequire(import.meta.url);
    const out = {
      resolves: typeof deriveSyncState === 'function',
      queued: deriveSyncState(3, false, null),
      components: [DeniedState, SyncIndicator, EmptyState].every(f => typeof f === 'function'),
      css: req.resolve('@kbg/ui-kit/tokens.css'),
    };
    console.log(JSON.stringify(out));
  `);
  const probe = JSON.parse(run('node probe.mjs', work).trim());
  t('imports by package name from an INSTALLED tarball', probe.resolves);
  t('the sync invariant survives the build', probe.queued === 'queued');
  t('every component export resolves', probe.components);
  t('tokens.css resolves through the exports map', existsSync(probe.css));
  t('...and still carries the 44px floor token',
    /--kbg-touch-min:\s*44px/.test(readFileSync(probe.css, 'utf8')));
  t('type declarations ship', existsSync(join(installed, 'dist', 'index.d.ts')));
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(`\n${'='.repeat(70)}\n${ok}/${ok + bad} consumability checks passed\n${'='.repeat(70)}`);
process.exit(bad ? 1 : 0);
