/** tsc emits JS and .d.ts but not CSS, so the token sheet is copied explicitly.
 *  It is exposed as "./tokens.css" in package.json exports, so a consumer never
 *  reaches into dist/ by hand. */
import { mkdirSync, copyFileSync } from 'node:fs';
mkdirSync('dist/tokens', { recursive: true });
copyFileSync('src/tokens/tokens.css', 'dist/tokens/tokens.css');
console.log('copied tokens.css -> dist/tokens/tokens.css');
