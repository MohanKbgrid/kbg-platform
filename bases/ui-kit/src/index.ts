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
