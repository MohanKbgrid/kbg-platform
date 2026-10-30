// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 KB Grid
/**
 * ErrorBoundary - the last-resort screen for a crash, instead of a blank white page.
 *
 * Catches two different classes of failure, because React's boundary contract covers only the first:
 *   1. render / lifecycle errors, through getDerivedStateFromError + componentDidCatch;
 *   2. uncaught script errors and unhandled promise rejections OUTSIDE rendering (event handlers,
 *      async callbacks, sync code), through window listeners - a boundary never sees these.
 *
 * It follows the Error state of the Experience contract: what happened, what to do, and a REFERENCE
 * support can trace. The technical detail sits behind a disclosure and can be copied, because on a
 * device with no debugger a screenshot is sometimes the only channel back to the developer.
 *
 * It renders without any provider above it, so it works even when the crash is inside the layer
 * that wraps the app. It must never throw itself.
 */
import { Component, type ErrorInfo, type ReactNode } from 'react';

export interface CapturedError {
  message: string;
  stack?: string;
  componentStack?: string;
  source: 'render' | 'window' | 'promise';
  reference: string;
  at: string;
}

export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Called once per captured error: send it to your logger. */
  onError?: (e: CapturedError) => void;
  /** Wording for the "what to do" line. */
  whatToDo?: string;
}

interface State { error: CapturedError | null; copied: boolean }

/** Short, sortable, and unique enough for a support query. */
export function makeReference(now: number = Date.now(), rand: number = Math.random()): string {
  return `ERR-${now.toString(36).toUpperCase()}-${Math.floor(rand * 36 ** 3).toString(36).toUpperCase().padStart(3, '0')}`;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, State> {
  state: State = { error: null, copied: false };

  private capture(partial: Omit<CapturedError, 'reference' | 'at'>): CapturedError {
    return { ...partial, reference: makeReference(), at: new Date().toISOString() };
  }

  private record(e: CapturedError) {
    this.setState((prev) => (prev.error ? prev : { error: e, copied: false }));
    try { this.props.onError?.(e); } catch { /* a logger must not take the error screen down */ }
  }

  private onWindowError = (ev: ErrorEvent) => {
    this.record(this.capture({
      message: ev.message || String(ev.error ?? 'Unknown error'), stack: ev.error?.stack, source: 'window',
    }));
  };

  private onRejection = (ev: PromiseRejectionEvent) => {
    const r = ev.reason as { message?: unknown; stack?: string } | undefined;
    this.record(this.capture({
      message: r?.message ? String(r.message) : String(r), stack: r?.stack, source: 'promise',
    }));
  };

  componentDidMount() {
    if (typeof window === 'undefined') return;
    window.addEventListener('error', this.onWindowError);
    window.addEventListener('unhandledrejection', this.onRejection);
  }

  componentWillUnmount() {
    if (typeof window === 'undefined') return;
    window.removeEventListener('error', this.onWindowError);
    window.removeEventListener('unhandledrejection', this.onRejection);
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      error: {
        message: error?.message || String(error), stack: error?.stack, source: 'render',
        reference: makeReference(), at: new Date().toISOString(),
      },
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    const cur = this.state.error;
    const full: CapturedError = {
      message: error?.message || String(error), stack: error?.stack, source: 'render',
      componentStack: info.componentStack ?? undefined,
      reference: cur?.reference ?? makeReference(), at: cur?.at ?? new Date().toISOString(),
    };
    this.setState({ error: full });
    try { this.props.onError?.(full); } catch { /* see record() */ }
  }

  private details(): string {
    const e = this.state.error;
    if (!e) return '';
    return [
      `Reference: ${e.reference}`, `Time: ${e.at}`, `Source: ${e.source}`, `Message: ${e.message}`,
      e.stack ? `\nStack:\n${e.stack}` : '', e.componentStack ? `\nComponents:${e.componentStack}` : '',
    ].filter(Boolean).join('\n');
  }

  private copy = async () => {
    try {
      await navigator.clipboard.writeText(this.details());
      this.setState({ copied: true });
    } catch {
      /* clipboard unavailable: the details stay visible for a screenshot */
    }
  };

  private reset = () => this.setState({ error: null, copied: false });

  render() {
    const { error, copied } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="kbg-state kbg-state--error kbg-boundary" role="alert">
        <p className="kbg-state__title">Something went wrong on this screen</p>
        <p className="kbg-state__body">
          {this.props.whatToDo ?? 'Your saved work is not affected. Try again; if it keeps happening, quote the reference below.'}
        </p>
        <p className="kbg-state__ref">Reference: <code>{error.reference}</code></p>
        <div className="kbg-boundary__actions">
          <button type="button" onClick={this.reset}>Try again</button>
          <button type="button" onClick={this.copy}>{copied ? 'Copied' : 'Copy details'}</button>
        </div>
        <details className="kbg-boundary__details">
          <summary>Technical details</summary>
          <pre>{this.details()}</pre>
        </details>
      </div>
    );
  }
}
