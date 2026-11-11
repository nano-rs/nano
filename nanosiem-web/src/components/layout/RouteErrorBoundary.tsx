// SPDX-License-Identifier: AGPL-3.0-or-later
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { isStaleBuildError, tryStaleBuildReload } from '@/lib/stale-build';
import { redactText } from '@/lib/support-diagnostics';

interface Props {
  /** The boundary clears its error when this changes (the route pathname). */
  resetKey: string;
  children: ReactNode;
  /** Test seam: defaults to the sessionStorage-guarded one-shot reload. */
  attemptReload?: () => boolean;
  onReload?: () => void;
}

interface State {
  error: Error | null;
  stale: boolean;
  reloading: boolean;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

/**
 * NAN-5273: catches a failed page inside the app shell so the nav stays usable.
 * A stale-build error (chunk load failure, a lazy page holding a second copy of
 * a context module) reloads the document once; if it fails again the panel says
 * nano was updated.
 */
export class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null, stale: false, reloading: false };

  static getDerivedStateFromError(value: unknown): Partial<State> {
    return { error: toError(value), stale: isStaleBuildError(value), reloading: false };
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    console.error('Route failed to render:', error, info.componentStack ?? '');
    if (isStaleBuildError(error) && (this.props.attemptReload ?? tryStaleBuildReload)()) {
      this.setState({ reloading: true });
    }
  }

  componentDidUpdate(prev: Props): void {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null, stale: false, reloading: false });
    }
  }

  private reload = () => {
    (this.props.onReload ?? (() => window.location.reload()))();
  };

  render() {
    const { error, stale, reloading } = this.state;
    if (!error) return this.props.children;
    if (reloading) {
      return <div className="p-4 text-[12px] text-muted-foreground" role="status">Reloading…</div>;
    }
    // Shown on screen and often screenshotted into tickets: redact like support reports.
    const details = redactText([`${error.name}: ${error.message}`, error.stack?.split('\n').slice(1, 9).join('\n')]
      .filter(Boolean).join('\n'));
    return (
      <div role="alert" data-testid="route-error" className="m-3 max-w-2xl rounded-md border border-border bg-card p-3 text-[12px]">
        <div className="flex items-center gap-2">
          <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4 shrink-0 text-destructive">
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v4.5M12 16h.01" />
          </svg>
          <h2 className="text-[13px] font-medium text-foreground">This page failed to load</h2>
          <button
            type="button"
            onClick={this.reload}
            className="ml-auto h-6 rounded border border-border px-2 text-[12px] text-foreground hover:bg-muted"
          >
            Reload
          </button>
        </div>
        <p className="mt-1 text-muted-foreground">
          {stale ? 'nano was updated, reload to continue.' : 'The rest of nano still works. Use the navigation, or reload this page.'}
        </p>
        <details className="mt-2">
          <summary className="cursor-pointer select-none text-[11px] text-muted-foreground">Error details</summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-muted/40 p-2 font-mono text-[10.5px] text-muted-foreground">{details}</pre>
        </details>
      </div>
    );
  }
}
