// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5798: the seam between the app's error boundary and opt-in error
// tracking. No SDK import: without Sentry in the build, reports go nowhere.

export interface ErrorReporter {
  captureBoundary(error: unknown, componentStack: string): void;
}

let reporter: ErrorReporter | null = null;

export function setErrorReporter(next: ErrorReporter | null): void {
  reporter = next;
}

/** Called by RouteErrorBoundary.componentDidCatch. A no-op unless Sentry started. */
export function reportBoundaryError(error: unknown, componentStack: string): void {
  try {
    reporter?.captureBoundary(error, componentStack);
  } catch {
    // Reporting must never break the boundary.
  }
}
