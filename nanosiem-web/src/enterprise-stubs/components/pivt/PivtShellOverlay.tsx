// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for PivtShellOverlay. Real implementation hosts the
// docked pivt panel as a flex sibling alongside the main content; the stub
// just passes children through so the surrounding flex layout still works
// in open mode.

import type { ReactNode } from 'react';

// `props` is typed loosely so consumers (AppLayout) can pass `state` and
// other real-side props without TS complaining about extras here.
export function PivtShellOverlay(
  props: { children?: ReactNode } & Record<string, unknown>,
) {
  return <>{props.children}</>;
}
