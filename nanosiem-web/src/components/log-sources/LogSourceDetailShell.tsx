// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from 'react';

/**
 * Page root for Log Source detail. It uses the same shell as the other
 * document pages (Rules, Dashboards, Alerts): full width inside AppLayout's
 * `p-3` gutter, sections stacked with `gap-3`.
 *
 * NAN-3011: the page scrolls in the app shell's own scroll container
 * (AppLayout `scrollContainerRef`). It must not become a nested fixed-height
 * scroller (#4801 made the root `h-[calc(100%+1.5rem)] overflow-auto`).
 * NAN-3014: no centered max-width column and no bespoke gutters (#4801 used
 * `mx-auto max-w-[1360px] px-6 pt-6`); the editor tabs bound their own height
 * via EditorFrame.
 */
export const LOG_SOURCE_DETAIL_ROOT_CLASS = 'flex w-full min-w-0 flex-col gap-3';

export function LogSourceDetailShell({ children }: { children: ReactNode }) {
  return (
    <div data-testid="log-source-detail-page" className={LOG_SOURCE_DETAIL_ROOT_CLASS}>
      {children}
    </div>
  );
}
