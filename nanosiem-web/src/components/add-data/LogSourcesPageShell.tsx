// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ComponentType, ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LogSourcesTabs } from './LogSourcesTabs';

type Tab = Parameters<typeof LogSourcesTabs>[0]['active'];

/**
 * Shared full-width shell for the Log sources family (Log sources, Onboarding,
 * Credentials). The app header already renders the breadcrumb, so pages in this
 * shell never add their own. Normal document flow inside the app scroller: no
 * centred max-width box and no fill-height inner scroll column (NAN-3250, NAN-3769).
 */
export function LogSourcesPageShell({
  active,
  testId,
  tabs = true,
  className,
  children,
}: {
  active: Tab;
  testId: string;
  tabs?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn('flex flex-col min-h-full -m-3 bg-background', className)}
      data-testid={testId}
      data-page-shell="log-sources"
    >
      {tabs && <LogSourcesTabs active={active} />}
      {children}
    </div>
  );
}

/** Title row + mono meta row, matching the Credentials page header. */
export function LogSourcesPageHeader({
  icon: Icon,
  title,
  actions,
  meta,
  children,
}: {
  icon: ComponentType<{ className?: string; strokeWidth?: number }>;
  title: string;
  actions?: ReactNode;
  meta?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="shrink-0 border-b border-border px-5 py-3">
      <div className="flex items-center gap-2.5 flex-wrap">
        <Icon className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
        <h1 className="text-[16px] font-semibold tracking-[-0.01em] text-foreground">{title}</h1>
        <span className="flex-1" />
        {actions}
      </div>
      {meta && (
        <div className="flex items-center gap-4 mt-1.5 font-mono text-[10.5px] text-muted-foreground tabular-nums">
          {meta}
        </div>
      )}
      {children}
    </div>
  );
}
