// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ReactNode } from 'react';

/** Dense settings explanation beside its controls; stacks on narrow screens. */
export function SettingsSection({
  title,
  description,
  children,
}: {
  title: string;
  description: ReactNode;
  children: ReactNode;
}) {
  return (
    <section
      aria-label={title}
      className="grid min-w-0 gap-4 border-t border-border pt-5 first:border-t-0 first:pt-0 lg:grid-cols-[minmax(180px,0.65fr)_minmax(0,1.5fr)] lg:gap-8"
    >
      <div className="space-y-1.5 lg:max-w-[280px]">
        <h2 className="text-[12.5px] font-semibold text-foreground">{title}</h2>
        <div className="text-[11.5px] leading-relaxed text-muted-foreground">
          {description}
        </div>
      </div>
      <div className="min-w-0 rounded-md border border-border bg-card">
        {children}
      </div>
    </section>
  );
}
