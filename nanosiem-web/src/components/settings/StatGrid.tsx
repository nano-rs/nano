// SPDX-License-Identifier: AGPL-3.0-or-later

/** Dense bordered stat grid (Settings storage panels). */
export interface StatCell {
  label: string;
  value: string;
  sub?: string | null;
}

export function StatGrid({ cells }: { cells: StatCell[] }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 border-l border-t border-border">
      {cells.map((c) => (
        <div key={c.label} className="px-4 py-3 border-r border-b border-border min-w-0">
          <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
            {c.label}
          </p>
          <p className="font-mono text-[16px] font-semibold tabular-nums text-foreground leading-none mt-1.5 truncate">
            {c.value}
          </p>
          {c.sub && (
            <p className="font-mono text-[10.5px] text-muted-foreground mt-1 truncate">{c.sub}</p>
          )}
        </div>
      ))}
    </div>
  );
}
