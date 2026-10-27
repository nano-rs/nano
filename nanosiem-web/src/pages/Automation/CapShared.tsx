// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — pieces shared by the Capabilities tabs (mock soar-shell.jsx:
 * SearchBox, TH/TD/Row, Disclosure, PageHeader-in-tab; soar-catalog.jsx
 * upgrade confirm).
 */
import { useState, type ReactNode } from 'react';
import { ChevronRight, Search } from 'lucide-react';
import type { SoarCatalogPack } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { cn } from '@/lib/utils';
import { GatedButton, xsButton } from './soar-kit';
import { availableVersion } from './cap-model';

export interface CapAccess {
  demo: boolean;
  canManage: boolean;
  canRun: boolean;
}
export function useCapAccess(demo: boolean): CapAccess {
  const { hasPermission } = useAuth();
  return { demo, canManage: !demo && hasPermission('soar:manage'), canRun: !demo && hasPermission('soar:run') };
}

/** Mock GatedButton bound to a permission; demo principals never see it. */
export function Gated({ perm, access, children, className, ...p }: {
  perm: 'soar:manage' | 'soar:run';
  access: CapAccess;
  children: ReactNode;
  className?: string;
  variant?: 'default' | 'outline' | 'ghost' | 'destructive';
  size?: 'sm' | 'xs';
  disabled?: boolean;
  reason?: string;
  onClick?: () => void;
}) {
  if (access.demo) return null;
  const { size = 'xs', variant = 'default', ...rest } = p;
  const allowed = perm === 'soar:manage' ? access.canManage : access.canRun;
  return (
    <GatedButton
      allowed={allowed}
      why={`Requires ${perm}`}
      size="sm"
      variant={variant}
      className={cn(size === 'xs' ? xsButton : 'h-8 px-3 text-[12px] shadow-none', 'gap-1.5', className)}
      {...rest}
    >
      {children}
    </GatedButton>
  );
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative w-[260px] max-w-full">
      <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="h-7 w-full rounded-md border border-border-2 bg-transparent pl-8 pr-2 text-[12px] text-foreground placeholder:text-fg-4 focus:outline-none focus:ring-1 focus:ring-ring"
      />
    </div>
  );
}

export function TH({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cn('h-8 whitespace-nowrap px-3 text-left font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground', className)}>{children}</th>;
}
export function TD({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn('h-11 px-3 align-middle text-[12.5px]', className)}>{children}</td>;
}
export function Row({ children, onClick, active, testId }: { children: ReactNode; onClick: () => void; active?: boolean; testId?: string }) {
  return (
    <tr
      onClick={onClick}
      data-testid={testId}
      className={cn('cursor-pointer border-b border-border transition-colors', active ? 'bg-primary/[0.06]' : 'hover:bg-foreground/[0.03]')}
    >
      {children}
    </tr>
  );
}

/** Second-level page header inside a Capabilities tab (mock PageHeader). */
export function TabHeader({ title, meta, actions }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start gap-x-4 gap-y-2 px-5 pb-3 pt-4">
      <div className="min-w-0 flex-1 sm:min-w-[300px]">
        <h2 className="text-[18px] font-semibold tracking-[-0.015em] text-foreground">{title}</h2>
        {meta && <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted-foreground [&>*]:whitespace-nowrap">{meta}</div>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Disclosure({ title, meta, children, defaultOpen = false }: { title: ReactNode; meta?: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-md border border-border">
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="flex h-8 w-full items-center gap-2 px-2.5 text-[11.5px] text-fg-2 hover:text-foreground">
        <ChevronRight className={cn('h-3 w-3 transition-transform', open && 'rotate-90')} strokeWidth={1.5} />
        {title}
        <span className="flex-1" />
        {meta && <span className="font-mono text-[10.5px] text-fg-4">{meta}</span>}
      </button>
      {open && <div className="border-t border-border px-2.5 py-2">{children}</div>}
    </div>
  );
}

/** Split a server change summary into the mock's + added / ~ changed / − removed lines. */
export function changeLines(summary: string): Array<['added' | 'changed' | 'removed' | 'note', string]> {
  const out: Array<['added' | 'changed' | 'removed' | 'note', string]> = [];
  for (const part of summary.split(/(?<=\.)\s+|\n+/).map((s) => s.trim()).filter(Boolean)) {
    const m = part.match(/^(added|adds|changed|changes|removed|removes)\b[:\s]*(.*)$/i);
    if (!m) { out.push(['note', part]); continue; }
    const k = m[1].toLowerCase().startsWith('add') ? 'added' : m[1].toLowerCase().startsWith('change') ? 'changed' : 'removed';
    out.push([k, m[2].replace(/\.$/, '')]);
  }
  return out;
}

export type PackChange = { pack: SoarCatalogPack; kind: 'install' | 'upgrade' | 'remove' };

/** Install / upgrade confirm (mock ConfirmDialog tone="brand" in soar-catalog.jsx). */
export function PackChangeDialog({ change, onClose, onConfirm, pending }: { change: PackChange | null; onClose: () => void; onConfirm: (c: PackChange) => void; pending?: boolean }) {
  const p = change?.pack;
  const to = p ? availableVersion(p) ?? p.version : '';
  const lines = p ? changeLines(p.change_summary ?? '') : [];
  return (
    <ConfirmDialog
      open={change !== null}
      onOpenChange={(o) => !o && onClose()}
      title={change?.kind === 'install' ? `Install ${p?.display_name}?` : change?.kind === 'remove' ? `Remove ${p?.display_name}?` : `Upgrade ${p?.display_name} to ${to}?`}
      description={
        change?.kind === 'install'
          ? `Adds ${p?.actions.length ?? 0} actions at version ${to}. Nothing runs until a connection exists and someone requests an action.`
          : change?.kind === 'remove'
            ? 'Removes the pack from this tenant. The server refuses while connections or flows still reference it; run history stays readable.'
            : `Server summary: runs already started keep ${p?.installed_version ?? ''}. Flows referencing changed actions are revalidated after upgrade.`
      }
      confirmLabel={change?.kind === 'install' ? 'Install' : change?.kind === 'remove' ? 'Remove pack' : `Upgrade to ${to}`}
      variant={change?.kind === 'remove' ? 'danger' : 'default'}
      loading={pending}
      onConfirm={() => change && onConfirm(change)}
    >
      {change?.kind === 'upgrade' && p ? (
        <div className="flex flex-col gap-2">
          <div className="font-mono text-[11.5px] text-foreground">{p.installed_version} → {to}</div>
          <div className="flex flex-col gap-1 rounded-md border border-border px-2.5 py-2 text-[11.5px]" data-testid="pack-changes">
            {lines.length === 0 && <div className="text-muted-foreground">No change summary from the server.</div>}
            {lines.map(([k, t], i) => (
              <div key={i}>
                {k === 'added' && <span className="mr-2 font-mono text-good">+ added</span>}
                {k === 'changed' && <span className="mr-2 font-mono text-warn">~ changed</span>}
                {k === 'removed' && <span className="mr-2 font-mono text-destructive">− removed</span>}
                <span className={k === 'note' ? 'text-fg-2' : 'text-foreground'}>{t}</span>
              </div>
            ))}
            {lines.length > 0 && !lines.some(([k]) => k === 'removed') && <div className="text-muted-foreground"><span className="mr-2 font-mono">− removed</span>none</div>}
          </div>
        </div>
      ) : null}
    </ConfirmDialog>
  );
}
