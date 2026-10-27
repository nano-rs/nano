// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the top-bar Approvals button (mock soar3-gate.jsx ApprovalsBell).
 * Kept light: AppLayout renders it on every page, so it imports no Automation
 * page code. It toggles the Approvals drawer through the `approvals` search
 * param inside /automation, and opens Runs with the drawer elsewhere.
 */
import { useMemo } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Hand } from 'lucide-react';
import type { SoarApproval } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';
import { decisionBlock, minutesLeft } from './soar-model';
import { useApprovals } from './soar-queries';
import { useSoarGate, type SoarGate } from './soar-gate';

function sortByExpiry(a: SoarApproval, b: SoarApproval) {
  return Date.parse(a.expires_at) - Date.parse(b.expires_at);
}

/** Pending approvals split into the ones this user can decide ("mine") and all. */
export function usePendingApprovals(gate: SoarGate) {
  const { user, hasPermission } = useAuth();
  const enabled = gate.state === 'enabled' && !gate.demo;
  const q = useApprovals(gate.tenant, 'pending', enabled);
  const now = Date.now();
  const pending = useMemo(() => [...(q.data?.approvals ?? [])].filter((a) => a.status === 'pending').sort(sortByExpiry), [q.data]);
  const mine = pending.filter((a) => !decisionBlock(a, { userId: user?.id, canApprove: hasPermission('soar:approve'), demo: gate.demo, now }));
  return { query: q, pending, mine };
}

// ── Top-bar button (mock ApprovalsBell) ─────────────────────────────────
export function ApprovalsBell() {
  const gate = useSoarGate();
  const location = useLocation();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { mine, pending } = usePendingApprovals(gate);
  if (gate.state !== 'enabled' || gate.demo) return null;
  const inAutomation = location.pathname.startsWith('/automation');
  const open = inAutomation && params.has('approvals');
  const soon = pending.some((a) => minutesLeft(a.expires_at) <= 10);
  const onClick = () => {
    if (!inAutomation) { navigate('/automation/runs?approvals'); return; }
    const p = new URLSearchParams(params);
    if (open) p.delete('approvals'); else p.set('approvals', '');
    setParams(p, { replace: true });
  };
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={open}
      title="Approvals waiting on you"
      className={cn(
        'flex h-[26px] items-center gap-1.5 rounded-md border px-2 text-[12px]',
        open ? 'border-border-2 bg-foreground/[0.06] text-foreground' : 'border-transparent text-fg-2 hover:bg-foreground/[0.04] hover:text-foreground',
      )}
      data-testid="approvals-bell"
    >
      <Hand className="h-3.5 w-3.5" strokeWidth={1.5} />
      Approvals
      {mine.length > 0 && (
        <span className={cn('flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1 font-mono text-[10.5px] text-background', soon ? 'bg-destructive' : 'bg-warning')}>
          {mine.length}
        </span>
      )}
    </button>
  );
}

