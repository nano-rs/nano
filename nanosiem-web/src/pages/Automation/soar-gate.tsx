// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — the Automation workspace is gated by the tenant `soar_enabled`
 * preference (Settings → SOAR, NAN-4462).
 *
 * The gate reads the same React Query entry as Settings → SOAR
 * (`['soar-settings', tenant]`). Saving the checkbox writes that entry with
 * `setQueryData`, so the rail entry and every Automation route flip without a
 * page reload. While the gate is not `enabled`, no other SOAR request is made.
 *
 * Demo principals cannot read `/api/soar/settings` (the NAN-4483 fence hides
 * it). For them the flow list doubles as the probe: it answers 404 while SOAR
 * is off, and it is a read route the demo projection already serves.
 */
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Workflow } from 'lucide-react';
import { api } from '@/lib/api';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

export type SoarGateState = 'unavailable' | 'loading' | 'disabled' | 'enabled' | 'error';

export interface SoarGate {
  state: SoarGateState;
  /** Demo principal: read projection only, every effect control hidden. */
  demo: boolean;
  /** Tenant key for query keys, so a tenant switch never reuses cached data. */
  tenant: string;
  retry: () => void;
}

export function soarSettingsKey(tenant: string) {
  return ['soar-settings', tenant] as const;
}

function httpStatus(error: unknown): number | undefined {
  const status = (error as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : undefined;
}

export function useSoarGate(): SoarGate {
  const { capabilities } = useCapabilities();
  const { hasPermission, isDemoUser } = useAuth();
  const tenant = browserTenantRuntime.current().key;
  const eligible = capabilities.soar && hasPermission('soar:view');
  const settings = useQuery({
    queryKey: soarSettingsKey(tenant),
    queryFn: () => api.soar.getSettings(),
    enabled: eligible && !isDemoUser,
    staleTime: 30_000,
    retry: false,
  });
  const demoProbe = useQuery({
    queryKey: ['soar-demo-gate', tenant],
    queryFn: () => api.soar.getFlows(),
    enabled: eligible && isDemoUser,
    staleTime: 60_000,
    retry: false,
  });
  if (!eligible) return { state: 'unavailable', demo: isDemoUser, tenant, retry: () => {} };
  if (isDemoUser) {
    const state: SoarGateState = demoProbe.isPending
      ? 'loading'
      : demoProbe.isError
        ? httpStatus(demoProbe.error) === 404 ? 'disabled' : 'error'
        : 'enabled';
    return { state, demo: true, tenant, retry: () => void demoProbe.refetch() };
  }
  const state: SoarGateState = settings.isPending
    ? 'loading'
    : settings.isError
      ? 'error'
      : settings.data.soar_enabled ? 'enabled' : 'disabled';
  return { state, demo: false, tenant, retry: () => void settings.refetch() };
}

/**
 * Route wrapper. Children (and therefore every data query they own) mount only
 * while SOAR is enabled; otherwise this renders an explicit state.
 */
export function SoarRouteGate({ children }: { children: ReactNode }) {
  const gate = useSoarGate();
  if (gate.state === 'enabled') return <>{children}</>;
  return <SoarGateNotice gate={gate} />;
}

export function SoarGateNotice({ gate }: { gate: SoarGate }) {
  const { hasPermission } = useAuth();
  if (gate.state === 'enabled') return null;
  if (gate.state === 'loading') {
    return (
      <div className="flex h-full items-center justify-center" role="status" aria-label="Loading automation">
        <LoadingIcon className="h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
      </div>
    );
  }
  const copy = {
    unavailable: {
      title: 'Automation is not available',
      body: 'This tenant plan does not include SOAR, or your role cannot view automation.',
    },
    disabled: {
      title: 'SOAR is disabled',
      body: gate.demo
        ? 'Automation is turned off for this tenant.'
        : 'Enable it in Settings → SOAR to see runs, flows, approvals and capabilities.',
    },
    error: {
      title: 'Automation status is unavailable',
      body: 'The SOAR setting could not be loaded. Try again in a moment.',
    },
  }[gate.state];
  const canOpenSettings =
    gate.state === 'disabled' && !gate.demo &&
    (hasPermission('soar:view') || hasPermission('settings:system'));
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center" data-testid={`soar-gate-${gate.state}`}>
      <Workflow className="mb-3 h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
      <h1 className="mb-1 text-[13px] font-semibold text-foreground">{copy.title}</h1>
      <p className="mb-4 max-w-md text-[12px] text-muted-foreground">{copy.body}</p>
      {canOpenSettings && (
        <Link
          to="/settings/soar"
          className="inline-flex h-7 items-center rounded-md border border-border px-3 text-[12px] text-foreground hover:bg-accent"
        >
          Open Settings → SOAR
        </Link>
      )}
      {gate.state === 'error' && (
        <button
          type="button"
          onClick={gate.retry}
          className="inline-flex h-7 items-center rounded-md border border-border px-3 text-[12px] text-foreground hover:bg-accent"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** pivt on flows (drafting, NAN-4535; conversational edit, NAN-4653) needs
 *  the enterprise build, meloD, and both the `melod:chat` and `soar:manage`
 *  permissions the server checks. */
export function useFlowPivt(demo: boolean): boolean {
  const { hasPermission } = useAuth();
  const { edition, capabilities } = useCapabilities();
  return edition === 'enterprise' && capabilities.melod && !demo && hasPermission('melod:chat') && hasPermission('soar:manage');
}

/**
 * NAN-4660: why the Judge block cannot be added, or null. The server runs a
 * judge with the tenant AI principal and requires `melod:summarize` on the
 * requester (soar/flow/JUDGE.md), so the palette needs meloD and that permission.
 */
export function useJudgeBlock(): string | null {
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  if (!capabilities.melod) return 'AI judge needs meloD, which is not enabled for this tenant';
  if (!hasPermission('melod:summarize')) return 'AI judge needs the melod:summarize permission';
  return null;
}
