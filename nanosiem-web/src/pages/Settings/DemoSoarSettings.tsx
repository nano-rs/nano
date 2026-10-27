// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { SettingsSection } from '@/components/settings/SettingsSection';
import { Button } from '@/components/ui/button';
import { DetailSheet } from '@/components/ui/detail-sheet';
import type { SoarReadFlow } from '@/lib/api/soar';

export function DemoSoarSettings() {
  const tenant = browserTenantRuntime.current().key;
  const [flow, setFlow] = useState<SoarReadFlow | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const flows = useQuery({
    queryKey: ['soar-demo-flows', tenant],
    queryFn: () => api.soar.listFlows(),
  });
  const runs = useQuery({
    queryKey: ['soar-demo-runs', tenant],
    queryFn: () => api.soar.listRuns(),
  });
  const packs = useQuery({
    queryKey: ['soar-demo-packs', tenant],
    queryFn: () => api.soar.listPacks(),
  });
  const detail = useQuery({
    queryKey: ['soar-demo-run', tenant, runId],
    queryFn: () => api.soar.runDetail(runId!),
    enabled: !!runId,
  });
  const error = flows.error ?? runs.error ?? packs.error;
  return (
    <div className="max-w-[1160px] space-y-6 px-6 py-5 text-xs">
      <header className="space-y-2">
        <h1 className="text-[18px] font-semibold tracking-tight">SOAR</h1>
        <p className="text-[11.5px] text-muted-foreground">
          Read-only demo. External actions render without sending. Search and
          Judge steps can run.
        </p>
        <p className="font-mono text-[10.5px] text-muted-foreground">
          Flows · run history · pack catalog
        </p>
      </header>
      {error && (
        <p role="alert" className="text-destructive">
          Unable to load SOAR history. Try again.
        </p>
      )}
      <div className="space-y-5">
        <SettingsSection
          title="Flows"
          description="Inspect the flow structure. Editing and run triggers are unavailable to demo sessions."
        >
          {flows.isPending ? (
            <p className="p-4 text-muted-foreground">Loading flows…</p>
          ) : flows.data?.flows.length === 0 ? (
            <p className="p-4 text-muted-foreground">No flows yet.</p>
          ) : (
            flows.data?.flows.map((item) => (
              <div
                key={item.id}
                className="flex min-h-7 items-center justify-between gap-3 border-b border-border px-3 last:border-0"
              >
                <span className="truncate font-mono text-[11.5px]">
                  {item.name}
                </span>
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  v{item.version} · {item.status}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-[11.5px] shadow-none"
                  onClick={() => setFlow(item)}
                >
                  View flow
                </Button>
              </div>
            ))
          )}
        </SettingsSection>
        <SettingsSection
          title="Run history"
          description="Read completed steps and their outputs. Demo tenant actions make no outbound vendor or notification calls."
        >
          {runs.isPending ? (
            <p className="p-4 text-muted-foreground">Loading runs…</p>
          ) : runs.data?.runs.length === 0 ? (
            <p className="p-4 text-muted-foreground">No runs yet.</p>
          ) : (
            runs.data?.runs.map((item) => (
              <div
                key={item.id}
                className="flex min-h-7 items-center justify-between gap-3 border-b border-border px-3 font-mono text-[10.5px] last:border-0"
              >
                <span>
                  {item.trigger_kind} · {item.status}
                </span>
                <time dateTime={item.created_at}>{item.created_at}</time>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 font-sans text-[11.5px] shadow-none"
                  onClick={() => setRunId(item.id)}
                >
                  View run
                </Button>
              </div>
            ))
          )}
        </SettingsSection>
        <SettingsSection
          title="Pack catalog"
          description="Browse available response integrations without connections or credentials."
        >
          {packs.isPending ? (
            <p className="p-4 text-muted-foreground">Loading catalog…</p>
          ) : packs.data?.packs.length === 0 ? (
            <p className="p-4 text-muted-foreground">No packs available.</p>
          ) : (
            packs.data?.packs.map((item) => (
              <div
                key={item.name}
                className="flex min-h-7 items-center justify-between gap-3 border-b border-border px-3 font-mono text-[10.5px] last:border-0"
              >
                <span>{item.display_name || item.name}</span>
                <span className="text-muted-foreground">
                  {item.vendor} · {item.version}
                </span>
              </div>
            ))
          )}
        </SettingsSection>
      </div>
      <DetailSheet
        open={!!flow}
        onOpenChange={(open) => {
          if (!open) setFlow(null);
        }}
        size="lg"
        title={flow?.name ?? 'Flow'}
        breadcrumb={['Settings', 'SOAR']}
        className="shadow-none"
      >
        <pre className="overflow-auto whitespace-pre-wrap break-all p-4 font-mono text-[10.5px]">
          {JSON.stringify(flow?.definition, null, 2)}
        </pre>
      </DetailSheet>
      <DetailSheet
        open={!!runId}
        onOpenChange={(open) => {
          if (!open) setRunId(null);
        }}
        size="lg"
        title="Run history"
        breadcrumb={['Settings', 'SOAR']}
        className="shadow-none"
      >
        {detail.isError ? (
          <p role="alert" className="p-4 text-destructive">
            Unable to load this run.
          </p>
        ) : detail.isPending ? (
          <p className="p-4">Loading run…</p>
        ) : (
          detail.data?.steps.map((step) => (
            <div key={step.id} className="space-y-2 border-b border-border p-4">
              <p className="font-mono text-[11.5px]">
                {step.module_id} · {step.phase} · {step.status}
              </p>
              <pre className="overflow-auto whitespace-pre-wrap break-all font-mono text-[10.5px]">
                {JSON.stringify(step.outputs, null, 2)}
              </pre>
            </div>
          ))
        )}
      </DetailSheet>
    </div>
  );
}
