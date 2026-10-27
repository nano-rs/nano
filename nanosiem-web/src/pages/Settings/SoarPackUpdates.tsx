// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { api } from '@/lib/api';
import type { BulkApplySoarUpstreamResult, SoarUpstreamUpdate } from '@/lib/api/soar';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { SettingsSection } from '@/components/settings/SettingsSection';
import './SoarPackUpdates.css';

export function SoarPackUpdates({ enabled }: { enabled: boolean }) {
  const { hasPermission } = useAuth();
  const tenant = browserTenantRuntime.current().key;
  const client = useQueryClient();
  const queryKey = ['soar-upstream-updates', tenant];
  const canView = hasPermission('soar:view');
  const canManage = hasPermission('soar:manage');
  const [expanded, setExpanded] = useState(false);
  const [intent, setIntent] = useState<SoarUpstreamUpdate | 'all' | null>(null);
  const [result, setResult] = useState<BulkApplySoarUpstreamResult | null>(null);
  const updates = useQuery({
    queryKey, queryFn: () => api.soar.getUpstreamUpdates(), enabled: enabled && canView,
    staleTime: 0,
  });
  const apply = useMutation({
    mutationFn: async (target: SoarUpstreamUpdate | 'all') => {
      if (target === 'all') return api.soar.applyAllUpstreamUpdates();
      await api.soar.applyUpstreamUpdate(target.pack_name, target.upstream_version);
      return { updated: 1, failed: 0, results: [{ pack_name: target.pack_name, updated: true,
        version: target.upstream_version, message: 'Update applied' }] };
    },
    onMutate: () => setResult(null),
    onSuccess: (value) => { setResult(value); setIntent(null); },
    onSettled: () => {
      void client.invalidateQueries({ queryKey });
      void client.invalidateQueries({ queryKey: ['soar-packs', tenant] });
    },
  });
  if (!enabled || !canView) return null;
  const rows = updates.isError ? [] : updates.data?.updates ?? [];
  const count = updates.isError ? 0 : updates.data?.total_count ?? 0;
  const busy = apply.isPending || updates.isFetching;
  return (
    <SettingsSection title="Pack updates" description="Review upstream changes to installed SOAR packs and apply them individually or all at once.">
      <div className="n-soar-pack-updates-toolbar">
        <p className="n-soar-pack-updates-status" role="status">
          {updates.isError ? 'Pack updates are unavailable.' : updates.isPending ? 'Loading upstream updates…' : count > 0
            ? `${count} imported ${count === 1 ? 'pack has' : 'packs have'} upstream updates`
            : 'No upstream updates'}
        </p>
        {count > 0 && <Button className="n-soar-pack-updates-button" variant="link" size="sm" onClick={() => setExpanded(!expanded)}>{expanded ? 'Hide' : 'Review'}</Button>}
        {count > 0 && canManage && <Button className="n-soar-pack-updates-button" size="sm" disabled={busy} onClick={() => { apply.reset(); setIntent('all'); }}>Apply All Updates</Button>}
      </div>
      {updates.isError && <p role="alert" className="n-soar-pack-updates-notice n-soar-pack-updates-error">
        {updates.error instanceof Error ? updates.error.message : 'Unable to load upstream updates.'}
      </p>}
      {expanded && rows.length > 0 && <div className="n-soar-pack-updates-list">
        {rows.map(row => <div key={row.pack_name} className="n-soar-pack-updates-item">
          <div className="n-soar-pack-updates-copy"><p className="n-soar-pack-updates-name">{row.display_name}</p>
            <p className="n-soar-pack-updates-version">{row.installed_version} → {row.upstream_version}</p>
            <p className="n-soar-pack-updates-summary">{row.change_summary}</p>
          </div>
          {canManage && <Button className="n-soar-pack-updates-button" size="sm" variant="outline" disabled={busy} onClick={() => { apply.reset(); setIntent(row); }}>Apply Update</Button>}
        </div>)}
      </div>}
      {!canManage && count > 0 && <p className="n-soar-pack-updates-notice">Read-only. Applying updates requires the soar:manage permission.</p>}
      {apply.isError && <p role="alert" className="n-soar-pack-updates-notice n-soar-pack-updates-error">
        {apply.error instanceof Error ? apply.error.message : 'Unable to apply upstream updates.'}
      </p>}
      {result && <div className="n-soar-pack-updates-result" role="status">
        <p className="n-soar-pack-updates-result-count">{result.updated} updated · {result.failed} failed</p>
        {result.results.filter(row => !row.updated).map(row => <p key={row.pack_name} className="n-soar-pack-updates-error">{row.pack_name}: {row.message}</p>)}
      </div>}
      <ConfirmDialog open={intent !== null} onOpenChange={open => { if (!open) setIntent(null); }}
        title={intent === 'all' ? 'Apply All Updates' : 'Apply Update'}
        description="Applying updates changes the installed pack versions. Active runs using older versions can stop before their next request. Review the upstream changes before applying."
        confirmLabel={intent === 'all' ? 'Apply All Updates' : 'Apply Update'} loading={apply.isPending}
        onConfirm={() => { if (intent && canManage && !busy) apply.mutate(intent); }} />
    </SettingsSection>
  );
}
