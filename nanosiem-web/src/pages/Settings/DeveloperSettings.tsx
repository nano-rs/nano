// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Loader2,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { DeveloperSettings, UpdateDeveloperSettingsRequest } from '@/lib/api/types';

interface SchedulerRow {
  key: keyof DeveloperSettings;
  name: string;
  interval: string;
  clickhouseImpact: string;
}

const SCHEDULERS: SchedulerRow[] = [
  {
    key: 'detection_scheduler_enabled',
    name: 'Detection Scheduler',
    interval: '5s',
    clickhouseImpact: 'Queries for rule execution',
  },
  {
    key: 'tuning_scheduler_enabled',
    name: 'Tuning Scheduler',
    interval: '5min - 1hr',
    clickhouseImpact: 'Metrics, baselines, thresholds',
  },
  {
    key: 'enrichment_sync_scheduler_enabled',
    name: 'Enrichment Auto-Sync',
    interval: '5min',
    clickhouseImpact: 'May query for cleanup',
  },
  {
    key: 'custom_enrichment_scheduler_enabled',
    name: 'Custom Enrichment',
    interval: 'Configurable',
    clickhouseImpact: 'INSERT/SELECT for enrichments',
  },
  {
    key: 'feed_monitoring_enabled',
    name: 'Feed Staleness',
    interval: '5min',
    clickhouseImpact: 'SELECT max(timestamp) per source',
  },
  {
    key: 'ai_monitoring_enabled',
    name: 'AI Provider Monitoring',
    interval: '5min',
    clickhouseImpact: 'None (API calls only)',
  },
  {
    key: 'model_catalog_sync_scheduler_enabled',
    name: 'Model Catalog Auto-Sync',
    interval: '24hr',
    clickhouseImpact: 'None (GitHub fetch + PG only)',
  },
];

export function DeveloperSettings() {
  useDocumentTitle('Developer Settings');

  const { toast } = useToast();
  const [settings, setSettings] = useState<DeveloperSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [selected, setSelected] = useState<Set<keyof DeveloperSettings>>(new Set());

  const fetchSettings = async () => {
    try {
      setLoading(true);
      const data = await api.getDeveloperSettings();
      setSettings(data);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load settings',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleToggle = async (key: keyof DeveloperSettings, value: boolean) => {
    if (!settings) return;

    setUpdating(true);
    try {
      const updated = await api.updateDeveloperSettings({ [key]: value });
      setSettings(updated);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update settings',
        variant: 'destructive',
      });
    } finally {
      setUpdating(false);
    }
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelected(new Set(SCHEDULERS.map(s => s.key)));
    } else {
      setSelected(new Set());
    }
  };

  const handleSelectOne = (key: keyof DeveloperSettings, checked: boolean) => {
    const newSelected = new Set(selected);
    if (checked) {
      newSelected.add(key);
    } else {
      newSelected.delete(key);
    }
    setSelected(newSelected);
  };

  const handleBulkAction = async (enable: boolean) => {
    if (!settings || selected.size === 0) return;

    setUpdating(true);
    try {
      const updates: UpdateDeveloperSettingsRequest = {};
      selected.forEach(key => {
        updates[key] = enable;
      });
      const updated = await api.updateDeveloperSettings(updates);
      setSettings(updated);
      setSelected(new Set());
      toast({
        title: enable ? 'Schedulers enabled' : 'Schedulers paused',
        description: `${selected.size} scheduler${selected.size > 1 ? 's' : ''} ${enable ? 'enabled' : 'paused'}.`,
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update settings',
        variant: 'destructive',
      });
    } finally {
      setUpdating(false);
    }
  };

  const disabledCount = settings
    ? SCHEDULERS.filter(s => !settings[s.key]).length
    : 0;

  const allSelected = selected.size === SCHEDULERS.length;
  const someSelected = selected.size > 0 && selected.size < SCHEDULERS.length;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="px-6 py-5">
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 flex items-center gap-2.5">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <p className="text-[12px] text-red-400">Failed to load developer settings.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="px-6 py-5 space-y-5">
      <div>
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Developer Settings</h1>
        <p className="text-[11.5px] text-muted-foreground mt-0.5">Background scheduler controls for development environments</p>
      </div>

      {disabledCount > 0 && (
        <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 px-4 py-3 flex items-start gap-2.5">
          <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
          <div>
            <p className="text-[12.5px] font-medium text-yellow-400">
              {disabledCount === SCHEDULERS.length
                ? 'All schedulers paused'
                : `${disabledCount} scheduler${disabledCount > 1 ? 's' : ''} paused`}
            </p>
            <p className="text-[11.5px] text-muted-foreground mt-0.5">
              {disabledCount === SCHEDULERS.length
                ? 'ClickHouse Cloud will enter idle mode after the timeout period.'
                : 'Some background tasks are paused. This may affect detection execution, tuning, or enrichment updates.'}
            </p>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="border-b border-border px-4 py-3 flex items-center justify-between bg-card/50">
          <div>
            <span className="text-[13px] font-semibold text-foreground">Background Schedulers</span>
            <span className="text-[11.5px] text-muted-foreground ml-2">Disable to prevent ClickHouse Cloud from being kept alive during development</span>
          </div>
          {selected.size > 0 && (
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-muted-foreground">{selected.size} selected</span>
              <Button size="sm" variant="outline" onClick={() => handleBulkAction(true)} disabled={updating} className="h-7 text-[11px] border-border">Enable</Button>
              <Button size="sm" variant="outline" onClick={() => handleBulkAction(false)} disabled={updating} className="h-7 text-[11px] border-border">Pause</Button>
            </div>
          )}
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-border/60">
              <th className="text-left px-3 py-2 w-10">
                <Checkbox
                  checked={allSelected}
                  onCheckedChange={handleSelectAll}
                  aria-label="Select all"
                  className={someSelected ? 'data-[state=checked]:bg-primary/50' : ''}
                  {...(someSelected ? { 'data-state': 'checked' } : {})}
                />
              </th>
              <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Scheduler</th>
              <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Interval</th>
              <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">ClickHouse Impact</th>
              <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Status</th>
              <th className="text-right px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Enabled</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {SCHEDULERS.map((scheduler) => {
              const enabled = settings[scheduler.key];
              return (
                <tr key={scheduler.key} className="hover:bg-foreground/[0.025] transition-colors">
                  <td className="px-3 py-2">
                    <Checkbox
                      checked={selected.has(scheduler.key)}
                      onCheckedChange={(checked) => handleSelectOne(scheduler.key, checked as boolean)}
                      aria-label={`Select ${scheduler.name}`}
                    />
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-[12.5px] font-medium text-foreground">{scheduler.name}</span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[10.5px] text-muted-foreground">{scheduler.interval}</span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-[11.5px] text-muted-foreground">{scheduler.clickhouseImpact}</span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`font-mono text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-muted/40 text-muted-foreground'}`}>
                      {enabled ? 'Running' : 'Paused'}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Switch
                      checked={enabled}
                      onCheckedChange={(v) => handleToggle(scheduler.key, v)}
                      disabled={updating}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="text-[11.5px] text-muted-foreground">
        These settings are intended for development and testing. Disabling schedulers in production
        will stop detection execution, enrichment updates, and monitoring.
      </p>
    </div>
  );
}
