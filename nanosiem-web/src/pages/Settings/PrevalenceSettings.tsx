// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useId } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { NumberInput } from '@/components/ui/number-input';
import { Switch } from '@/components/ui/switch';
import {
  AlertTriangle,
  Hash,
  Globe,
  Loader2,
  Save,
  RotateCcw,
  Network,
} from 'lucide-react';
import { usePrevalenceSettings, useUpdatePrevalenceSettings } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';

const DEFAULTS = {
  rarity_threshold: 3,
  enable_hash_tracking: true,
  enable_domain_tracking: true,
  enable_ip_tracking: true,
  retention_days: 90,
  cache_ttl_seconds: 60,
} as const;

const TRACKING_OPTIONS = [
  {
    key: 'hash' as const,
    icon: Hash,
    color: 'text-primary',
    label: 'Hash tracking',
    hint: 'Track MD5 and SHA256 file hashes.',
  },
  {
    key: 'domain' as const,
    icon: Globe,
    color: 'text-emerald-400',
    label: 'Domain tracking',
    hint: 'Track domains and subdomains.',
  },
  {
    key: 'ip' as const,
    icon: Network,
    color: 'text-purple-400',
    label: 'IP address tracking',
    hint: 'Track source and destination IP addresses.',
  },
];

export function PrevalenceSettings() {
  useDocumentTitle('Prevalence Settings');

  const { toast } = useToast();
  const { data: settings, loading: loadingSettings, error: loadError, refetch } = usePrevalenceSettings();
  const { mutate: updateSettings, loading: saving } = useUpdatePrevalenceSettings();

  const [rarityThreshold, setRarityThreshold] = useState<number>(DEFAULTS.rarity_threshold);
  const [enableHashTracking, setEnableHashTracking] = useState<boolean>(DEFAULTS.enable_hash_tracking);
  const [enableDomainTracking, setEnableDomainTracking] = useState<boolean>(DEFAULTS.enable_domain_tracking);
  const [enableIpTracking, setEnableIpTracking] = useState<boolean>(DEFAULTS.enable_ip_tracking);
  const [retentionDays, setRetentionDays] = useState<number>(DEFAULTS.retention_days);
  const [cacheTtlSeconds, setCacheTtlSeconds] = useState<number>(DEFAULTS.cache_ttl_seconds);

  const baseId = useId();

  useEffect(() => {
    if (settings) {
      setRarityThreshold(settings.rarity_threshold);
      setEnableHashTracking(settings.enable_hash_tracking);
      setEnableDomainTracking(settings.enable_domain_tracking);
      setEnableIpTracking(settings.enable_ip_tracking ?? true);
      setRetentionDays(settings.retention_days);
      setCacheTtlSeconds(settings.cache_ttl_seconds);
    }
  }, [settings]);

  const hasChanges =
    settings != null &&
    (rarityThreshold !== settings.rarity_threshold ||
      enableHashTracking !== settings.enable_hash_tracking ||
      enableDomainTracking !== settings.enable_domain_tracking ||
      enableIpTracking !== (settings.enable_ip_tracking ?? true) ||
      retentionDays !== settings.retention_days ||
      cacheTtlSeconds !== settings.cache_ttl_seconds);

  const handleSave = async () => {
    try {
      await updateSettings({
        rarity_threshold: rarityThreshold,
        enable_hash_tracking: enableHashTracking,
        enable_domain_tracking: enableDomainTracking,
        enable_ip_tracking: enableIpTracking,
        retention_days: retentionDays,
        cache_ttl_seconds: cacheTtlSeconds,
      });
      toast({
        title: 'Settings saved',
        description: 'Prevalence configuration has been updated.',
      });
      refetch();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to save settings';
      toast({ title: 'Error', description: message, variant: 'destructive' });
    }
  };

  const handleReset = () => {
    setRarityThreshold(DEFAULTS.rarity_threshold);
    setEnableHashTracking(DEFAULTS.enable_hash_tracking);
    setEnableDomainTracking(DEFAULTS.enable_domain_tracking);
    setEnableIpTracking(DEFAULTS.enable_ip_tracking);
    setRetentionDays(DEFAULTS.retention_days);
    setCacheTtlSeconds(DEFAULTS.cache_ttl_seconds);
  };

  if (loadingSettings && !settings) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="px-6 py-5">
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-4 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] font-medium text-red-400">Failed to load settings</div>
            <div className="text-[11px] text-muted-foreground mt-0.5">{loadError.message}</div>
            <Button
              onClick={() => refetch()}
              variant="outline"
              size="sm"
              className="h-7 text-[11.5px] px-2.5 mt-2 border-red-500/30 text-red-400"
            >
              Try again
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const rarityInputId = `${baseId}-rarity`;
  const rarityDescId = `${baseId}-rarity-desc`;
  const retentionInputId = `${baseId}-retention`;
  const retentionDescId = `${baseId}-retention-desc`;
  const cacheInputId = `${baseId}-cache`;
  const cacheDescId = `${baseId}-cache-desc`;

  const trackingValues: Record<string, [boolean, (v: boolean) => void]> = {
    hash: [enableHashTracking, setEnableHashTracking],
    domain: [enableDomainTracking, setEnableDomainTracking],
    ip: [enableIpTracking, setEnableIpTracking],
  };

  return (
    <div className="px-6 py-5 space-y-7">
      <div>
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Rarity Thresholds</h1>
        <p className="text-[11.5px] text-muted-foreground mt-0.5">
          Artifact prevalence, rarity policy, tracking scope
        </p>
      </div>

      <section>
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Rarity policy
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          An artifact seen on fewer hosts than this threshold is flagged as <em>rare</em>. Lower values mean stricter rarity detection.
        </p>

        <div className="flex flex-col">
          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={rarityInputId} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Host count threshold
              </label>
              <div id={rarityDescId} className="text-[11px] text-muted-foreground mt-0.5">
                Recommended 3–5 for most environments. Increase for larger fleets.
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <NumberInput
                id={rarityInputId}
                min={1}
                max={1000}
                value={rarityThreshold}
                onChange={setRarityThreshold}
                aria-describedby={rarityDescId}
                className="h-8 w-[80px] text-center font-mono text-[12px]"
              />
              <span className="font-mono text-[10.5px] text-muted-foreground">hosts</span>
            </div>
          </div>
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Tracking scope
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Choose which artifact families participate in prevalence aggregation. Disabling a category stops tracking and frees ClickHouse capacity.
        </p>

        <div className="flex flex-col">
          {TRACKING_OPTIONS.map(({ key, icon: Icon, color, label, hint }) => {
            const [checked, onChange] = trackingValues[key];
            const switchId = `${baseId}-${key}`;
            return (
              <div key={key} className="flex items-center justify-between gap-4 py-3 border-b border-border/60">
                <div className="flex items-center gap-2.5 min-w-0">
                  <Icon className={`w-4 h-4 shrink-0 ${color}`} />
                  <div className="min-w-0">
                    <label htmlFor={switchId} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                      {label}
                    </label>
                    <div className="text-[11px] text-muted-foreground mt-0.5">{hint}</div>
                  </div>
                </div>
                <Switch
                  id={switchId}
                  checked={checked}
                  onCheckedChange={onChange}
                  className="h-4 w-7"
                />
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
          Retention & performance
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Controls how long prevalence aggregates are kept and how aggressively their lookups are cached.
        </p>

        <div className="flex flex-col">
          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={retentionInputId} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Data retention period
              </label>
              <div id={retentionDescId} className="text-[11px] text-muted-foreground mt-0.5">
                Aggregates older than this are dropped. (1–365 days)
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <NumberInput
                id={retentionInputId}
                min={1}
                max={365}
                value={retentionDays}
                onChange={setRetentionDays}
                aria-describedby={retentionDescId}
                className="h-8 w-[80px] text-center font-mono text-[12px]"
              />
              <span className="font-mono text-[10.5px] text-muted-foreground">days</span>
            </div>
          </div>

          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={cacheInputId} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Cache TTL
              </label>
              <div id={cacheDescId} className="text-[11px] text-muted-foreground mt-0.5">
                How long prevalence query results stay cached. Set to 0 to disable caching. (0–3600 s)
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <NumberInput
                id={cacheInputId}
                min={0}
                max={3600}
                value={cacheTtlSeconds}
                onChange={setCacheTtlSeconds}
                aria-describedby={cacheDescId}
                className="h-8 w-[80px] text-center font-mono text-[12px]"
              />
              <span className="font-mono text-[10.5px] text-muted-foreground">sec</span>
            </div>
          </div>
        </div>
      </section>

      <div className="flex justify-end items-center gap-2 pt-1">
        {hasChanges && (
          <span className="font-mono text-[10.5px] text-amber-400">Unsaved changes</span>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={handleReset}
          className="h-7 text-[11.5px] px-2.5"
        >
          <RotateCcw className="w-3 h-3 mr-1" />
          Reset to defaults
        </Button>
        <Button
          onClick={handleSave}
          disabled={saving || !hasChanges}
          size="sm"
          className="h-7 text-[11.5px] px-2.5"
        >
          {saving ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Save className="w-3 h-3 mr-1" />}
          Save changes
        </Button>
      </div>
    </div>
  );
}
