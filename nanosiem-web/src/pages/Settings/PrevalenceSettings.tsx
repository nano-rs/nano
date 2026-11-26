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
  Save,
  RotateCcw,
  Network,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { usePrevalenceSettings, useUpdatePrevalenceSettings } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import { Term } from '@/components/ui/term';
import { SettingsGroup, SettingsPageHeader, SettingsRow } from '@/components/settings/SettingsForm';

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
        <LoadingIcon className="w-5 h-5 text-muted-foreground" />
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
      <SettingsPageHeader
        title={<Term id="rarity-threshold">Rarity Thresholds</Term>}
        description={
          <>
            How nano decides what is rare (<Term id="prevalence">prevalence</Term>) and what it tracks
          </>
        }
      />

      <SettingsGroup title="Rarity policy">
        <div className="flex flex-col">
          <SettingsRow
            label="Host count threshold"
            hint={
              <>
                Anything seen on fewer hosts than this counts as <em>rare</em>. 3 to 5 suits most networks.
              </>
            }
            hintId={rarityDescId}
            htmlFor={rarityInputId}
          >
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
          </SettingsRow>
        </div>
      </SettingsGroup>

      <SettingsGroup
        title="Tracking scope"
        description="Turning off a category stops tracking it and frees up database space."
      >
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
      </SettingsGroup>

      <SettingsGroup title="Retention & performance">
        <div className="flex flex-col">
          <SettingsRow
            label="Data retention period"
            hint="Counts older than this are deleted. (1–365 days)"
            hintId={retentionDescId}
            htmlFor={retentionInputId}
          >
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
          </SettingsRow>
          <SettingsRow
            label="Cache TTL"
            hint={
              <>
                How long a lookup answer is reused (<Term id="cache-ttl">TTL</Term>). 0 turns the cache off. (0–3600 s)
              </>
            }
            hintId={cacheDescId}
            htmlFor={cacheInputId}
          >
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
          </SettingsRow>
        </div>
      </SettingsGroup>

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
          <RotateCcw className="w-3 h-3" />
          Reset to defaults
        </Button>
        <Button
          onClick={handleSave}
          disabled={saving || !hasChanges}
          size="sm"
          className="h-7 text-[11.5px] px-2.5"
        >
          {saving ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
          Save changes
        </Button>
      </div>
    </div>
  );
}
