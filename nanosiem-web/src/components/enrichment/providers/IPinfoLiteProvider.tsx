// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * IPinfo Lite Provider Configuration Component
 *
 * Handles configuration and management of the IPinfo Lite enrichment source.
 * Provides geolocation and ASN data for IP address enrichment.
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  Globe,
  RefreshCw,
  Loader2,
  CircleCheck,
  XCircle,
  Database,
  Search,
  Clock,
  CircleAlert,
  Calendar,
  Save,
} from 'lucide-react';
import { api, EnrichmentSource, IpLookupResult, AutoSyncConfig } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatUTC, formatNumber } from '@/lib/date-utils';
import { useAuth } from '@/contexts/AuthContext';

interface IPinfoLiteProviderProps {
  source: EnrichmentSource;
  onRefresh: () => void;
}

export function IPinfoLiteProvider({ source, onRefresh }: IPinfoLiteProviderProps) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canConfigure = hasPermission('enrichments:configure');

  // Configuration state
  const [ipinfoUrl, setIpinfoUrl] = useState(source.download_url || '');
  const [configuring, setConfiguring] = useState(false);
  const [syncing, setSyncing] = useState(false);

  // IP Lookup test
  const [testIp, setTestIp] = useState('');
  const [lookupResult, setLookupResult] = useState<IpLookupResult | null>(null);
  const [lookingUp, setLookingUp] = useState(false);

  // Auto-sync config
  const [autoSyncConfig, setAutoSyncConfig] = useState<AutoSyncConfig | null>(null);
  const [savingAutoSync, setSavingAutoSync] = useState(false);

  // Confirmation dialogs
  const [showEnableDialog, setShowEnableDialog] = useState(false);
  const [showDisableDialog, setShowDisableDialog] = useState(false);
  const [showConfigureDialog, setShowConfigureDialog] = useState(false);
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [pendingUrlChange, setPendingUrlChange] = useState(false);

  // Load auto-sync config
  useEffect(() => {
    const loadAutoSyncConfig = async () => {
      try {
        const config = await api.getAutoSyncConfig();
        setAutoSyncConfig(config);
      } catch {
        // Auto-sync config may not exist yet
      }
    };
    loadAutoSyncConfig();
  }, [source.id]);

  // Update URL when source changes
  useEffect(() => {
    setIpinfoUrl(source.download_url || '');
    setPendingUrlChange(false);
  }, [source.download_url]);

  const handleConfigureClick = () => {
    if (!ipinfoUrl.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter the IPinfo download URL',
        variant: 'destructive',
      });
      return;
    }
    setShowConfigureDialog(true);
  };

  const handleConfigureConfirm = async () => {
    setShowConfigureDialog(false);
    try {
      setConfiguring(true);
      await api.configureIpinfo({ download_url: ipinfoUrl });
      setPendingUrlChange(false);
      toast({
        title: 'Configuration Saved',
        description: 'IPinfo Lite URL has been saved. Click "Sync Now" to download and load the data.',
      });
      onRefresh();
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to configure IPinfo',
        variant: 'destructive',
      });
    } finally {
      setConfiguring(false);
    }
  };

  const handleSyncClick = () => {
    setShowSyncDialog(true);
  };

  const handleSyncConfirm = async () => {
    setShowSyncDialog(false);
    try {
      setSyncing(true);

      // Start the async sync
      const result = await api.syncIpinfo();

      if (!result.started) {
        // Sync already in progress (409)
        toast({
          title: 'Sync Already Running',
          description: 'A sync is already in progress. The status will update when it completes.',
        });
      } else {
        toast({
          title: 'Sync Started',
          description: 'Downloading and processing IP enrichment data. This may take a few minutes...',
        });
      }

      // Poll for completion
      const pollForCompletion = async () => {
        const pollInterval = 5000; // 5 seconds
        const maxPollTime = 1800000; // 30 minutes
        const startTime = Date.now();

        while (Date.now() - startTime < maxPollTime) {
          await new Promise(resolve => setTimeout(resolve, pollInterval));

          const sources = await api.listEnrichmentSources();
          const updatedSource = sources.find(s => s.id === source.id);

          if (updatedSource && updatedSource.last_sync_status !== 'in_progress') {
            // Sync complete - refresh and show result
            onRefresh();

            if (updatedSource.last_sync_status === 'success') {
              toast({
                title: 'Sync Complete',
                description: `Successfully loaded ${formatNumber(updatedSource.record_count)} IP records`,
              });
            } else {
              toast({
                title: 'Sync Failed',
                description: 'The sync operation failed. Check the server logs for details.',
                variant: 'destructive',
              });
            }
            return;
          }
        }

        // Timeout - sync is still running
        toast({
          title: 'Sync Still Running',
          description: 'The sync is taking longer than expected. Check the status later.',
        });
      };

      await pollForCompletion();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to sync IPinfo data';
      toast({
        title: 'Sync Failed',
        description: message,
        variant: 'destructive',
      });
    } finally {
      setSyncing(false);
    }
  };

  const handleToggleClick = (enabled: boolean) => {
    if (enabled) {
      setShowEnableDialog(true);
    } else {
      setShowDisableDialog(true);
    }
  };

  const handleEnableConfirm = async () => {
    setShowEnableDialog(false);
    try {
      await api.enableEnrichmentSource(source.id);
      toast({
        title: 'Enrichment Enabled',
        description: 'IP enrichment is now active. New logs will be enriched with geolocation and ASN data.',
      });
      onRefresh();
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to enable enrichment source',
        variant: 'destructive',
      });
    }
  };

  const handleDisableConfirm = async () => {
    setShowDisableDialog(false);
    try {
      await api.disableEnrichmentSource(source.id);
      toast({
        title: 'Enrichment Disabled',
        description: 'IP enrichment has been disabled. New logs will not be enriched.',
      });
      onRefresh();
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to disable enrichment source',
        variant: 'destructive',
      });
    }
  };

  const handleLookup = async () => {
    if (!testIp.trim()) return;

    try {
      setLookingUp(true);
      const result = await api.lookupIp(testIp.trim());
      setLookupResult(result);
    } catch {
      toast({
        title: 'Lookup Failed',
        description: 'Failed to lookup IP',
        variant: 'destructive',
      });
    } finally {
      setLookingUp(false);
    }
  };

  const handleAutoSyncToggle = async (enabled: boolean) => {
    try {
      setSavingAutoSync(true);
      const result = await api.configureAutoSync({
        enabled,
        interval_hours: autoSyncConfig?.interval_hours || 24
      });
      setAutoSyncConfig(result);
      toast({
        title: enabled ? 'Auto-sync enabled' : 'Auto-sync disabled',
        description: enabled
          ? `Will sync every ${result.interval_hours} hours`
          : 'Automatic syncing has been disabled',
      });
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to update auto-sync settings',
        variant: 'destructive',
      });
    } finally {
      setSavingAutoSync(false);
    }
  };

  const handleIntervalChange = async (hours: string) => {
    try {
      setSavingAutoSync(true);
      const result = await api.configureAutoSync({
        enabled: autoSyncConfig?.enabled ?? true,
        interval_hours: parseInt(hours)
      });
      setAutoSyncConfig(result);
      toast({
        title: 'Sync interval updated',
        description: `Will sync every ${hours} hours`,
      });
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to update sync interval',
        variant: 'destructive',
      });
    } finally {
      setSavingAutoSync(false);
    }
  };

  return (
    <>
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-primary/10 rounded-xl">
                <Database className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">IP Records</p>
                <p className="text-2xl font-bold text-foreground">
                  {formatNumber(source.record_count)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-green-500/10 rounded-xl">
                {source.enabled ? (
                  <CircleCheck className="w-6 h-6 text-green-400" />
                ) : (
                  <XCircle className="w-6 h-6 text-muted-foreground" />
                )}
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Status</p>
                <p className="text-2xl font-bold text-foreground">
                  {source.enabled ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-purple-500/10 rounded-xl">
                <Clock className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Last Sync</p>
                <p className="text-lg font-medium text-foreground">
                  {source.last_sync_at
                    ? formatUTC(new Date(source.last_sync_at))
                    : 'Never'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Configuration */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Globe className="w-5 h-5 text-primary" />
              </div>
              <CardTitle className="text-lg text-foreground">Configuration</CardTitle>
            </div>
            <div className="flex items-center gap-3">
              <Badge className={
                source.last_sync_status === 'success'
                  ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20'
                  : source.last_sync_status === 'failed'
                  ? 'bg-red-500/10 text-red-400 border-red-500/20'
                  : source.last_sync_status === 'in_progress'
                  ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                  : 'bg-gray-500/10 text-muted-foreground border-gray-500/20'
              }>
                {source.last_sync_status === 'success' && <CircleCheck className="w-3 h-3 mr-1" />}
                {source.last_sync_status === 'failed' && <XCircle className="w-3 h-3 mr-1" />}
                {source.last_sync_status === 'in_progress' && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                {source.last_sync_status || 'Not synced'}
              </Badge>
              {canConfigure && (
                <div className="flex items-center gap-2">
                  <Switch
                    checked={source.enabled}
                    onCheckedChange={handleToggleClick}
                  />
                  <Label className="text-sm text-muted-foreground">Enabled</Label>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="p-4 bg-muted/50 rounded-xl space-y-4">
            {canConfigure ? (
              <div>
                <Label className="text-sm text-muted-foreground mb-2 block">Download URL</Label>
                <div className="flex gap-2">
                  <Input
                    value={ipinfoUrl}
                    onChange={(e) => {
                      setIpinfoUrl(e.target.value);
                      setPendingUrlChange(e.target.value !== (source.download_url || ''));
                    }}
                    placeholder="https://ipinfo.io/data/ipinfo_lite.csv.gz?token=YOUR_TOKEN"
                    className="flex-1 border-border text-foreground rounded-xl"
                  />
                  <Button
                    onClick={handleConfigureClick}
                    disabled={configuring || !ipinfoUrl.trim() || !pendingUrlChange}
                    className="bg-primary hover:bg-primary/90 text-foreground rounded-xl"
                  >
                    {configuring ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <>
                        <Save className="w-4 h-4" />
                        Save
                      </>
                    )}
                  </Button>
                </div>
                {pendingUrlChange && (
                  <p className="text-xs text-amber-400 mt-1 flex items-center gap-1">
                    <CircleAlert className="w-3 h-3" />
                    You have unsaved changes. Click Save to apply.
                  </p>
                )}
                <p className="text-xs text-muted-foreground mt-2">
                  Get your free token at{' '}
                  <a href="https://ipinfo.io/lite" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                    ipinfo.io/lite
                  </a>
                </p>
              </div>
            ) : (
              <div>
                <Label className="text-sm text-muted-foreground mb-2 block">Status</Label>
                <p className="text-sm text-foreground">
                  {source.download_url ? 'Configured' : 'Not configured'}
                </p>
              </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-border">
              <div className="text-sm text-muted-foreground">
                {source.record_count > 0
                  ? `${formatNumber(source.record_count)} records loaded`
                  : 'No data loaded yet'}
              </div>
              {canConfigure && (
                <Button
                  onClick={handleSyncClick}
                  disabled={syncing || !source.download_url || source.last_sync_status === 'in_progress'}
                  variant="outline"
                  className="border-border text-foreground hover:bg-accent/50 rounded-xl"
                >
                  {syncing || source.last_sync_status === 'in_progress' ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Syncing...
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-4 h-4" />
                      Sync Now
                    </>
                  )}
                </Button>
              )}
            </div>
          </div>

          {/* Info about enrichment */}
          <div className="flex items-start gap-3 p-4 bg-primary/5 border border-blue-500/10 rounded-xl">
            <CircleAlert className="w-5 h-5 text-primary mt-0.5" />
            <div className="text-sm text-foreground">
              <p className="font-medium text-foreground mb-1">How enrichment works</p>
              <p>When logs are ingested, IP addresses are automatically enriched with geolocation and ASN data.
              You can then search using fields like <code className="bg-muted/30 px-1 rounded">enriched_src_country_code = "US"</code> or <code className="bg-muted/30 px-1 rounded">enriched_src_asn = "AS15169"</code>.</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Auto-Sync Configuration - only show if user can configure */}
      {canConfigure && (
        <Card className="bg-card border-0 rounded-2xl">
          <CardHeader className="pb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/10 rounded-lg">
                <Calendar className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <CardTitle className="text-lg text-foreground">Automatic Sync</CardTitle>
                <p className="text-sm text-muted-foreground">Keep enrichment data up to date automatically</p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 bg-muted/50 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">Enable Auto-Sync</p>
                  <p className="text-xs text-muted-foreground">Automatically sync enrichment data on a schedule</p>
                </div>
                <Switch
                  checked={autoSyncConfig?.auto_sync_enabled ?? true}
                  onCheckedChange={handleAutoSyncToggle}
                  disabled={savingAutoSync}
                />
              </div>

              {(autoSyncConfig?.auto_sync_enabled ?? true) && (
                <>
                  <div className="pt-3 border-t border-border">
                    <Label className="text-sm text-muted-foreground mb-2 block">Sync Interval</Label>
                    <Select
                      value={String(autoSyncConfig?.sync_interval_hours ?? 24)}
                      onValueChange={handleIntervalChange}
                      disabled={savingAutoSync}
                    >
                      <SelectTrigger className="w-48 border-border text-foreground rounded-xl">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="6">Every 6 hours</SelectItem>
                        <SelectItem value="12">Every 12 hours</SelectItem>
                        <SelectItem value="24">Daily (24 hours)</SelectItem>
                        <SelectItem value="48">Every 2 days</SelectItem>
                        <SelectItem value="168">Weekly</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {autoSyncConfig?.next_sync_at && (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Clock className="w-4 h-4" />
                      <span>Next sync: {formatUTC(new Date(autoSyncConfig.next_sync_at))}</span>
                    </div>
                  )}
                </>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* IP Lookup Test */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader className="pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Search className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <CardTitle className="text-lg text-foreground">Test IP Lookup</CardTitle>
              <p className="text-sm text-muted-foreground">Verify enrichment data for an IP address</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              value={testIp}
              onChange={(e) => setTestIp(e.target.value)}
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              className="flex-1 bg-muted/50 border-border text-foreground rounded-xl"
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            />
            <Button
              onClick={handleLookup}
              disabled={lookingUp || !testIp.trim()}
              className="bg-ai hover:bg-ai-muted text-foreground rounded-xl"
            >
              {lookingUp ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Lookup'}
            </Button>
          </div>

          {lookupResult && (
            <div className="p-4 bg-muted/50 rounded-xl">
              {lookupResult.found ? (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase">Country</p>
                    <p className="text-sm text-foreground">{lookupResult.country || '-'}</p>
                    <p className="text-xs text-muted-foreground">{lookupResult.country_code}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase">Continent</p>
                    <p className="text-sm text-foreground">{lookupResult.continent || '-'}</p>
                    <p className="text-xs text-muted-foreground">{lookupResult.continent_code}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase">ASN</p>
                    <p className="text-sm text-foreground">{lookupResult.asn || '-'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase">Organization</p>
                    <p className="text-sm text-foreground truncate">{lookupResult.as_name || '-'}</p>
                    <p className="text-xs text-muted-foreground truncate">{lookupResult.as_domain}</p>
                  </div>
                </div>
              ) : (
                <p className="text-muted-foreground text-sm">No enrichment data found for {lookupResult.ip}</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialogs */}
      <ConfirmDialog
        open={showEnableDialog}
        onOpenChange={setShowEnableDialog}
        variant="default"
        title="Enable IP Enrichment?"
        description={
          <>
            This will enable automatic IP enrichment for all incoming logs. IP addresses will be
            enriched with geolocation (country, continent) and ASN information.
            <br /><br />
            Make sure you have synced the enrichment data first.
          </>
        }
        confirmLabel="Enable Enrichment"
        onConfirm={handleEnableConfirm}
      />

      <ConfirmDialog
        open={showDisableDialog}
        onOpenChange={setShowDisableDialog}
        variant="danger"
        title="Disable IP Enrichment?"
        description={
          <>
            This will disable IP enrichment. New logs will no longer be enriched with geolocation
            and ASN data.
            <br /><br />
            Existing enriched logs will not be affected.
          </>
        }
        confirmLabel="Disable Enrichment"
        onConfirm={handleDisableConfirm}
      />

      <ConfirmDialog
        open={showConfigureDialog}
        onOpenChange={setShowConfigureDialog}
        variant="default"
        title="Save Configuration?"
        description={
          <>
            This will save the IPinfo download URL. After saving, you'll need to click "Sync Now" to
            download and load the enrichment data.
            <br /><br />
            <span className="text-amber-400">Make sure your token is correct before saving.</span>
          </>
        }
        confirmLabel="Save Configuration"
        onConfirm={handleConfigureConfirm}
      />

      <ConfirmDialog
        open={showSyncDialog}
        onOpenChange={setShowSyncDialog}
        variant="default"
        title="Sync Enrichment Data?"
        description={
          <>
            This will download the IPinfo database and load it into nano. This process may take
            30-60 seconds depending on your connection speed.
            <br /><br />
            {source.record_count > 0 ? (
              <span className="text-amber-400">
                This will replace the existing {formatNumber(source.record_count)} records with
                fresh data.
              </span>
            ) : (
              <span className="text-muted-foreground">
                This is the initial data load.
              </span>
            )}
          </>
        }
        confirmLabel="Start Sync"
        onConfirm={handleSyncConfirm}
      />
    </>
  );
}
