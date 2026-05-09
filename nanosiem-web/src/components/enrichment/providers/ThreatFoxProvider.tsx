// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ThreatFox Provider Configuration Component
 *
 * Handles configuration and management of ThreatFox IOC enrichment source.
 * Provides threat intelligence data for IP addresses, domains, and file hashes.
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Shield,
  RefreshCw,
  Loader2,
  CircleCheck,
  XCircle,
  Database,
  Search,
  Clock,
  CircleAlert,
  Save,
  Globe,
  Hash,
  Server,
} from 'lucide-react';
import { api, EnrichmentSource, IocLookupResult, IocStats } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatUTC, formatNumber } from '@/lib/date-utils';
import { useAuth } from '@/contexts/AuthContext';

interface ThreatFoxProviderProps {
  source: EnrichmentSource;
  onRefresh: () => void;
}

export function ThreatFoxProvider({ source, onRefresh }: ThreatFoxProviderProps) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canConfigure = hasPermission('enrichments:configure');

  // Configuration state
  const [apiKey, setApiKey] = useState('');
  const [ttlDays, setTtlDays] = useState('7');
  const [syncIntervalHours, setSyncIntervalHours] = useState('6');
  const [configuring, setConfiguring] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);

  // IOC Lookup test
  const [testIoc, setTestIoc] = useState('');
  const [lookupResult, setLookupResult] = useState<IocLookupResult | null>(null);
  const [lookingUp, setLookingUp] = useState(false);

  // IOC Stats
  const [iocStats, setIocStats] = useState<IocStats | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);

  // Confirmation dialogs
  const [showEnableDialog, setShowEnableDialog] = useState(false);
  const [showDisableDialog, setShowDisableDialog] = useState(false);
  const [showConfigureDialog, setShowConfigureDialog] = useState(false);
  const [showSyncDialog, setShowSyncDialog] = useState(false);

  // Load stats on mount
  useEffect(() => {
    const loadStats = async () => {
      try {
        setLoadingStats(true);
        const stats = await api.getIocStats(source.id);
        setIocStats(stats);
      } catch {
        // Stats may not be available yet
      } finally {
        setLoadingStats(false);
      }
    };
    loadStats();
  }, [source.id]);

  // Load config from source
  useEffect(() => {
    const config = source.config || {};
    setTtlDays(String(config.ttl_days ?? 7));
    setSyncIntervalHours(String(config.sync_interval_hours ?? 6));
    // If API key is masked (meaning one exists), show placeholder
    if (config.api_key === '••••••••') {
      setApiKey('••••••••');
    } else {
      setApiKey('');
    }
    setPendingChanges(false);
  }, [source.config]);

  const handleConfigureClick = () => {
    setShowConfigureDialog(true);
  };

  const handleConfigureConfirm = async () => {
    setShowConfigureDialog(false);
    try {
      setConfiguring(true);
      // Don't send API key if it's still the masked placeholder (means user didn't change it)
      const keyToSend = apiKey === '••••••••' ? undefined : (apiKey || undefined);
      await api.configureThreatFox({
        api_key: keyToSend,
        ttl_days: parseInt(ttlDays),
        sync_interval_hours: parseInt(syncIntervalHours),
      });
      setPendingChanges(false);
      toast({
        title: 'Configuration Saved',
        description: 'ThreatFox settings have been saved. Click "Sync Now" to fetch IOCs.',
      });
      onRefresh();
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to configure ThreatFox',
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
      const result = await api.syncThreatFox();

      if (!result.started) {
        // Sync already in progress (409)
        toast({
          title: 'Sync Already Running',
          description: 'A sync is already in progress. The status will update when it completes.',
        });
      } else {
        toast({
          title: 'Sync Started',
          description: 'Fetching IOCs from ThreatFox. This may take a few minutes...',
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
            // Sync complete - refresh stats and show result
            try {
              const stats = await api.getIocStats(source.id);
              setIocStats(stats);
            } catch {
              // Ignore stats error
            }
            onRefresh();

            if (updatedSource.last_sync_status === 'success') {
              toast({
                title: 'Sync Complete',
                description: `Successfully loaded ${formatNumber(updatedSource.record_count)} IOCs`,
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
      const message = err instanceof Error ? err.message : 'Failed to sync ThreatFox data';
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
        description: 'IOC enrichment is now active. Logs will be matched against threat intelligence.',
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
        description: 'IOC enrichment has been disabled. New logs will not be matched.',
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
    if (!testIoc.trim()) return;

    try {
      setLookingUp(true);
      const result = await api.lookupIoc(testIoc.trim());
      setLookupResult(result);
    } catch {
      toast({
        title: 'Lookup Failed',
        description: 'Failed to lookup IOC',
        variant: 'destructive',
      });
    } finally {
      setLookingUp(false);
    }
  };

  const totalIocs = iocStats
    ? (iocStats.ip_count ?? 0) + (iocStats.domain_count ?? 0) + (iocStats.md5_count ?? 0) + (iocStats.sha256_count ?? 0)
    : source.record_count;

  return (
    <>
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-primary/10 rounded-xl">
                <Database className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total IOCs</p>
                <p className="text-2xl font-bold text-foreground">
                  {loadingStats ? '...' : formatNumber(totalIocs)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-red-500/10 rounded-xl">
                <Server className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">IPs</p>
                <p className="text-2xl font-bold text-foreground">
                  {loadingStats ? '...' : formatNumber(iocStats?.ip_count ?? 0)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-blue-500/10 rounded-xl">
                <Globe className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Domains</p>
                <p className="text-2xl font-bold text-foreground">
                  {loadingStats ? '...' : formatNumber(iocStats?.domain_count ?? 0)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-purple-500/10 rounded-xl">
                <Hash className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Hashes</p>
                <p className="text-2xl font-bold text-foreground">
                  {loadingStats ? '...' : formatNumber((iocStats?.md5_count ?? 0) + (iocStats?.sha256_count ?? 0))}
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
      </div>

      {/* Configuration */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-500/10 rounded-lg">
                <Shield className="w-5 h-5 text-orange-400" />
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
              <>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <Label className="text-sm text-muted-foreground mb-2 block">API Key (Optional)</Label>
                    <Input
                      type="password"
                      value={apiKey}
                      onChange={(e) => {
                        setApiKey(e.target.value);
                        setPendingChanges(true);
                      }}
                      onFocus={() => {
                        // Clear masked placeholder when user focuses to enter new key
                        if (apiKey === '••••••••') {
                          setApiKey('');
                          setPendingChanges(true);
                        }
                      }}
                      placeholder="Leave blank for anonymous access"
                      className="border-border text-foreground rounded-xl"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      {apiKey === '••••••••' ? 'API key configured' : 'Higher rate limits with API key'}
                    </p>
                  </div>

                  <div>
                    <Label className="text-sm text-muted-foreground mb-2 block">TTL (Days)</Label>
                    <Select
                      value={ttlDays}
                      onValueChange={(val) => {
                        setTtlDays(val);
                        setPendingChanges(true);
                      }}
                    >
                      <SelectTrigger className="border-border text-foreground rounded-xl">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="3">3 days</SelectItem>
                        <SelectItem value="5">5 days</SelectItem>
                        <SelectItem value="7">7 days (Recommended)</SelectItem>
                        <SelectItem value="14">14 days</SelectItem>
                        <SelectItem value="30">30 days</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground mt-1">
                      IOCs expire after this time
                    </p>
                  </div>

                  <div>
                    <Label className="text-sm text-muted-foreground mb-2 block">Sync Interval</Label>
                    <Select
                      value={syncIntervalHours}
                      onValueChange={(val) => {
                        setSyncIntervalHours(val);
                        setPendingChanges(true);
                      }}
                    >
                      <SelectTrigger className="border-border text-foreground rounded-xl">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">Every hour</SelectItem>
                        <SelectItem value="3">Every 3 hours</SelectItem>
                        <SelectItem value="6">Every 6 hours (Recommended)</SelectItem>
                        <SelectItem value="12">Every 12 hours</SelectItem>
                        <SelectItem value="24">Daily</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground mt-1">
                      Auto-sync frequency
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-border">
                  <div className="flex items-center gap-4">
                    {pendingChanges && (
                      <p className="text-xs text-amber-400 flex items-center gap-1">
                        <CircleAlert className="w-3 h-3" />
                        Unsaved changes
                      </p>
                    )}
                    {source.last_sync_at && (
                      <p className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Last sync: {formatUTC(new Date(source.last_sync_at))}
                      </p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <Button
                      onClick={handleConfigureClick}
                      disabled={configuring || !pendingChanges}
                      className="bg-primary hover:bg-primary/90 text-foreground rounded-xl"
                    >
                      {configuring ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <>
                          <Save className="w-4 h-4 mr-2" />
                          Save
                        </>
                      )}
                    </Button>
                    <Button
                      onClick={handleSyncClick}
                      disabled={syncing || source.last_sync_status === 'in_progress'}
                      variant="outline"
                      className="border-border text-foreground hover:bg-accent/50 rounded-xl"
                    >
                      {syncing || source.last_sync_status === 'in_progress' ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Syncing...
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2" />
                          Sync Now
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-sm text-muted-foreground mb-1 block">Status</Label>
                  <p className="text-sm text-foreground">{source.enabled ? 'Enabled' : 'Disabled'}</p>
                </div>
                {source.last_sync_at && (
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Last sync: {formatUTC(new Date(source.last_sync_at))}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Info about enrichment */}
          <div className="flex items-start gap-3 p-4 bg-orange-500/5 border border-orange-500/10 rounded-xl">
            <CircleAlert className="w-5 h-5 text-orange-400 mt-0.5" />
            <div className="text-sm text-foreground">
              <p className="font-medium text-foreground mb-1">How IOC enrichment works</p>
              <p>When logs are ingested, IPs, domains, and hashes are matched against known threat indicators.
              You can then search using fields like <code className="bg-muted/30 px-1 rounded">ioc_confidence &gt; 80</code> or <code className="bg-muted/30 px-1 rounded">ioc_dest_ip_malware != ""</code>.</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* IOC Lookup Test */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader className="pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Search className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <CardTitle className="text-lg text-foreground">Test IOC Lookup</CardTitle>
              <p className="text-sm text-muted-foreground">Check if an IP, domain, or hash is in the threat feed</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              value={testIoc}
              onChange={(e) => setTestIoc(e.target.value)}
              placeholder="Enter IP, domain, or hash (e.g., 45.1.33.4, evil.com, d41d8cd9...)"
              className="flex-1"
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            />
            <Button
              onClick={handleLookup}
              disabled={lookingUp || !testIoc.trim()}
              className="bg-ai hover:bg-ai-muted text-foreground rounded-xl"
            >
              {lookingUp ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Lookup'}
            </Button>
          </div>

          {lookupResult && (
            <div className="p-4 bg-muted/50 rounded-xl">
              {lookupResult.found ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Badge className="bg-red-500/10 text-red-400 border-red-500/20">
                      Threat Found
                    </Badge>
                    <span className="text-sm text-foreground font-mono">{lookupResult.ioc_value}</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Type</p>
                      <p className="text-sm text-foreground">{lookupResult.ioc_type || '-'}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Confidence</p>
                      <p className="text-sm text-foreground">{lookupResult.confidence_level ?? '-'}%</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Threat Type</p>
                      <p className="text-sm text-foreground">{lookupResult.threat_type || '-'}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Malware</p>
                      <p className="text-sm text-foreground">{lookupResult.malware || '-'}</p>
                    </div>
                  </div>
                  {lookupResult.tags && lookupResult.tags.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground uppercase mb-1">Tags</p>
                      <div className="flex flex-wrap gap-1">
                        {lookupResult.tags.map((tag, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <CircleCheck className="w-4 h-4 text-green-400" />
                  <p className="text-muted-foreground text-sm">No threat data found for {lookupResult.ioc_value}</p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialogs */}
      <AlertDialog open={showEnableDialog} onOpenChange={setShowEnableDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Enable IOC Enrichment?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will enable automatic IOC matching for all incoming logs. IPs, domains, and hashes will be checked against known threat indicators.
              <br /><br />
              Make sure you have synced the threat data first.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleEnableConfirm}
              className=""
            >
              Enable Enrichment
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showDisableDialog} onOpenChange={setShowDisableDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Disable IOC Enrichment?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will disable IOC matching. New logs will no longer be checked against threat intelligence.
              <br /><br />
              Existing enriched logs will not be affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDisableConfirm}
              className="bg-red-600 hover:bg-red-700 text-foreground"
            >
              Disable Enrichment
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showConfigureDialog} onOpenChange={setShowConfigureDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Save Configuration?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will save the ThreatFox configuration including TTL and sync interval settings.
              <br /><br />
              <span className="text-amber-400">After saving, click "Sync Now" to fetch IOCs.</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfigureConfirm}
              className="bg-primary hover:bg-primary/90 text-foreground"
            >
              Save Configuration
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Sync Threat Data?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will fetch the latest IOCs from ThreatFox and load them into the database. The sync typically takes 10-30 seconds.
              <br /><br />
              {totalIocs > 0 ? (
                <span className="text-amber-400">
                  This will refresh the existing {formatNumber(totalIocs)} IOCs with fresh data.
                </span>
              ) : (
                <span className="text-muted-foreground">
                  This is the initial data load.
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleSyncConfirm}
              className="bg-ai hover:bg-ai-muted text-foreground"
            >
              Start Sync
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
