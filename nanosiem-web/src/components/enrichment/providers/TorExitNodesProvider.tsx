// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * TOR Exit Nodes Provider Configuration Component
 *
 * Handles configuration and management of TOR Exit Nodes IOC enrichment source.
 * Uses the official Tor Project Onionoo API to fetch exit node IP addresses.
 * Useful for detecting anonymized traffic patterns in enterprise networks.
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
  RefreshCw,
  Loader2,
  CircleCheck,
  XCircle,
  Database,
  Clock,
  CircleAlert,
  Save,
  Server,
  Eye,
} from 'lucide-react';
import { api, EnrichmentSource, IocStats } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatUTC, formatNumber } from '@/lib/date-utils';
import { useAuth } from '@/contexts/AuthContext';

interface TorExitNodesProviderProps {
  source: EnrichmentSource;
  onRefresh: () => void;
}

export function TorExitNodesProvider({ source, onRefresh }: TorExitNodesProviderProps) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canConfigure = hasPermission('enrichments:configure');

  // Configuration state
  const [ttlDays, setTtlDays] = useState('1');
  const [syncIntervalHours, setSyncIntervalHours] = useState('6');
  const [confidenceLevel, setConfidenceLevel] = useState('100');
  const [configuring, setConfiguring] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);

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
    setTtlDays(String(config.ttl_days ?? 1));
    setSyncIntervalHours(String(config.sync_interval_hours ?? 6));
    setConfidenceLevel(String(config.confidence_level ?? 100));
    setPendingChanges(false);
  }, [source.config]);

  const handleConfigureClick = () => {
    setShowConfigureDialog(true);
  };

  const handleConfigureConfirm = async () => {
    setShowConfigureDialog(false);
    try {
      setConfiguring(true);
      await api.configureTorExitNodes({
        ttl_days: parseInt(ttlDays),
        sync_interval_hours: parseInt(syncIntervalHours),
        confidence_level: parseInt(confidenceLevel),
      });
      setPendingChanges(false);
      toast({
        title: 'Configuration Saved',
        description: 'TOR Exit Nodes settings have been saved. Click "Sync Now" to fetch data.',
      });
      onRefresh();
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to configure TOR Exit Nodes',
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
      const result = await api.syncTorExitNodes();

      if (!result.started) {
        // Sync already in progress (409)
        toast({
          title: 'Sync Already Running',
          description: 'A sync is already in progress. The status will update when it completes.',
        });
      } else {
        toast({
          title: 'Sync Started',
          description: 'Fetching TOR exit nodes from Onionoo API. This may take a few minutes...',
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
                description: `Successfully loaded ${formatNumber(updatedSource.record_count)} TOR exit node IPs`,
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
      const message = err instanceof Error ? err.message : 'Failed to sync TOR exit nodes';
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
        description: 'TOR Exit Node enrichment is now active. Logs will be matched against known exit nodes.',
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
        description: 'TOR Exit Node enrichment has been disabled. New logs will not be matched.',
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

  const totalIocs = iocStats?.ip_count ?? source.record_count;

  return (
    <>
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-primary/10 rounded-xl">
                <Database className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Exit Nodes</p>
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
              <div className="p-3 bg-purple-500/10 rounded-xl">
                <Server className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Type</p>
                <p className="text-2xl font-bold text-foreground">IP</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-amber-500/10 rounded-xl">
                <Eye className="w-6 h-6 text-amber-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Confidence</p>
                <p className="text-2xl font-bold text-foreground">{confidenceLevel}%</p>
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
              <div className="p-2 bg-purple-500/10 rounded-lg">
                <Eye className="w-5 h-5 text-purple-400" />
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
                        <SelectItem value="1">1 day (Recommended)</SelectItem>
                        <SelectItem value="2">2 days</SelectItem>
                        <SelectItem value="3">3 days</SelectItem>
                        <SelectItem value="7">7 days</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground mt-1">
                      Exit node IPs expire after this time
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

                  <div>
                    <Label className="text-sm text-muted-foreground mb-2 block">Confidence Level</Label>
                    <Select
                      value={confidenceLevel}
                      onValueChange={(val) => {
                        setConfidenceLevel(val);
                        setPendingChanges(true);
                      }}
                    >
                      <SelectTrigger className="border-border text-foreground rounded-xl">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="70">70%</SelectItem>
                        <SelectItem value="80">80%</SelectItem>
                        <SelectItem value="85">85% (Recommended)</SelectItem>
                        <SelectItem value="90">90%</SelectItem>
                        <SelectItem value="95">95%</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground mt-1">
                      IOC confidence for matches
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

          {/* Info about TOR enrichment */}
          <div className="flex items-start gap-3 p-4 bg-purple-500/5 border border-purple-500/10 rounded-xl">
            <CircleAlert className="w-5 h-5 text-purple-400 mt-0.5" />
            <div className="text-sm text-foreground">
              <p className="font-medium text-foreground mb-1">How TOR exit node enrichment works</p>
              <p>When logs are ingested, source and destination IPs are matched against the official TOR exit node list from the Tor Project.
              You can search for TOR traffic using fields like <code className="bg-muted/30 px-1 rounded">ioc_threat_type = "anonymizer"</code> or <code className="bg-muted/30 px-1 rounded">tags CONTAINS "tor_exit"</code>.</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Confirmation Dialogs */}
      <AlertDialog open={showEnableDialog} onOpenChange={setShowEnableDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Enable TOR Exit Node Enrichment?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will enable automatic TOR exit node enrichment for all incoming logs. Source and destination IPs will be checked against known TOR exit nodes.
              <br /><br />
              Make sure you have synced the exit node data first.
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
            <AlertDialogTitle className="text-foreground">Disable TOR Exit Node Detection?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will disable TOR exit node enrichment. New logs will no longer be checked against TOR exit nodes.
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
              Disable Detection
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showConfigureDialog} onOpenChange={setShowConfigureDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Save Configuration?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will save the TOR Exit Nodes configuration including TTL, sync interval, and confidence level settings.
              <br /><br />
              <span className="text-amber-400">After saving, click "Sync Now" to fetch exit node data.</span>
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
            <AlertDialogTitle className="text-foreground">Sync TOR Exit Nodes?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will fetch the latest TOR exit node IPs from the official Tor Project Onionoo API. The sync typically takes 10-30 seconds.
              <br /><br />
              {totalIocs > 0 ? (
                <span className="text-amber-400">
                  This will refresh the existing {formatNumber(totalIocs)} exit node IPs with fresh data.
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
