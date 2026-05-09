// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VirusTotal Provider Configuration Component
 *
 * Handles configuration of VirusTotal as an agent enrichment provider
 * for AI-powered alert triage.
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
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
  Loader2,
  CircleCheck,
  XCircle,
  Key,
  Eye,
  EyeOff,
  RefreshCw,
  Save,
  CircleAlert,
  Trash2,
  ExternalLink,
} from 'lucide-react';
import { SiVirustotal } from '@icons-pack/react-simple-icons';
import { AgentEnrichmentProvider, ProviderType } from '@/lib/api';
import {
  useCreateAgentEnrichmentProvider,
  useUpdateAgentEnrichmentProvider,
  useUpdateAgentEnrichmentCredentials,
  useTestAgentEnrichmentConnection,
  useDeleteAgentEnrichmentProvider,
} from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import { NumberInput } from '@/components/ui/number-input';
import { useNavigate } from 'react-router-dom';

interface VirusTotalProviderProps {
  provider: AgentEnrichmentProvider | null;
  providerType: ProviderType;
  onRefresh: () => void;
}

export function VirusTotalProvider({ provider, providerType, onRefresh }: VirusTotalProviderProps) {
  const { toast } = useToast();
  const navigate = useNavigate();
  const isNew = !provider;

  // Form state
  const [name, setName] = useState(provider?.name || 'VirusTotal');
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  const [apiKey, setApiKey] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [rateLimitPerMinute, setRateLimitPerMinute] = useState(provider?.rate_limit_per_minute || 4);
  const [rateLimitPerDay, setRateLimitPerDay] = useState(provider?.rate_limit_per_day || 500);
  const [pendingChanges, setPendingChanges] = useState(false);

  // Test result state
  const [testResult, setTestResult] = useState<{ success: boolean; error?: string; responseTime?: number } | null>(null);

  // Confirmation dialogs
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  // Mutations
  const { mutate: createProvider, loading: creating } = useCreateAgentEnrichmentProvider();
  const { mutate: updateProvider, loading: updating } = useUpdateAgentEnrichmentProvider();
  const { mutate: updateCredentials, loading: updatingCreds } = useUpdateAgentEnrichmentCredentials();
  const { mutate: testConnection, loading: testing } = useTestAgentEnrichmentConnection();
  const { mutate: deleteProvider, loading: deleting } = useDeleteAgentEnrichmentProvider();

  // Load provider data
  useEffect(() => {
    if (provider) {
      setName(provider.name);
      setEnabled(provider.enabled);
      setRateLimitPerMinute(provider.rate_limit_per_minute);
      setRateLimitPerDay(provider.rate_limit_per_day);
    }
    setPendingChanges(false);
  }, [provider]);

  const handleSave = async () => {
    setShowSaveDialog(false);
    try {
      if (isNew) {
        await createProvider({
          id: providerType,
          name,
          provider_type: providerType,
          enabled,
          api_key: apiKey || undefined,
          rate_limit_per_minute: rateLimitPerMinute,
          rate_limit_per_day: rateLimitPerDay,
        });
        toast({ title: 'Provider Created', description: 'VirusTotal has been configured.' });
      } else {
        await updateProvider({
          providerId: provider!.id,
          data: { name, enabled, rate_limit_per_minute: rateLimitPerMinute, rate_limit_per_day: rateLimitPerDay },
        });
        if (apiKey) {
          await updateCredentials({ providerId: provider!.id, apiKey });
        }
        toast({ title: 'Settings Saved', description: 'VirusTotal settings have been updated.' });
      }
      setPendingChanges(false);
      onRefresh();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save provider',
        variant: 'destructive',
      });
    }
  };

  const handleTestConnection = async () => {
    if (!provider?.id) {
      toast({ title: 'Save First', description: 'Please save the provider before testing.', variant: 'destructive' });
      return;
    }
    try {
      setTestResult(null);
      const result = await testConnection(provider.id);
      setTestResult({
        success: result.success,
        error: result.error,
        responseTime: result.response_time_ms,
      });
    } catch (err) {
      setTestResult({
        success: false,
        error: err instanceof Error ? err.message : 'Connection test failed',
      });
    }
  };

  const handleDelete = async () => {
    if (!provider) return;
    setShowDeleteDialog(false);
    try {
      await deleteProvider(provider.id);
      toast({ title: 'Provider Deleted', description: 'VirusTotal has been removed.' });
      navigate('/enrichments?tab=agent');
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete provider',
        variant: 'destructive',
      });
    }
  };

  const loading = creating || updating || updatingCreds;
  const usagePercent = provider ? (provider.requests_today / provider.rate_limit_per_day) * 100 : 0;

  const getStatusBadge = () => {
    if (!provider) {
      return <Badge className="bg-gray-500/10 text-muted-foreground border-gray-500/20">Not Configured</Badge>;
    }
    if (!provider.has_api_key) {
      return <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20">No API Key</Badge>;
    }
    if (!provider.enabled) {
      return <Badge className="bg-gray-500/10 text-muted-foreground border-gray-500/20">Disabled</Badge>;
    }
    if (provider.last_error) {
      return (
        <Badge className="bg-red-500/10 text-red-400 border-red-500/20">
          <XCircle className="w-3 h-3 mr-1" />
          Error
        </Badge>
      );
    }
    return (
      <Badge className="bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20">
        <CircleCheck className="w-3 h-3 mr-1" />
        Active
      </Badge>
    );
  };

  return (
    <>
      {/* Stats */}
      {provider && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-red-500/10 rounded-xl">
                  <SiVirustotal className="w-6 h-6" color="#394EFF" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  <div className="mt-1">{getStatusBadge()}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-blue-500/10 rounded-xl">
                  <RefreshCw className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Today's Requests</p>
                  <p className="text-2xl font-bold text-foreground">{provider.requests_today}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-purple-500/10 rounded-xl">
                  <Key className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Daily Limit</p>
                  <p className="text-2xl font-bold text-foreground">{provider.rate_limit_per_day}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Usage</p>
                <Progress value={usagePercent} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  {provider.requests_today} / {provider.rate_limit_per_day} requests
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Configuration */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/10 rounded-lg">
                <SiVirustotal className="w-5 h-5" color="#394EFF" />
              </div>
              <CardTitle className="text-lg text-foreground">Configuration</CardTitle>
            </div>
            <div className="flex items-center gap-3">
              {getStatusBadge()}
              {provider && (
                <div className="flex items-center gap-2">
                  <Switch
                    checked={enabled}
                    onCheckedChange={(val) => {
                      setEnabled(val);
                      setPendingChanges(true);
                    }}
                  />
                  <Label className="text-sm text-muted-foreground">Enabled</Label>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="p-4 bg-muted/50 rounded-xl space-y-4">
            {/* Name */}
            <div>
              <Label className="text-sm text-muted-foreground mb-2 block">Display Name</Label>
              <Input
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setPendingChanges(true);
                }}
                placeholder="VirusTotal"
                className="border-border text-foreground rounded-xl"
              />
            </div>

            {/* API Key */}
            <div>
              <Label className="text-sm text-muted-foreground mb-2 block flex items-center gap-2">
                <Key className="w-4 h-4" />
                API Key
                {provider?.has_api_key && (
                  <Badge variant="outline" className="text-xs">Configured</Badge>
                )}
              </Label>
              <div className="relative">
                <Input
                  type={showApiKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={(e) => {
                    setApiKey(e.target.value);
                    setPendingChanges(true);
                  }}
                  placeholder={provider?.has_api_key ? '••••••••••••••••' : 'Enter API key'}
                  className="border-border text-foreground rounded-xl pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Get your API key from{' '}
                <a
                  href="https://developers.virustotal.com/reference/overview"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center gap-1"
                >
                  VirusTotal documentation
                  <ExternalLink className="w-3 h-3" />
                </a>
              </p>
            </div>

            {/* Rate Limits */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-sm text-muted-foreground mb-2 block">Requests/Minute</Label>
                <NumberInput
                  min={1}
                  max={1000}
                  value={rateLimitPerMinute}
                  onChange={(val) => {
                    setRateLimitPerMinute(val);
                    setPendingChanges(true);
                  }}
                />
                <p className="text-xs text-muted-foreground mt-1">Free tier: 4/min</p>
              </div>
              <div>
                <Label className="text-sm text-muted-foreground mb-2 block">Requests/Day</Label>
                <NumberInput
                  min={1}
                  max={100000}
                  value={rateLimitPerDay}
                  onChange={(val) => {
                    setRateLimitPerDay(val);
                    setPendingChanges(true);
                  }}
                />
                <p className="text-xs text-muted-foreground mt-1">Free tier: 500/day</p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-border">
              <div className="flex items-center gap-4">
                {pendingChanges && (
                  <p className="text-xs text-amber-400 flex items-center gap-1">
                    <CircleAlert className="w-3 h-3" />
                    Unsaved changes
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                {provider && (
                  <Button
                    variant="outline"
                    onClick={() => setShowDeleteDialog(true)}
                    className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete
                  </Button>
                )}
                <Button
                  onClick={() => setShowSaveDialog(true)}
                  disabled={loading || !name}
                  className="bg-primary hover:bg-primary/90 text-foreground rounded-xl"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      <Save className="w-4 h-4 mr-2" />
                      {isNew ? 'Create' : 'Save'}
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Connection Test */}
      {provider && (
        <Card className="bg-card border-0 rounded-2xl">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <RefreshCw className="w-5 h-5 text-blue-400" />
                </div>
                <CardTitle className="text-lg text-foreground">Connection Test</CardTitle>
              </div>
              <Button
                variant="outline"
                onClick={handleTestConnection}
                disabled={testing || !provider?.has_api_key}
                className="border-border text-foreground hover:bg-accent/50 rounded-xl"
              >
                {testing ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <RefreshCw className="w-4 h-4 mr-2" />
                )}
                Test Connection
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {!provider.has_api_key ? (
              <p className="text-sm text-muted-foreground">Configure an API key to test the connection.</p>
            ) : testResult ? (
              <div className={`p-4 rounded-xl ${testResult.success ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                <div className="flex items-center gap-2">
                  {testResult.success ? (
                    <CircleCheck className="w-5 h-5 text-green-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <span className={`font-medium ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                    {testResult.success ? 'Connection successful' : 'Connection failed'}
                  </span>
                </div>
                {testResult.responseTime && (
                  <p className="text-sm text-muted-foreground mt-2">
                    Response time: {testResult.responseTime}ms
                  </p>
                )}
                {testResult.error && (
                  <p className="text-sm text-red-400 mt-2">{testResult.error}</p>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Click "Test Connection" to verify your API key.</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Save Confirmation */}
      <AlertDialog open={showSaveDialog} onOpenChange={setShowSaveDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              {isNew ? 'Create Provider?' : 'Save Changes?'}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              {isNew
                ? 'This will configure VirusTotal as an agent enrichment provider for AI-powered alert triage.'
                : 'This will update the VirusTotal configuration.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleSave}
              className="bg-primary hover:bg-primary/90 text-foreground"
            >
              {isNew ? 'Create' : 'Save'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Confirmation */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Delete Provider?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              Are you sure you want to delete VirusTotal? This will also clear all cached enrichment results.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-red-600 hover:bg-red-700 text-foreground"
              disabled={deleting}
            >
              {deleting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
