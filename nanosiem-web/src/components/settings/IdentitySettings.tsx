// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetFooter,
} from '@/components/ui/sheet';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Users,
  CircleCheck,
  XCircle,
  Clock,
  Loader2,
  RefreshCw,
  Plug,
  Trash2,
  Search,
  Shield,
  Building2,
  Server,
  KeyRound,
  Briefcase,
  Wand2,
  Download,
} from 'lucide-react';
import { api } from '@/lib/api';
import type {
  IdentityProviderSummary,
  IdentityProviderType,
  IdentityUser,
  IdentityStats,
} from '@/lib/api/types';
import { useToast } from '@/hooks/use-toast';
import { formatUTCCompact } from '@/lib/date-utils';

// =============================================================================
// Provider metadata
// =============================================================================

const PROVIDER_METADATA: Record<
  IdentityProviderType,
  {
    name: string;
    description: string;
    icon: React.ReactNode;
    iconBg: string;
    setupSteps: string[];
    credentialFields: { key: string; label: string; type: 'text' | 'password' | 'textarea' }[];
  }
> = {
  entra_id: {
    name: 'Microsoft Entra ID',
    description: 'Azure AD / Entra ID via Microsoft Graph API',
    icon: <Shield className="w-6 h-6 text-blue-500" />,
    iconBg: 'bg-blue-500/10',
    setupSteps: [
      'Register an App in Azure AD > App registrations',
      'Add API permission: Microsoft Graph > User.Read.All (Application)',
      'Grant admin consent for the permission',
      'Create a client secret under Certificates & secrets',
      'Copy the Tenant ID, Application (client) ID, and secret value below',
    ],
    credentialFields: [
      { key: 'tenant_id', label: 'Tenant ID', type: 'text' },
      { key: 'client_id', label: 'Client ID', type: 'text' },
      { key: 'client_secret', label: 'Client Secret', type: 'password' },
    ],
  },
  google_workspace: {
    name: 'Google Workspace',
    description: 'Google Admin SDK Directory API',
    icon: <Building2 className="w-6 h-6 text-green-500" />,
    iconBg: 'bg-green-500/10',
    setupSteps: [
      'Create a service account in Google Cloud Console > IAM',
      'Enable domain-wide delegation on the service account',
      'In Google Workspace Admin, authorize the client ID with scope: https://www.googleapis.com/auth/admin.directory.user.readonly',
      'Download the service account JSON key and paste it below',
      'Enter the admin email that the service account will impersonate',
    ],
    credentialFields: [
      { key: 'service_account_json', label: 'Service Account JSON', type: 'textarea' },
      { key: 'admin_email', label: 'Admin Email (for delegation)', type: 'text' },
      { key: 'domain', label: 'Domain', type: 'text' },
    ],
  },
  okta: {
    name: 'Okta',
    description: 'Okta Users API with SSWS token authentication',
    icon: <KeyRound className="w-6 h-6 text-indigo-500" />,
    iconBg: 'bg-indigo-500/10',
    setupSteps: [
      'In Okta Admin Console, go to Security > API > Tokens',
      'Create a new API token (requires Super Admin or Org Admin role)',
      'Copy the token immediately — it is only shown once',
      'Enter your Okta org domain (e.g. dev-12345.okta.com) and the token below',
    ],
    credentialFields: [
      { key: 'domain', label: 'Okta Domain (e.g. dev-12345.okta.com)', type: 'text' },
      { key: 'api_token', label: 'API Token (SSWS)', type: 'password' },
    ],
  },
  workday: {
    name: 'Workday',
    description: 'Workday RaaS (Report as a Service) worker directory',
    icon: <Briefcase className="w-6 h-6 text-amber-500" />,
    iconBg: 'bg-amber-500/10',
    setupSteps: [
      'Create a custom report in Workday with worker fields (Worker_ID, Email, Display_Name, Department, etc.)',
      'Publish the report as a web service (Advanced > Web Service > Enable)',
      'Create an Integration System User (ISU) with report access',
      'Copy the published RaaS JSON URL and enter it with the ISU credentials below',
    ],
    credentialFields: [
      { key: 'report_url', label: 'RaaS Report URL', type: 'text' },
      { key: 'username', label: 'ISU Username', type: 'text' },
      { key: 'password', label: 'ISU Password', type: 'password' },
    ],
  },
  active_directory: {
    name: 'Active Directory',
    description: 'On-premises AD via push-based collector',
    icon: <Server className="w-6 h-6 text-orange-500" />,
    iconBg: 'bg-orange-500/10',
    setupSteps: [
      'Generate a collector token below (or enter your own)',
      'Download the PowerShell collector script from the card below',
      'Run the script on a domain-joined server with AD module installed',
      'Schedule it via Task Scheduler to sync periodically (e.g. every 6 hours)',
    ],
    credentialFields: [
      { key: 'collector_token', label: 'Collector Token', type: 'text' },
    ],
  },
};

// =============================================================================
// Main component
// =============================================================================

export function IdentitySettings() {
  const { toast } = useToast();
  const [providers, setProviders] = useState<IdentityProviderSummary[]>([]);
  const [stats, setStats] = useState<IdentityStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [configDialog, setConfigDialog] = useState<IdentityProviderType | null>(null);
  const [editingProvider, setEditingProvider] = useState<IdentityProviderSummary | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [users, setUsers] = useState<IdentityUser[]>([]);
  const [usersTotal, setUsersTotal] = useState(0);
  const [usersPage, setUsersPage] = useState(1);
  const [usersLoading, setUsersLoading] = useState(false);

  const fetchProviders = useCallback(async () => {
    try {
      const resp = await api.listIdentityProviders();
      setProviders(resp.providers);
    } catch {
      toast({ title: 'Error', description: 'Failed to load identity providers', variant: 'destructive' });
    }
  }, [toast]);

  const fetchStats = useCallback(async () => {
    try {
      const s = await api.getIdentityStats();
      setStats(s);
    } catch { /* stats are optional */ }
  }, []);

  const fetchUsers = useCallback(async (page = 1, search = '') => {
    setUsersLoading(true);
    try {
      const resp = await api.listIdentityUsers({ page, page_size: 20, search: search || undefined });
      setUsers(resp.users);
      setUsersTotal(resp.total);
      setUsersPage(resp.page);
    } catch { /* silent */ }
    setUsersLoading(false);
  }, []);

  useEffect(() => {
    Promise.all([fetchProviders(), fetchStats(), fetchUsers()])
      .finally(() => setLoading(false));
  }, [fetchProviders, fetchStats, fetchUsers]);

  const getStatusBadge = (provider: IdentityProviderSummary) => {
    if (!provider.has_credentials) {
      return <Badge variant="outline" className="text-muted-foreground">Not Configured</Badge>;
    }
    if (!provider.enabled) {
      return <Badge variant="outline" className="text-muted-foreground">Disabled</Badge>;
    }
    if (provider.sync_status === 'completed') {
      return (
        <Badge className="bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20">
          <CircleCheck className="w-3 h-3 mr-1" /> Connected
        </Badge>
      );
    }
    if (provider.sync_status === 'failed') {
      return (
        <Badge className="bg-red-500/10 text-red-400 border-red-500/20">
          <XCircle className="w-3 h-3 mr-1" /> Sync Failed
        </Badge>
      );
    }
    if (provider.sync_status === 'in_progress') {
      return (
        <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/20">
          <Loader2 className="w-3 h-3 mr-1 animate-spin" /> Syncing
        </Badge>
      );
    }
    return (
      <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
        <Clock className="w-3 h-3 mr-1" /> Not Synced
      </Badge>
    );
  };

  const handleOpenConfig = (type: IdentityProviderType, existing?: IdentityProviderSummary) => {
    setConfigDialog(type);
    setEditingProvider(existing || null);
    setCredentials({});
  };

  const handleSave = async () => {
    if (!configDialog) return;
    setSaving(true);
    const meta = PROVIDER_METADATA[configDialog];

    try {
      let providerId = editingProvider?.id;

      if (!editingProvider) {
        // Create new provider
        const result = await api.createIdentityProvider({
          id: configDialog,
          name: meta.name,
          provider_type: configDialog,
          enabled: true,
        });
        providerId = result.id;
      }

      // Update credentials if any were entered
      const hasCredentials = Object.values(credentials).some(v => v.trim());
      if (hasCredentials && providerId) {
        await api.updateIdentityCredentials(providerId, credentials);
      }

      toast({ title: 'Success', description: `${meta.name} configured successfully` });
      setConfigDialog(null);
      await fetchProviders();
    } catch (e) {
      toast({ title: 'Error', description: `Failed to save: ${e}`, variant: 'destructive' });
    }
    setSaving(false);
  };

  const handleTestConnection = async (providerId: string) => {
    setTesting(providerId);
    try {
      const result = await api.testIdentityConnection(providerId);
      if (result.success) {
        toast({ title: 'Success', description: `Connection successful${result.user_count_sample ? ` (${result.user_count_sample} users found)` : ''}` });
      } else {
        toast({ title: 'Connection Failed', description: result.error || 'Unknown error', variant: 'destructive' });
      }
    } catch (e) {
      toast({ title: 'Error', description: `Test failed: ${e}`, variant: 'destructive' });
    }
    setTesting(null);
  };

  const handleSync = async (providerId: string) => {
    setSyncing(providerId);
    try {
      await api.triggerIdentitySync(providerId);
      toast({ title: 'Sync Started', description: 'Sync is running in the background' });
      // Refresh after a short delay to show updated status
      setTimeout(() => { fetchProviders(); fetchStats(); fetchUsers(); }, 3000);
    } catch (e) {
      toast({ title: 'Error', description: `Sync failed: ${e}`, variant: 'destructive' });
    }
    setSyncing(null);
  };

  const handleDelete = async (providerId: string) => {
    if (!confirm('Delete this provider? All synced user records will be removed.')) return;
    try {
      await api.deleteIdentityProvider(providerId);
      toast({ title: 'Deleted', description: 'Provider removed' });
      await Promise.all([fetchProviders(), fetchStats(), fetchUsers()]);
    } catch (e) {
      toast({ title: 'Error', description: `Delete failed: ${e}`, variant: 'destructive' });
    }
  };

  const handleUserSearch = () => {
    fetchUsers(1, userSearch);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 rounded-xl">
                  <Users className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Users</p>
                  <p className="text-2xl font-bold">{stats.total_users.toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-green-500/10 rounded-xl">
                  <CircleCheck className="w-6 h-6 text-green-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Active Users</p>
                  <p className="text-2xl font-bold">{stats.active_users.toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card border-0 rounded-2xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-orange-500/10 rounded-xl">
                  <XCircle className="w-6 h-6 text-orange-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Disabled Users</p>
                  <p className="text-2xl font-bold">{stats.disabled_users.toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Provider Cards */}
      <div>
        <h2 className="text-lg font-semibold mb-4">Identity Providers</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {(Object.keys(PROVIDER_METADATA) as IdentityProviderType[]).map((type) => {
            const meta = PROVIDER_METADATA[type];
            const existing = providers.find(p => p.provider_type === type);

            return (
              <Card
                key={type}
                className="bg-card border-0 rounded-2xl hover:bg-muted/30 transition-all cursor-pointer group"
                onClick={() => handleOpenConfig(type, existing)}
              >
                <CardContent className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className={`p-3 rounded-xl ${meta.iconBg}`}>
                      {meta.icon}
                    </div>
                    {existing ? getStatusBadge(existing) : (
                      <Badge variant="outline" className="text-muted-foreground">Not Configured</Badge>
                    )}
                  </div>
                  <h3 className="font-semibold group-hover:text-primary transition-colors mb-1">
                    {meta.name}
                  </h3>
                  <p className="text-sm text-muted-foreground mb-3">{meta.description}</p>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{existing?.user_count ? `${existing.user_count.toLocaleString()} users` : 'No users'}</span>
                    {existing?.last_sync_at && (
                      <span>Synced {formatUTCCompact(new Date(existing.last_sync_at))}</span>
                    )}
                  </div>
                  {/* Action buttons */}
                  {existing?.has_credentials && (
                    <div className="flex gap-2 mt-3 pt-3 border-t border-border/50" onClick={e => e.stopPropagation()}>
                      {type !== 'active_directory' && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => handleTestConnection(existing.id)}
                            disabled={testing === existing.id}
                          >
                            {testing === existing.id ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Plug className="w-3 h-3 mr-1" />}
                            Test
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => handleSync(existing.id)}
                            disabled={syncing === existing.id}
                          >
                            {syncing === existing.id ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
                            Sync
                          </Button>
                        </>
                      )}
                      {type === 'active_directory' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs"
                          asChild
                        >
                          <a href="/scripts/Sync-ADUsers.ps1" download>
                            <Download className="w-3 h-3 mr-1" />
                            Collector Script
                          </a>
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-destructive hover:text-destructive"
                        onClick={() => handleDelete(existing.id)}
                      >
                        <Trash2 className="w-3 h-3 mr-1" />
                        Delete
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* User Browser */}
      <div>
        <h2 className="text-lg font-semibold mb-4">User Directory</h2>
        <div className="flex gap-2 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder="Search users by name, email, or department..."
              value={userSearch}
              onChange={e => setUserSearch(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleUserSearch()}
            />
          </div>
          <Button variant="outline" onClick={handleUserSearch}>Search</Button>
        </div>

        <Card className="bg-card border-0 rounded-2xl overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Department</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Provider</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {usersLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <Loader2 className="w-5 h-5 animate-spin inline-block mr-2" />Loading...
                  </TableCell>
                </TableRow>
              ) : users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    {providers.length === 0 ? 'Configure an identity provider to sync users' : 'No users found'}
                  </TableCell>
                </TableRow>
              ) : (
                users.map(user => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium">{user.display_name || user.username || '—'}</div>
                        <div className="text-xs text-muted-foreground">{user.upn || user.username}</div>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{user.email || '—'}</TableCell>
                    <TableCell className="text-sm">{user.department || '—'}</TableCell>
                    <TableCell className="text-sm">{user.title || '—'}</TableCell>
                    <TableCell>
                      <Badge variant={user.account_status === 'active' ? 'default' : 'outline'} className={
                        user.account_status === 'active'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : 'text-muted-foreground'
                      }>
                        {user.account_status || 'unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{user.provider_id}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          {usersTotal > 20 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border/50">
              <span className="text-sm text-muted-foreground">{usersTotal.toLocaleString()} total users</span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={usersPage <= 1}
                  onClick={() => fetchUsers(usersPage - 1, userSearch)}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={usersPage * 20 >= usersTotal}
                  onClick={() => fetchUsers(usersPage + 1, userSearch)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Configuration Dialog */}
      <Sheet open={!!configDialog} onOpenChange={(open) => { if (!open) setConfigDialog(null); }}>
        <SheetContent className="w-[480px] sm:w-[560px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle>
              {editingProvider ? 'Update' : 'Configure'} {configDialog ? PROVIDER_METADATA[configDialog].name : ''}
            </SheetTitle>
          </SheetHeader>

          {configDialog && (
            <div className="space-y-4">
              {!editingProvider && (
                <div className="p-3 bg-muted/50 rounded-lg space-y-1.5">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Setup</p>
                  <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                    {PROVIDER_METADATA[configDialog].setupSteps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}
              {PROVIDER_METADATA[configDialog].credentialFields.map(field => (
                <div key={field.key} className="space-y-2">
                  <Label>{field.label}</Label>
                  {field.type === 'textarea' ? (
                    <Textarea
                      placeholder={editingProvider?.has_credentials ? '(unchanged)' : `Enter ${field.label.toLowerCase()}`}
                      value={credentials[field.key] || ''}
                      onChange={e => setCredentials(prev => ({ ...prev, [field.key]: e.target.value }))}
                      rows={4}
                    />
                  ) : field.key === 'collector_token' ? (
                    <div className="flex gap-2">
                      <Input
                        type="text"
                        className="font-mono text-sm"
                        placeholder={editingProvider?.has_credentials ? '(unchanged)' : 'Generate or enter a token'}
                        value={credentials[field.key] || ''}
                        onChange={e => setCredentials(prev => ({ ...prev, [field.key]: e.target.value }))}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="shrink-0 h-9"
                        onClick={() => {
                          const bytes = crypto.getRandomValues(new Uint8Array(32));
                          const token = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
                          setCredentials(prev => ({ ...prev, [field.key]: token }));
                        }}
                      >
                        <Wand2 className="w-3.5 h-3.5 mr-1.5" />
                        Generate
                      </Button>
                    </div>
                  ) : (
                    <Input
                      type={field.type}
                      placeholder={editingProvider?.has_credentials ? '(unchanged)' : `Enter ${field.label.toLowerCase()}`}
                      value={credentials[field.key] || ''}
                      onChange={e => setCredentials(prev => ({ ...prev, [field.key]: e.target.value }))}
                    />
                  )}
                </div>
              ))}

              {editingProvider?.last_sync_error && (
                <div className="p-3 bg-red-500/10 rounded-lg text-sm text-red-400">
                  Last error: {editingProvider.last_sync_error}
                </div>
              )}
            </div>
          )}

          <SheetFooter className="mt-6">
            <Button variant="outline" onClick={() => setConfigDialog(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
              {editingProvider ? 'Update' : 'Save'}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
