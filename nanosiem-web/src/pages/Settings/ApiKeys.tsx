// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * API Keys Management Page
 *
 * Requirements: 12.1, 12.3, 12.6, 12.8
 * - List API keys (masked) with last used
 * - Navigate to create page (no edit - keys are immutable)
 * - Show full key only once on creation (modal)
 * - Enable/disable/delete confirmation modals
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
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
  Key,
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  Power,
  PowerOff,
  Search,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, ApiKeySummary } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';

// Content component for use in tabbed Access Control page
export function ApiKeysContent() {
  const navigate = useNavigate();
  const { toast } = useToast();

  // Data state
  const [apiKeys, setApiKeys] = useState<ApiKeySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog state for confirmations only
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [toggleDialogOpen, setToggleDialogOpen] = useState(false);
  const [selectedKey, setSelectedKey] = useState<ApiKeySummary | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Fetch API keys
  const fetchData = async () => {
    setLoading(true);
    try {
      const keysRes = await api.listApiKeys();
      setApiKeys(keysRes.api_keys);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load API keys',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter keys by search query
  const filteredKeys = apiKeys.filter(key =>
    key.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (key.description?.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  // Navigate to create page
  const handleOpenCreate = () => {
    navigate('/settings/access-control/api-keys/new');
  };

  // Open delete dialog
  const handleOpenDelete = (key: ApiKeySummary) => {
    setSelectedKey(key);
    setDeleteDialogOpen(true);
  };

  // Delete API key
  const handleDelete = async () => {
    if (!selectedKey) return;

    setActionLoading(true);
    try {
      await api.deleteApiKey(selectedKey.id);
      toast({ title: 'API key deleted', description: `${selectedKey.name} has been deleted.` });
      setDeleteDialogOpen(false);
      setSelectedKey(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete API key',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Open toggle dialog
  const handleOpenToggle = (key: ApiKeySummary) => {
    setSelectedKey(key);
    setToggleDialogOpen(true);
  };

  // Toggle key enabled (after confirmation)
  const handleToggleEnabled = async () => {
    if (!selectedKey) return;
    setActionLoading(true);
    try {
      if (selectedKey.enabled) {
        await api.disableApiKey(selectedKey.id);
        toast({ title: 'API key disabled', description: `${selectedKey.name} has been disabled.` });
      } else {
        await api.enableApiKey(selectedKey.id);
        toast({ title: 'API key enabled', description: `${selectedKey.name} has been enabled.` });
      }
      setToggleDialogOpen(false);
      setSelectedKey(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to toggle API key',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Check if key is expired
  const isExpired = (key: ApiKeySummary) => {
    if (!key.expires_at) return false;
    return new Date(key.expires_at) < new Date();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground">Manage API keys for service-to-service authentication</p>
        <Button
          onClick={handleOpenCreate}
        >
          <Plus className="w-4 h-4 mr-2" />
          Create API Key
        </Button>
      </div>

      {/* Search and Table */}
      <Card className="border-0">
        <CardHeader>
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search API keys..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>Key Prefix</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredKeys.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No API keys found
                  </TableCell>
                </TableRow>
              ) : (
                filteredKeys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-medium text-foreground">
                      <div
                        className="cursor-pointer hover:text-primary transition-colors"
                        onClick={() => navigate(`/settings/access-control/api-keys/${key.id}`)}
                      >
                        {key.name}
                        {key.description && (
                          <p className="text-xs text-muted-foreground mt-0.5">{key.description}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-foreground font-mono text-sm">
                      {key.key_prefix}...
                    </TableCell>
                    <TableCell>
                      {isExpired(key) ? (
                        <Badge className="bg-red-500/10 text-red-400 rounded-lg">Expired</Badge>
                      ) : key.enabled ? (
                        <Badge className="bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 rounded-lg">Active</Badge>
                      ) : (
                        <Badge className="bg-gray-500/10 text-muted-foreground rounded-lg">Disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-border text-foreground rounded-lg">
                        {key.permissions.length} permissions
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatUTC(key.last_used_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {key.expires_at ? formatUTC(key.expires_at) : 'Never'}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                            <MoreHorizontal className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => navigate(`/settings/access-control/api-keys/${key.id}`)}
                          >
                            <Pencil className="w-4 h-4 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleOpenToggle(key)}
                          >
                            {key.enabled ? (
                              <>
                                <PowerOff className="w-4 h-4 mr-2" />
                                Disable
                              </>
                            ) : (
                              <>
                                <Power className="w-4 h-4 mr-2" />
                                Enable
                              </>
                            )}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleOpenDelete(key)}
                            className="text-destructive focus:text-destructive"
                          >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete API Key</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <span className="text-foreground font-medium">{selectedKey?.name}</span>?
              Any services using this key will immediately lose access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={actionLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Toggle Enable/Disable Confirmation Dialog */}
      <AlertDialog open={toggleDialogOpen} onOpenChange={setToggleDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {selectedKey?.enabled ? 'Disable' : 'Enable'} API Key
            </AlertDialogTitle>
            <AlertDialogDescription>
              {selectedKey?.enabled ? (
                <>
                  Are you sure you want to disable <span className="text-foreground font-medium">{selectedKey?.name}</span>?
                  Any services using this key will immediately lose access.
                </>
              ) : (
                <>
                  Are you sure you want to enable <span className="text-foreground font-medium">{selectedKey?.name}</span>?
                  This will restore access for services using this key.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleToggleEnabled}
              disabled={actionLoading}
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              {selectedKey?.enabled ? 'Disable' : 'Enable'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function ApiKeysPage() {
  return (
    <div className="p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-xl">
          <Key className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-foreground">API Keys</h1>
      </div>
      <ApiKeysContent />
    </div>
  );
}
