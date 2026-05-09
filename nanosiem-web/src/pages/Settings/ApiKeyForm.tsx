// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * API Key Form Page
 *
 * Create or edit API key with permissions
 * Shows the created/reset key only once for security
 */

import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import {
  ArrowLeft,
  Loader2,
  Key,
  AlertTriangle,
  Copy,
  Check,
  SquareCheckBig,
  Square,
  RefreshCw,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, ApiKeySummary, CreateApiKeyRequest, UpdateApiKeyRequest } from '@/lib/api';
import type { PermissionInfo } from '@/lib/api/types';
import { categoryDisplayName } from '@/lib/permissions';

export function ApiKeyForm() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const isEditing = !!id && id !== 'new';

  // Data state
  const [apiKey, setApiKey] = useState<ApiKeySummary | null>(null);
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    permissions: [] as string[],
    expires_at: '',
    rate_limit: '',
  });
  const [openAccordionItems, setOpenAccordionItems] = useState<string[]>([]);

  // Dialog state
  const [keyDialogOpen, setKeyDialogOpen] = useState(false);
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Group permissions by category
  const permissionsByCategory = useMemo(() => {
    const grouped: Record<string, PermissionInfo[]> = {};
    permissions.forEach(perm => {
      if (!grouped[perm.category]) {
        grouped[perm.category] = [];
      }
      grouped[perm.category].push(perm);
    });
    return Object.fromEntries(
      Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b))
    );
  }, [permissions]);

  // Fetch data
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const permsRes = await api.listPermissions();
        setPermissions(permsRes);

        if (isEditing) {
          const key = await api.getApiKey(id);
          setApiKey(key);
          setFormData({
            name: key.name,
            description: key.description || '',
            permissions: key.permissions,
            expires_at: key.expires_at ? new Date(key.expires_at).toISOString().slice(0, 16) : '',
            rate_limit: key.rate_limit?.toString() || '',
          });
        }
      } catch (err) {
        toast({
          title: 'Error',
          description: err instanceof Error ? err.message : 'Failed to load data',
          variant: 'destructive',
        });
        if (isEditing) {
          navigate('/settings/access-control?tab=api-keys');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id, isEditing, navigate, toast]);

  // Toggle permission
  const togglePermission = (permissionId: string) => {
    setFormData(prev => ({
      ...prev,
      permissions: prev.permissions.includes(permissionId)
        ? prev.permissions.filter(p => p !== permissionId)
        : [...prev.permissions, permissionId],
    }));
  };

  // Toggle all permissions in a category
  const toggleCategory = (category: string) => {
    const categoryPerms = permissionsByCategory[category]?.map(p => p.id) || [];

    const allSelected = categoryPerms.every(p => formData.permissions.includes(p));

    setFormData(prev => ({
      ...prev,
      permissions: allSelected
        ? prev.permissions.filter(p => !categoryPerms.includes(p))
        : [...new Set([...prev.permissions, ...categoryPerms])],
    }));
  };

  // Check if all permissions in a category are selected
  const isCategoryFullySelected = (category: string) => {
    const categoryPerms = permissionsByCategory[category]?.map(p => p.id) || [];
    return categoryPerms.length > 0 && categoryPerms.every(p => formData.permissions.includes(p));
  };

  // Check if some permissions in a category are selected
  const isCategoryPartiallySelected = (category: string) => {
    const categoryPerms = permissionsByCategory[category]?.map(p => p.id) || [];
    const selectedCount = categoryPerms.filter(p => formData.permissions.includes(p)).length;
    return selectedCount > 0 && selectedCount < categoryPerms.length;
  };

  // Copy key to clipboard
  const handleCopyKey = async () => {
    if (!newKey) return;
    try {
      await navigator.clipboard.writeText(newKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to copy to clipboard',
        variant: 'destructive',
      });
    }
  };

  // Handle save
  const handleSave = async () => {
    if (!formData.name || formData.permissions.length === 0) {
      toast({
        title: 'Validation Error',
        description: 'Name and at least one permission are required',
        variant: 'destructive',
      });
      return;
    }

    setSaving(true);
    try {
      if (isEditing && apiKey) {
        const request: UpdateApiKeyRequest = {
          name: formData.name !== apiKey.name ? formData.name : undefined,
          description: formData.description !== (apiKey.description || '') ? formData.description : undefined,
          permissions: formData.permissions,
          expires_at: formData.expires_at || undefined,
          rate_limit: formData.rate_limit ? parseInt(formData.rate_limit) : undefined,
        };
        await api.updateApiKey(apiKey.id, request);
        toast({ title: 'API key updated', description: `${formData.name} has been updated.` });
        navigate('/settings/access-control?tab=api-keys');
      } else {
        const request: CreateApiKeyRequest = {
          name: formData.name,
          description: formData.description || undefined,
          permissions: formData.permissions,
          expires_at: formData.expires_at || undefined,
          rate_limit: formData.rate_limit ? parseInt(formData.rate_limit) : undefined,
        };
        const response = await api.createApiKey(request);
        setNewKey(response.key);
        setKeyDialogOpen(true);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save API key',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  // Handle reset key
  const handleResetKey = async () => {
    if (!apiKey) return;

    setResetting(true);
    try {
      const response = await api.resetApiKey(apiKey.id);
      setNewKey(response.key);
      setResetDialogOpen(false);
      setKeyDialogOpen(true);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to reset API key',
        variant: 'destructive',
      });
    } finally {
      setResetting(false);
    }
  };

  // Handle key dialog close
  const handleKeyDialogClose = () => {
    setKeyDialogOpen(false);
    setNewKey(null);
    setCopied(false);
    navigate('/settings/access-control?tab=api-keys');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-8 space-y-6">
      {/* Back button */}
      <Button
        variant="ghost"
        onClick={() => navigate('/settings/access-control?tab=api-keys')}
        className="rounded-xl"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to API Keys
      </Button>

      {/* Header with title and save button */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-xl">
            <Key className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">
              {isEditing ? 'Edit API Key' : 'Create API Key'}
            </h1>
            <p className="text-muted-foreground">
              {isEditing
                ? 'Update API key settings and permissions'
                : 'Create a new API key for service-to-service authentication'}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          {isEditing && (
            <Button
              variant="outline"
              onClick={() => setResetDialogOpen(true)}
              className="rounded-xl border-border"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Reset Key
            </Button>
          )}
          <Button
            onClick={handleSave}
            disabled={saving}
            className="bg-primary hover:bg-primary/90 rounded-xl"
          >
            {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            {isEditing ? 'Save Changes' : 'Create API Key'}
          </Button>
        </div>
      </div>

      {/* Key prefix info for edit mode */}
      {isEditing && apiKey && (
        <div className="p-4 bg-muted/50 border border-border rounded-xl flex items-center gap-3">
          <Key className="w-5 h-5 text-muted-foreground" />
          <div>
            <p className="text-sm text-foreground">
              Key prefix: <span className="font-mono">{apiKey.key_prefix}...</span>
            </p>
            <p className="text-xs text-muted-foreground">
              The full key value is hidden for security. Use "Reset Key" to generate a new one.
            </p>
          </div>
        </div>
      )}

      {/* Form in cards */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-foreground">Basic Information</CardTitle>
          <CardDescription className="text-muted-foreground">
            API key identification and optional settings
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Name</Label>
            <Input
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="My API Key"
              className="border-border rounded-xl"
            />
          </div>
          <div className="space-y-2">
            <Label>Description (optional)</Label>
            <Textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="What is this API key used for?"
              className="border-border rounded-xl resize-none"
              rows={2}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Expiration (optional)</Label>
              <Input
                type="datetime-local"
                value={formData.expires_at}
                onChange={(e) => setFormData(prev => ({ ...prev, expires_at: e.target.value }))}
                className="border-border rounded-xl"
              />
            </div>
            <div className="space-y-2">
              <Label>Rate Limit (requests/min, optional)</Label>
              <Input
                type="number"
                value={formData.rate_limit}
                onChange={(e) => setFormData(prev => ({ ...prev, rate_limit: e.target.value }))}
                placeholder="Unlimited"
                className="border-border rounded-xl"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-foreground">Permissions</CardTitle>
              <CardDescription className="text-muted-foreground">
                Select the permissions this API key should have
              </CardDescription>
            </div>
            <Badge variant="outline" className="border-border text-muted-foreground">
              {formData.permissions.length} selected
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-[500px] overflow-y-auto p-2 bg-muted/50 rounded-xl">
            <Accordion
              type="multiple"
              className="w-full"
              value={openAccordionItems}
              onValueChange={setOpenAccordionItems}
            >
              {Object.entries(permissionsByCategory).map(([category, perms]) => {
                const isFullySelected = isCategoryFullySelected(category);
                const isPartiallySelected = isCategoryPartiallySelected(category);

                return (
                  <AccordionItem key={category} value={category} className="border-border">
                    <AccordionTrigger className="hover:no-underline py-2">
                      <div className="flex items-center gap-3 w-full">
                        <div
                          className="cursor-pointer"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleCategory(category);
                          }}
                        >
                          {isFullySelected ? (
                            <SquareCheckBig className="w-4 h-4 text-primary" />
                          ) : isPartiallySelected ? (
                            <div className="w-4 h-4 border-2 border-blue-400 rounded bg-blue-400/30" />
                          ) : (
                            <Square className="w-4 h-4 text-muted-foreground" />
                          )}
                        </div>
                        <span className="text-foreground">{categoryDisplayName(category)}</span>
                        <Badge variant="outline" className="ml-auto mr-2 border-border text-muted-foreground">
                          {perms.filter(p => formData.permissions.includes(p.id)).length}/{perms.length}
                        </Badge>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="space-y-2 pl-7 pt-2">
                        {perms.map((perm) => (
                          <div key={perm.id} className="flex items-start space-x-2">
                            <Checkbox
                              id={`perm-${perm.id}`}
                              checked={formData.permissions.includes(perm.id)}
                              onCheckedChange={() => togglePermission(perm.id)}
                              className="mt-0.5"
                            />
                            <label
                              htmlFor={`perm-${perm.id}`}
                              className="text-sm cursor-pointer"
                            >
                              <span className="text-foreground">{perm.name}</span>
                              {perm.description && (
                                <p className="text-xs text-muted-foreground">{perm.description}</p>
                              )}
                            </label>
                          </div>
                        ))}
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                );
              })}
            </Accordion>
          </div>
        </CardContent>
      </Card>

      {/* Reset Key Confirmation Dialog */}
      <AlertDialog open={resetDialogOpen} onOpenChange={setResetDialogOpen}>
        <AlertDialogContent className="bg-card border-border rounded-2xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">Reset API Key</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              Are you sure you want to reset this API key? This will generate a new key value and
              immediately invalidate the old one. Any services using the current key will need to be updated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="rounded-xl border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleResetKey}
              disabled={resetting}
              className="bg-orange-600 hover:bg-orange-700 rounded-xl"
            >
              {resetting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Reset Key
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Key Created/Reset Dialog - Shows the key only once */}
      <Dialog open={keyDialogOpen} onOpenChange={(open) => {
        if (!open) handleKeyDialogClose();
      }}>
        <DialogContent className="bg-card border-border rounded-2xl max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-foreground flex items-center gap-2">
              <Check className="w-5 h-5 text-green-400" />
              {isEditing ? 'API Key Reset' : 'API Key Created'}
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Copy your API key now. You won't be able to see it again!
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="flex items-center gap-2 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl mb-4">
              <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0" />
              <p className="text-sm text-amber-700 dark:text-amber-200">
                This is the only time you'll see this key. Store it securely.
              </p>
            </div>
            <div className="relative">
              <Input
                value={newKey || ''}
                readOnly
                className="border-border rounded-xl font-mono pr-12"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopyKey}
                className="absolute right-1 top-1/2 -translate-y-1/2 h-8 w-8 p-0"
              >
                {copied ? (
                  <Check className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-muted-foreground" />
                )}
              </Button>
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={handleKeyDialogClose}
              className="bg-primary hover:bg-primary/90 rounded-xl text-foreground"
            >
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
