// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Role Form Page
 *
 * Create/Edit role page with permission editor
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
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import {
  ArrowLeft,
  Loader2,
  ShieldCheck,
  SquareCheckBig,
  Square,
  Shield,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, RoleDetail, PermissionInfo, CreateRoleRequest, UpdateRoleRequest } from '@/lib/api';
import { categoryDisplayName } from '@/lib/permissions';


export function RoleForm() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const isEditing = !!id && id !== 'new';

  // Data state
  const [role, setRole] = useState<RoleDetail | null>(null);
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    permissions: [] as string[],
  });
  const [openAccordionItems, setOpenAccordionItems] = useState<string[]>([]);

  // Group permissions by category
  const permissionsByCategory = useMemo(() => {
    const grouped: Record<string, PermissionInfo[]> = {};
    permissions.forEach(perm => {
      if (!grouped[perm.category]) {
        grouped[perm.category] = [];
      }
      grouped[perm.category].push(perm);
    });
    // Sort categories alphabetically
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
          const rolesRes = await api.listRoles();
          const foundRole = rolesRes.roles.find(r => r.id === id);
          if (foundRole) {
            if (foundRole.is_system && foundRole.name === 'Admin') {
              toast({
                title: 'Cannot Edit',
                description: 'The Admin role cannot be modified',
                variant: 'destructive',
              });
              navigate('/settings/access-control?tab=roles');
              return;
            }
            setRole({
              ...foundRole,
              permissions: foundRole.permissions || [],
              created_at: foundRole.created_at || new Date().toISOString(),
              updated_at: foundRole.updated_at || new Date().toISOString(),
            });
            setFormData({
              name: foundRole.name,
              description: foundRole.description || '',
              permissions: foundRole.permissions || [],
            });
          } else {
            toast({
              title: 'Error',
              description: 'Role not found',
              variant: 'destructive',
            });
            navigate('/settings/access-control?tab=roles');
          }
        }
      } catch (err) {
        toast({
          title: 'Error',
          description: err instanceof Error ? err.message : 'Failed to load data',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id, isEditing, navigate, toast]);

  // Toggle permission selection
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

  // Handle save
  const handleSave = async () => {
    if (!formData.name) {
      toast({
        title: 'Validation Error',
        description: 'Role name is required',
        variant: 'destructive',
      });
      return;
    }

    setSaving(true);
    try {
      if (isEditing && role) {
        const request: UpdateRoleRequest = {
          name: formData.name !== role.name ? formData.name : undefined,
          description: formData.description !== role.description ? formData.description : undefined,
          permissions: formData.permissions,
        };
        await api.updateRole(role.id, request);
        toast({ title: 'Role updated', description: `${formData.name} has been updated.` });
      } else {
        const request: CreateRoleRequest = {
          name: formData.name,
          description: formData.description || undefined,
          permissions: formData.permissions,
        };
        await api.createRole(request);
        toast({ title: 'Role created', description: `${formData.name} has been created.` });
      }
      navigate('/settings/access-control?tab=roles');
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save role',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
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
        onClick={() => navigate('/settings/access-control?tab=roles')}
        className="rounded-xl"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Roles
      </Button>

      {/* Header with title and save button */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-xl">
            <ShieldCheck className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">
              {isEditing ? 'Edit Role' : 'Create Role'}
            </h1>
            <p className="text-muted-foreground">
              {isEditing ? 'Update role details and permissions' : 'Create a new role with specific permissions'}
            </p>
          </div>
        </div>
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-primary hover:bg-primary/90 rounded-xl"
        >
          {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
          {isEditing ? 'Save Changes' : 'Create Role'}
        </Button>
      </div>

      {/* System role warning */}
      {isEditing && role?.is_system && (
        <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-xl flex items-center gap-3">
          <Shield className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
          <p className="text-sm text-yellow-700 dark:text-yellow-300">
            This is a system role. The name cannot be changed, but permissions can be modified.
          </p>
        </div>
      )}

      {/* Form in cards */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-foreground">Basic Information</CardTitle>
          <CardDescription className="text-muted-foreground">
            Role name and description
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Name</Label>
            <Input
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Security Analyst"
              className="border-border rounded-xl"
              disabled={isEditing && role?.is_system}
            />
          </div>
          <div className="space-y-2">
            <Label>Description</Label>
            <Textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Optional description..."
              className="border-border rounded-xl resize-none"
              rows={2}
            />
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-foreground">Permissions</CardTitle>
              <CardDescription className="text-muted-foreground">
                Select the permissions for this role
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
                              <p className="text-xs text-muted-foreground">{perm.description}</p>
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
    </div>
  );
}
