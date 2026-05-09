// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Group Form Page
 *
 * Create/Edit group page with form in cards
 */

import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import {
  ArrowLeft,
  Loader2,
  Shield,
  Users2,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, GroupDetail, RoleDetail, CreateGroupRequest, UpdateGroupRequest } from '@/lib/api';

export function GroupForm() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const isEditing = !!id && id !== 'new';

  // Data state
  const [group, setGroup] = useState<GroupDetail | null>(null);
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    role_ids: [] as string[],
  });

  // Fetch data
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const rolesRes = await api.listRoles();
        setRoles(rolesRes.roles.map(r => ({
          ...r,
          permissions: r.permissions || [],
          created_at: r.created_at || new Date().toISOString(),
          updated_at: r.updated_at || new Date().toISOString(),
        })));

        if (isEditing) {
          const groupsRes = await api.listGroups();
          const foundGroup = groupsRes.groups.find(g => g.id === id);
          if (foundGroup) {
            if (foundGroup.is_system) {
              toast({
                title: 'Cannot Edit',
                description: 'System groups cannot be modified',
                variant: 'destructive',
              });
              navigate('/settings/access-control?tab=groups');
              return;
            }
            setGroup(foundGroup);
            setFormData({
              name: foundGroup.name,
              description: foundGroup.description || '',
              role_ids: foundGroup.roles.map(r => r.id),
            });
          } else {
            toast({
              title: 'Error',
              description: 'Group not found',
              variant: 'destructive',
            });
            navigate('/settings/access-control?tab=groups');
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

  // Toggle role selection
  const toggleRole = (roleId: string) => {
    setFormData(prev => ({
      ...prev,
      role_ids: prev.role_ids.includes(roleId)
        ? prev.role_ids.filter(rid => rid !== roleId)
        : [...prev.role_ids, roleId],
    }));
  };

  // Handle save
  const handleSave = async () => {
    if (!formData.name) {
      toast({
        title: 'Validation Error',
        description: 'Group name is required',
        variant: 'destructive',
      });
      return;
    }

    setSaving(true);
    try {
      if (isEditing && group) {
        const request: UpdateGroupRequest = {
          name: formData.name !== group.name ? formData.name : undefined,
          description: formData.description !== group.description ? formData.description : undefined,
          role_ids: formData.role_ids,
        };
        await api.updateGroup(group.id, request);
        toast({ title: 'Group updated', description: `${formData.name} has been updated.` });
      } else {
        const request: CreateGroupRequest = {
          name: formData.name,
          description: formData.description || undefined,
          role_ids: formData.role_ids,
        };
        await api.createGroup(request);
        toast({ title: 'Group created', description: `${formData.name} has been created.` });
      }
      navigate('/settings/access-control?tab=groups');
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save group',
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
        onClick={() => navigate('/settings/access-control?tab=groups')}
        className="rounded-xl"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Groups
      </Button>

      {/* Header with title and save button */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-xl">
            <Users2 className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">
              {isEditing ? 'Edit Group' : 'Create Group'}
            </h1>
            <p className="text-muted-foreground">
              {isEditing ? 'Update group details and role assignments' : 'Create a new group and assign roles'}
            </p>
          </div>
        </div>
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-primary hover:bg-primary/90 rounded-xl"
        >
          {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
          {isEditing ? 'Save Changes' : 'Create Group'}
        </Button>
      </div>

      {/* Form in cards */}
      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-foreground">Basic Information</CardTitle>
          <CardDescription className="text-muted-foreground">
            Group name and description
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Name</Label>
            <Input
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Security Analysts"
              className="border-border rounded-xl"
            />
          </div>
          <div className="space-y-2">
            <Label>Description</Label>
            <Textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Optional description..."
              className="border-border rounded-xl resize-none"
              rows={3}
            />
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-0 rounded-2xl">
        <CardHeader>
          <CardTitle className="text-foreground">Role Assignments</CardTitle>
          <CardDescription className="text-muted-foreground">
            Assign roles to define permissions for group members
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-60 overflow-y-auto p-2 bg-muted/50 rounded-xl">
            {roles.length === 0 ? (
              <p className="text-center text-muted-foreground py-4">No roles available</p>
            ) : (
              roles.map((role) => (
                <div key={role.id} className="flex items-center space-x-2 p-2 hover:bg-accent/50 rounded-lg">
                  <Checkbox
                    id={`role-${role.id}`}
                    checked={formData.role_ids.includes(role.id)}
                    onCheckedChange={() => toggleRole(role.id)}
                  />
                  <label
                    htmlFor={`role-${role.id}`}
                    className="flex-1 text-sm text-foreground cursor-pointer flex items-center gap-2"
                  >
                    {role.name}
                    {role.is_system && (
                      <Shield className="w-3 h-3 text-primary" />
                    )}
                  </label>
                  <span className="text-xs text-muted-foreground">
                    {role.permissions?.length || 0} permissions
                  </span>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
