// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Roles Management Page
 *
 * Requirements: 11.3, 11.7
 * - List roles with permission counts
 * - Navigate to form pages for create/edit
 * - Delete confirmation modal
 * - Protection for system roles
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
  ShieldCheck,
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  Search,
  Shield,
  Key,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, RoleDetail } from '@/lib/api';

// Content component for use in tabbed Access Control page
export function RolesContent() {
  const navigate = useNavigate();
  const { toast } = useToast();

  // Data state
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog state for delete confirmation only
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedRole, setSelectedRole] = useState<RoleDetail | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Fetch roles
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
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load roles',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter roles by search query
  const filteredRoles = roles.filter(role =>
    role.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (role.description?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false)
  );

  // Navigate to create page
  const handleOpenCreate = () => {
    navigate('/settings/access-control/roles/new');
  };

  // Navigate to edit page
  const handleOpenEdit = (role: RoleDetail) => {
    if (role.is_system && role.name === 'Admin') {
      toast({
        title: 'Cannot Edit',
        description: 'The Admin role cannot be modified',
        variant: 'destructive',
      });
      return;
    }
    navigate(`/settings/access-control/roles/${role.id}`);
  };

  // Open delete dialog
  const handleOpenDelete = (role: RoleDetail) => {
    if (role.is_system) {
      toast({
        title: 'Cannot Delete',
        description: 'System roles cannot be deleted',
        variant: 'destructive',
      });
      return;
    }
    setSelectedRole(role);
    setDeleteDialogOpen(true);
  };

  // Delete role
  const handleDelete = async () => {
    if (!selectedRole) return;

    setActionLoading(true);
    try {
      await api.deleteRole(selectedRole.id);
      toast({ title: 'Role deleted', description: `${selectedRole.name} has been deleted.` });
      setDeleteDialogOpen(false);
      setSelectedRole(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete role',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Get role badge color based on name
  const getRoleBadgeColor = (role: RoleDetail) => {
    if (role.name === 'Admin') return 'bg-red-500/10 text-red-400';
    if (role.name === 'Editor') return 'bg-orange-500/10 text-orange-400';
    if (role.name === 'ReadOnly') return 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400';
    return 'bg-gray-500/10 text-muted-foreground';
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
        <p className="text-muted-foreground">Define roles with specific permissions for access control</p>
        <Button
          onClick={handleOpenCreate}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Role
        </Button>
      </div>

      {/* Search and Table */}
      <Card className="border-0">
        <CardHeader>
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search roles..."
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
                <TableHead>Description</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRoles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                    No roles found
                  </TableCell>
                </TableRow>
              ) : (
                filteredRoles.map((role) => (
                  <TableRow key={role.id}>
                    <TableCell className="font-medium">
                      <div
                        className="flex items-center gap-2 cursor-pointer hover:text-primary transition-colors"
                        onClick={() => handleOpenEdit(role)}
                      >
                        <Badge className={`${getRoleBadgeColor(role)} rounded-lg`}>
                          {role.name}
                        </Badge>
                        {role.is_system && (
                          <Shield className="w-4 h-4 text-primary" />
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-xs truncate">
                      {role.description || '-'}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Key className="w-4 h-4 text-muted-foreground" />
                        <span className="text-foreground">
                          {role.permissions?.includes('*')
                            ? 'All permissions'
                            : `${role.permissions?.length || 0} permissions`}
                        </span>
                      </div>
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
                            onClick={() => handleOpenEdit(role)}
                            disabled={role.is_system && role.name === 'Admin'}
                          >
                            <Pencil className="w-4 h-4 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleOpenDelete(role)}
                            className="text-destructive focus:text-destructive"
                            disabled={role.is_system}
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
            <AlertDialogTitle>Delete Role</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <span className="text-foreground font-medium">{selectedRole?.name}</span>?
              Groups using this role will need to be reassigned.
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
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function RolesPage() {
  return (
    <div className="p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-xl">
          <ShieldCheck className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-foreground">Role Management</h1>
      </div>
      <RolesContent />
    </div>
  );
}
