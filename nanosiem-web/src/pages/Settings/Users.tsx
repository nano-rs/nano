// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Users Management Page
 *
 * Requirements: 11.1
 * - List all users with status, groups, and last login
 * - Navigate to form pages for create/edit
 * - Unlock, disable, enable actions (as modals)
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
  Users,
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  Unlock,
  UserX,
  UserCheck,
  Search,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, UserDetail } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';
import { useTierContext } from '@/hooks/use-tier';
import { TierUsageBar } from '@/components/TierUsageBar';

// Content component for use in tabbed Access Control page
export function UsersContent() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { status: tierStatus, isEnforced } = useTierContext();

  // Data state
  const [users, setUsers] = useState<UserDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog state for confirmations only
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [unlockDialogOpen, setUnlockDialogOpen] = useState(false);
  const [disableDialogOpen, setDisableDialogOpen] = useState(false);
  const [enableDialogOpen, setEnableDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Fetch users
  const fetchData = async () => {
    setLoading(true);
    try {
      const usersRes = await api.listUsers();
      setUsers(usersRes.users);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load users',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter users by search query
  const filteredUsers = users.filter(user =>
    user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    user.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Navigate to create page
  const handleOpenCreate = () => {
    navigate('/settings/access-control/users/new');
  };

  // Navigate to edit page
  const handleOpenEdit = (user: UserDetail) => {
    navigate(`/settings/access-control/users/${user.id}`);
  };

  // Open delete dialog
  const handleOpenDelete = (user: UserDetail) => {
    setSelectedUser(user);
    setDeleteDialogOpen(true);
  };

  // Delete user
  const handleDelete = async () => {
    if (!selectedUser) return;

    setActionLoading(true);
    try {
      await api.deleteUser(selectedUser.id);
      toast({ title: 'User deleted', description: `${selectedUser.name} has been deleted.` });
      setDeleteDialogOpen(false);
      setSelectedUser(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete user',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Open unlock dialog
  const handleOpenUnlock = (user: UserDetail) => {
    setSelectedUser(user);
    setUnlockDialogOpen(true);
  };

  // Unlock user (after confirmation)
  const handleUnlock = async () => {
    if (!selectedUser) return;
    setActionLoading(true);
    try {
      await api.unlockUser(selectedUser.id);
      toast({ title: 'User unlocked', description: `${selectedUser.name} has been unlocked.` });
      setUnlockDialogOpen(false);
      setSelectedUser(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to unlock user',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Open disable dialog
  const handleOpenDisable = (user: UserDetail) => {
    setSelectedUser(user);
    setDisableDialogOpen(true);
  };

  // Disable user (after confirmation)
  const handleDisable = async () => {
    if (!selectedUser) return;
    setActionLoading(true);
    try {
      await api.disableUser(selectedUser.id);
      toast({ title: 'User disabled', description: `${selectedUser.name} has been disabled.` });
      setDisableDialogOpen(false);
      setSelectedUser(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to disable user',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Open enable dialog
  const handleOpenEnable = (user: UserDetail) => {
    setSelectedUser(user);
    setEnableDialogOpen(true);
  };

  // Enable user (after confirmation)
  const handleEnable = async () => {
    if (!selectedUser) return;
    setActionLoading(true);
    try {
      await api.enableUser(selectedUser.id);
      toast({ title: 'User enabled', description: `${selectedUser.name} has been enabled.` });
      setEnableDialogOpen(false);
      setSelectedUser(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to enable user',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  // Get status badge
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 rounded-lg">Active</Badge>;
      case 'locked':
        return <Badge className="bg-yellow-500/10 text-yellow-400 rounded-lg">Locked</Badge>;
      case 'disabled':
        return <Badge className="bg-red-500/10 text-red-400 rounded-lg">Disabled</Badge>;
      default:
        return <Badge className="bg-gray-500/10 text-muted-foreground rounded-lg">{status}</Badge>;
    }
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
        <p className="text-muted-foreground">Manage user accounts, status, and group memberships</p>
        <div className="flex items-center gap-3">
          {isEnforced && tierStatus && (
            <TierUsageBar
              label="members"
              current={tierStatus.usage.team_members}
              limit={tierStatus.limits.max_team_members}
            />
          )}
          <Button
            onClick={handleOpenCreate}
          >
            <Plus className="w-4 h-4 mr-2" />
            Add User
          </Button>
        </div>
      </div>

      {/* Search and Table */}
      <Card className="border-0">
        <CardHeader>
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search users..."
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
                <TableHead>Email</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Groups</TableHead>
                <TableHead>Last Login</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No users found
                  </TableCell>
                </TableRow>
              ) : (
                filteredUsers.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium text-foreground">
                      <div
                        className="flex items-center gap-2 cursor-pointer hover:text-primary transition-colors"
                        onClick={() => handleOpenEdit(user)}
                      >
                        {user.name}
                        {user.oidc_provider && (
                          <Badge className="bg-purple-500/10 text-purple-400 rounded-lg text-xs">
                            SSO
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-foreground">{user.email}</TableCell>
                    <TableCell>{getStatusBadge(user.status)}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {user.groups.slice(0, 3).map((group) => (
                          <Badge
                            key={group.id}
                            variant="outline"
                            className="border-border text-foreground rounded-lg text-xs"
                          >
                            {group.name}
                          </Badge>
                        ))}
                        {user.groups.length > 3 && (
                          <Badge
                            variant="outline"
                            className="border-border text-muted-foreground rounded-lg text-xs"
                          >
                            +{user.groups.length - 3}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatUTC(user.last_login_at)}
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
                            onClick={() => handleOpenEdit(user)}
                          >
                            <Pencil className="w-4 h-4 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {user.status === 'locked' && (
                            <DropdownMenuItem
                              onClick={() => handleOpenUnlock(user)}
                            >
                              <Unlock className="w-4 h-4 mr-2" />
                              Unlock
                            </DropdownMenuItem>
                          )}
                          {user.status === 'active' && (
                            <DropdownMenuItem
                              onClick={() => handleOpenDisable(user)}
                            >
                              <UserX className="w-4 h-4 mr-2" />
                              Disable
                            </DropdownMenuItem>
                          )}
                          {user.status === 'disabled' && (
                            <DropdownMenuItem
                              onClick={() => handleOpenEnable(user)}
                            >
                              <UserCheck className="w-4 h-4 mr-2" />
                              Enable
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleOpenDelete(user)}
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
            <AlertDialogTitle>Delete User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <span className="text-foreground font-medium">{selectedUser?.name}</span>?
              This action cannot be undone.
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

      {/* Unlock Confirmation Dialog */}
      <AlertDialog open={unlockDialogOpen} onOpenChange={setUnlockDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unlock User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to unlock <span className="text-foreground font-medium">{selectedUser?.name}</span>?
              This will allow them to log in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleUnlock}
              disabled={actionLoading}
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Unlock
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Disable Confirmation Dialog */}
      <AlertDialog open={disableDialogOpen} onOpenChange={setDisableDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disable User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to disable <span className="text-foreground font-medium">{selectedUser?.name}</span>?
              They will no longer be able to log in until re-enabled.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDisable}
              disabled={actionLoading}
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Disable
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Enable Confirmation Dialog */}
      <AlertDialog open={enableDialogOpen} onOpenChange={setEnableDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Enable User</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to enable <span className="text-foreground font-medium">{selectedUser?.name}</span>?
              This will restore their access to the system.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleEnable}
              disabled={actionLoading}
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Enable
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function UsersPage() {
  return (
    <div className="p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-xl">
          <Users className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-foreground">User Management</h1>
      </div>
      <UsersContent />
    </div>
  );
}
