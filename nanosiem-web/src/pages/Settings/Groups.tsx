// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Groups Management Page
 *
 * Requirements: 11.2
 * - List groups with role assignments and member counts
 * - Navigate to form pages for create/edit
 * - Delete confirmation modal
 * - Members view modal (read-only)
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
  Users2,
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  Search,
  Shield,
  UserCircle,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api, GroupDetail } from '@/lib/api';

// Content component for use in tabbed Access Control page
export function GroupsContent() {
  const navigate = useNavigate();
  const { toast } = useToast();

  // Data state
  const [groups, setGroups] = useState<GroupDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog state for confirmations and members view only
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [membersDialogOpen, setMembersDialogOpen] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<GroupDetail | null>(null);
  const [groupMembers, setGroupMembers] = useState<Array<{ id: string; name: string; email: string }>>([]);
  const [actionLoading, setActionLoading] = useState(false);

  // Fetch groups
  const fetchData = async () => {
    setLoading(true);
    try {
      const groupsRes = await api.listGroups();
      setGroups(groupsRes.groups);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load groups',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter groups by search query
  const filteredGroups = groups.filter(group =>
    group.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (group.description?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false)
  );

  // Navigate to create page
  const handleOpenCreate = () => {
    navigate('/settings/access-control/groups/new');
  };

  // Navigate to edit page
  const handleOpenEdit = (group: GroupDetail) => {
    if (group.is_system) {
      toast({
        title: 'Cannot Edit',
        description: 'System groups cannot be modified',
        variant: 'destructive',
      });
      return;
    }
    navigate(`/settings/access-control/groups/${group.id}`);
  };

  // Open delete dialog
  const handleOpenDelete = (group: GroupDetail) => {
    setSelectedGroup(group);
    setDeleteDialogOpen(true);
  };

  // Open members dialog
  const handleOpenMembers = async (group: GroupDetail) => {
    setSelectedGroup(group);
    setMembersDialogOpen(true);
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL ?? ''}/api/groups/${group.id}/members`);
      if (response.ok) {
        const data = await response.json();
        setGroupMembers(data.members || []);
      }
    } catch (err) {
      console.error('Failed to fetch group members:', err);
      setGroupMembers([]);
    }
  };

  // Delete group
  const handleDelete = async () => {
    if (!selectedGroup) return;

    if (selectedGroup.is_system) {
      toast({
        title: 'Error',
        description: 'System groups cannot be deleted',
        variant: 'destructive',
      });
      return;
    }

    setActionLoading(true);
    try {
      await api.deleteGroup(selectedGroup.id);
      toast({ title: 'Group deleted', description: `${selectedGroup.name} has been deleted.` });
      setDeleteDialogOpen(false);
      setSelectedGroup(null);
      fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete group',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
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
        <p className="text-muted-foreground">Organize users into groups and assign roles</p>
        <Button
          onClick={handleOpenCreate}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Group
        </Button>
      </div>

      {/* Search and Table */}
      <Card className="border-0">
        <CardHeader>
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search groups..."
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
                <TableHead>Roles</TableHead>
                <TableHead>Members</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredGroups.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                    No groups found
                  </TableCell>
                </TableRow>
              ) : (
                filteredGroups.map((group) => (
                  <TableRow key={group.id}>
                    <TableCell className="font-medium text-foreground">
                      <div
                        className="flex items-center gap-2 cursor-pointer hover:text-primary transition-colors"
                        onClick={() => handleOpenEdit(group)}
                      >
                        {group.name}
                        {group.is_system && (
                          <Badge className="bg-primary/10 text-primary rounded-lg text-xs">
                            <Shield className="w-3 h-3 mr-1" />
                            System
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-xs truncate">
                      {group.description || '-'}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {group.roles.slice(0, 3).map((role) => (
                          <Badge
                            key={role.id}
                            variant="outline"
                            className="border-border text-foreground rounded-lg text-xs"
                          >
                            {role.name}
                          </Badge>
                        ))}
                        {group.roles.length > 3 && (
                          <Badge
                            variant="outline"
                            className="border-border text-muted-foreground rounded-lg text-xs"
                          >
                            +{group.roles.length - 3}
                          </Badge>
                        )}
                        {group.roles.length === 0 && (
                          <span className="text-muted-foreground text-sm">No roles</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleOpenMembers(group)}
                        className="text-foreground hover:text-primary"
                      >
                        <UserCircle className="w-4 h-4 mr-1" />
                        {group.member_count}
                      </Button>
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
                            onClick={() => handleOpenEdit(group)}
                            disabled={group.is_system}
                          >
                            <Pencil className="w-4 h-4 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleOpenDelete(group)}
                            className="text-destructive focus:text-destructive"
                            disabled={group.is_system}
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
            <AlertDialogTitle>Delete Group</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <span className="text-foreground font-medium">{selectedGroup?.name}</span>?
              Users in this group will not be deleted, but they will lose the roles assigned through this group.
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

      {/* Members Dialog (read-only) */}
      <Dialog open={membersDialogOpen} onOpenChange={setMembersDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {selectedGroup?.name} Members
            </DialogTitle>
            <DialogDescription>
              {groupMembers.length} member{groupMembers.length !== 1 ? 's' : ''} in this group
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {groupMembers.length === 0 ? (
              <p className="text-center text-muted-foreground py-4">No members in this group</p>
            ) : (
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {groupMembers.map((member) => (
                  <div
                    key={member.id}
                    className="flex items-center gap-3 p-2 rounded-lg bg-muted/50"
                  >
                    <div className="w-8 h-8 rounded-full bg-purple-500/20 flex items-center justify-center">
                      <UserCircle className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">{member.name}</p>
                      <p className="text-xs text-muted-foreground">{member.email}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setMembersDialogOpen(false)}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function GroupsPage() {
  return (
    <div className="p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-xl">
          <Users2 className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-foreground">Group Management</h1>
      </div>
      <GroupsContent />
    </div>
  );
}
