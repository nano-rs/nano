// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * DashboardShareDialog
 *
 * Dialog for changing dashboard visibility and sharing with groups.
 * Supports three visibility levels:
 * - Private: Only the owner can view
 * - Group: Shared with specific groups
 * - Public: All users with dashboards:view permission can view
 */

import { useState, useEffect } from 'react';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Checkbox } from '@/components/ui/checkbox';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Shield,
  Loader2,
  Users,
  Globe,
  Lock,
  CircleAlert,
} from 'lucide-react';
import { api, GroupDetail, SharedGroup, DashboardVisibility, DashboardShareResult } from '@/lib/api';
import { cn } from '@/lib/utils';

interface DashboardShareDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dashboardId: string;
  dashboardName: string;
  currentVisibility: DashboardVisibility;
  currentSharedGroups: SharedGroup[];
  isOwner: boolean;
  /**
   * NAN-1719 (DSH42): admins can re-share dashboards they don't own (the backend
   * already supports admin re-share). When true, the editable dialog opens for a
   * non-owner instead of the view-only block. Optional so existing callers keep
   * the owner-only behavior.
   */
  isAdmin?: boolean;
  onShare: (result: DashboardShareResult) => void;
}

export function DashboardShareDialog({
  open,
  onOpenChange,
  dashboardId,
  dashboardName,
  currentVisibility,
  currentSharedGroups,
  isOwner,
  isAdmin,
  onShare,
}: DashboardShareDialogProps) {
  const [visibility, setVisibility] = useState<DashboardVisibility>(currentVisibility);
  const [selectedGroups, setSelectedGroups] = useState<string[]>(
    currentSharedGroups.map(g => g.id)
  );
  const [availableGroups, setAvailableGroups] = useState<GroupDetail[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [affectedUsers, setAffectedUsers] = useState<{ user_name: string; user_email: string }[]>([]);
  // DSH41: the share result is held here while the "users lost access" banner is
  // shown, and only handed to the parent (onShare) when the user dismisses.
  const [pendingResult, setPendingResult] = useState<DashboardShareResult | null>(null);

  // Reset state when dialog opens
  useEffect(() => {
    if (open) {
      setVisibility(currentVisibility);
      setSelectedGroups(currentSharedGroups.map(g => g.id));
      setError(null);
      setAffectedUsers([]);
      setPendingResult(null);
      loadGroups();
    }
  }, [open, currentVisibility, currentSharedGroups]);

  const loadGroups = async () => {
    setIsLoading(true);
    try {
      const response = await api.listGroups();
      setAvailableGroups(response.groups);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load groups');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGroupToggle = (groupId: string, checked: boolean) => {
    if (checked) {
      setSelectedGroups(prev => [...prev, groupId]);
    } else {
      setSelectedGroups(prev => prev.filter(id => id !== groupId));
    }
  };

  const handleSave = async () => {
    // Validate group selection for group visibility
    if (visibility === 'group' && selectedGroups.length === 0) {
      setError('Please select at least one group to share with');
      return;
    }

    setIsSaving(true);
    setError(null);

    try {
      const result = await api.dashboards.shareDashboard(dashboardId, {
        visibility,
        group_ids: visibility === 'group' ? selectedGroups : undefined,
      });

      // DSH41: if this share revoked access for some users, keep the sheet open
      // so the amber "users lost access" banner is actually visible — closing
      // synchronously unmounts before it can render. Hold the result and notify
      // the parent only when the user dismisses (Done). With no affected users,
      // notify + close immediately as before.
      if (result.users_who_lost_access.length > 0) {
        setAffectedUsers(result.users_who_lost_access);
        setPendingResult(result);
      } else {
        onShare(result);
        onOpenChange(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update sharing settings');
    } finally {
      setIsSaving(false);
    }
  };

  const hasChanges =
    visibility !== currentVisibility ||
    (visibility === 'group' &&
      JSON.stringify(selectedGroups.sort()) !==
        JSON.stringify(currentSharedGroups.map(g => g.id).sort()));

  // Header (shared across owner/non-owner) — redesign-density chrome
  const headerNode = (
    <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
      <Shield className="w-[13px] h-[13px] text-primary" />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
          Dashboard Permissions
        </div>
        <div className="text-[11px] text-muted-foreground mt-0.5 truncate">
          {dashboardName ? `Visibility for "${dashboardName}"` : 'Visibility settings'}
        </div>
      </div>
    </div>
  );

  // a11y-only SheetTitle/Description (visually hidden) so radix doesn't warn
  const a11yHeader = (
    <SheetHeader className="hidden">
      <SheetTitle>Dashboard Permissions</SheetTitle>
      <SheetDescription>Change visibility for {dashboardName}</SheetDescription>
    </SheetHeader>
  );

  // DSH42: owners edit their own dashboards; admins may re-share any dashboard.
  // Everyone else sees the view-only block.
  if (!isOwner && !isAdmin) {
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent
          side="right"
          className="w-[480px] max-w-[min(480px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
        >
          {headerNode}
          {a11yHeader}
          <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col items-center justify-center gap-2 text-center">
            <Lock className="w-8 h-8 text-muted-foreground/50" />
            <div className="text-[12.5px] text-foreground font-medium">View only</div>
            <div className="text-[11.5px] text-muted-foreground">
              Only the dashboard owner can change permissions.
            </div>
          </div>
          <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
            <Button variant="ghost" size="sm" className="h-[28px]" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[480px] max-w-[min(480px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        {headerNode}
        {a11yHeader}

        <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <>
              <div className="flex flex-col gap-1.5">
                <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                  Visibility
                </Label>
                <RadioGroup
                  value={visibility}
                  onValueChange={v => setVisibility(v as DashboardVisibility)}
                  className="flex flex-col gap-1.5"
                >
                  {[
                    { id: 'private' as DashboardVisibility, icon: Lock, iconClass: 'text-muted-foreground', label: 'Private', desc: 'Only you can view this dashboard.' },
                    { id: 'group' as DashboardVisibility, icon: Users, iconClass: 'text-sky-400', label: 'Share with groups', desc: 'Members of selected groups can view.' },
                    { id: 'public' as DashboardVisibility, icon: Globe, iconClass: 'text-emerald-400', label: 'Public', desc: 'All users with dashboard access can view.' },
                  ].map(opt => {
                    const Icon = opt.icon;
                    const selected = visibility === opt.id;
                    return (
                      <div
                        key={opt.id}
                        className={cn(
                          'flex items-center gap-2.5 px-3 py-2 rounded-md border cursor-pointer transition-colors',
                          selected
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/40 hover:bg-foreground/[0.03]',
                        )}
                        onClick={() => setVisibility(opt.id)}
                      >
                        <RadioGroupItem value={opt.id} id={opt.id} className="border-border" />
                        <Icon className={cn('w-[13px] h-[13px] shrink-0', opt.iconClass)} />
                        <div className="flex-1 min-w-0">
                          <Label
                            htmlFor={opt.id}
                            className="text-[12.5px] font-semibold text-foreground cursor-pointer"
                          >
                            {opt.label}
                          </Label>
                          <p className="text-[10.5px] text-muted-foreground leading-[1.35]">
                            {opt.desc}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </RadioGroup>
              </div>

              {visibility === 'group' && (
                <div className="flex flex-col gap-1.5">
                  <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                    Select groups
                  </Label>
                  <ScrollArea className="h-[180px] border border-border rounded-md">
                    {availableGroups.length === 0 ? (
                      <div className="p-3 text-center text-[11.5px] text-muted-foreground">
                        No groups available. Create groups in Settings to share dashboards.
                      </div>
                    ) : (
                      <div className="p-1.5 flex flex-col gap-0.5">
                        {availableGroups.map(group => {
                          const isSelected = selectedGroups.includes(group.id);
                          return (
                            <div
                              key={group.id}
                              className={cn(
                                'flex items-center gap-2 px-2 py-1.5 rounded-[3px] cursor-pointer transition-colors',
                                isSelected ? 'bg-primary/10' : 'hover:bg-foreground/[0.04]',
                              )}
                              onClick={() => handleGroupToggle(group.id, !isSelected)}
                            >
                              <Checkbox
                                checked={isSelected}
                                onCheckedChange={checked =>
                                  handleGroupToggle(group.id, checked as boolean)
                                }
                                className="border-border"
                              />
                              <Users className="w-[12px] h-[12px] text-muted-foreground shrink-0" />
                              <div className="flex-1 min-w-0">
                                <p className="text-[12px] font-semibold text-foreground truncate">
                                  {group.name}
                                </p>
                                {group.description && (
                                  <p className="text-[10.5px] text-muted-foreground truncate">
                                    {group.description}
                                  </p>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </ScrollArea>
                  {selectedGroups.length > 0 && (
                    <p className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
                      {selectedGroups.length} group{selectedGroups.length !== 1 ? 's' : ''} selected
                    </p>
                  )}
                </div>
              )}

              {affectedUsers.length > 0 && (
                <div className="rounded-md bg-amber-500/10 border border-amber-500/30 px-3 py-2 flex items-start gap-2">
                  <CircleAlert className="w-[13px] h-[13px] text-amber-500 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-semibold text-amber-400">Users lost access</p>
                    <p className="text-[10.5px] text-muted-foreground mt-0.5">
                      {affectedUsers.map(u => u.user_name).join(', ')}
                    </p>
                  </div>
                </div>
              )}

              {error && (
                <div className="rounded-md bg-rose-500/10 border border-rose-500/30 px-3 py-2 flex items-start gap-2">
                  <CircleAlert className="w-[13px] h-[13px] text-rose-400 shrink-0 mt-0.5" />
                  <p className="text-[11.5px] text-rose-400">{error}</p>
                </div>
              )}
            </>
          )}
        </div>

        <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
          {pendingResult ? (
            // DSH41: the share succeeded and revoked access — the banner above is
            // visible; dismiss explicitly, handing the result to the parent now.
            <Button
              size="sm"
              className="h-[28px]"
              onClick={() => {
                if (pendingResult) onShare(pendingResult);
                onOpenChange(false);
              }}
            >
              Done
            </Button>
          ) : (
            <>
              <Button variant="ghost" size="sm" className="h-[28px]" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                className="h-[28px] gap-1.5"
                onClick={handleSave}
                disabled={isSaving || !hasChanges || isLoading}
              >
                {isSaving ? (
                  <>
                    <Loader2 className="w-[12px] h-[12px] animate-spin" />
                    Saving…
                  </>
                ) : (
                  <>
                    <Shield className="w-[12px] h-[12px]" />
                    Save
                  </>
                )}
              </Button>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default DashboardShareDialog;
