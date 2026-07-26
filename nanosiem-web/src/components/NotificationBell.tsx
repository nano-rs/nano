// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  Bell,
  BookOpen,
  CheckCheck,
  Loader2,
  MessageSquare,
  UserPlus,
  AlertTriangle,
  Info,
  ServerCrash,
  Database,
  Share2,
  CircleCheck,
  Clock,
  Search,
  XCircle,
  RefreshCw,
  FileText,
} from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  canViewNotifications,
  notificationCountQueryOptions,
  notificationListQueryOptions,
} from '@/components/notification-query-policy';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';
import { api, Notification, NotificationType } from '@/lib/api';

const NOTIFICATION_ICONS: Record<NotificationType, typeof Bell> = {
  case_mention: MessageSquare,
  case_assigned: UserPlus,
  case_status_change: AlertTriangle,
  case_shared: Share2,
  alert_assigned: AlertTriangle,
  ai_provider_down: ServerCrash,
  data_feed_stale: Database,
  search_access_removed: Info,
  case_access_removed: Info,
  system: Info,
  tuning_triggered: PivtIcon,
  tuning_validation_complete: CircleCheck,
  tuning_staging_deployed: Clock,
  tuning_promoted: CircleCheck,
  tuning_reverted: AlertTriangle,
  search_completed: Search,
  search_failed: XCircle,
  notebook_mention: BookOpen,
  // NAN-1793: a scheduled report finished — link points at the /reports list.
  report_ready: FileText,
  model_deprecated: RefreshCw,
};

// Tone bucket per notification kind. Drives the icon-tile colour so the
// row's purpose reads at a glance without leaning on the title text.
type Tone = 'attention' | 'warn' | 'danger' | 'good' | 'neutral';
const NOTIFICATION_TONE: Partial<Record<NotificationType, Tone>> = {
  case_status_change: 'warn',
  alert_assigned: 'danger',
  ai_provider_down: 'danger',
  data_feed_stale: 'warn',
  tuning_validation_complete: 'good',
  tuning_promoted: 'good',
  tuning_reverted: 'warn',
  search_completed: 'good',
  search_failed: 'danger',
  search_access_removed: 'warn',
  case_access_removed: 'warn',
  report_ready: 'good',
  model_deprecated: 'warn',
};

const TONE_TILE: Record<Tone, string> = {
  attention: 'bg-primary/15 text-primary',
  warn: 'bg-[color-mix(in_srgb,var(--warning)_15%,transparent)] text-[var(--warning)]',
  danger: 'bg-destructive/15 text-destructive',
  good: 'bg-[color-mix(in_srgb,var(--success)_15%,transparent)] text-[var(--success)]',
  neutral: 'bg-foreground/8 text-muted-foreground',
};

export function NotificationBell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const [open, setOpen] = useState(false);
  const canView = canViewNotifications(hasPermission);

  const { data: countData } = useQuery(
    notificationCountQueryOptions(canView, () => api.getUnreadNotificationCount()),
  );

  const { data: notificationsData, isLoading } = useQuery(
    notificationListQueryOptions(canView && open, () => api.getNotifications(20)),
  );

  const markReadMutation = useMutation({
    mutationFn: (id: string) => api.markNotificationRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications-count'] });
    },
  });

  const markAllReadMutation = useMutation({
    mutationFn: () => api.markAllNotificationsRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications-count'] });
    },
  });

  const handleNotificationClick = useCallback(
    (notification: Notification) => {
      if (!notification.read_at) {
        markReadMutation.mutate(notification.id);
      }
      if (notification.link) {
        setOpen(false);
        navigate(notification.link);
      }
    },
    [markReadMutation, navigate],
  );

  const unreadCount = countData?.count ?? 0;
  const notifications = notificationsData?.notifications ?? [];

  if (!canView) {
    return null;
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          className={cn(
            'relative w-7 h-7 rounded-md flex items-center justify-center transition-colors',
            'text-muted-foreground hover:text-foreground hover:bg-foreground/5',
            unreadCount > 0 && 'text-foreground',
          )}
          aria-label={
            unreadCount > 0 ? `${unreadCount} unread notifications` : 'Notifications'
          }
          type="button"
        >
          <Bell className="w-[14px] h-[14px]" />
          {unreadCount > 0 && (
            // NAN-917 F-23: show the count instead of a featureless dot.
            // The popover header already uses this exact treatment.
            <span className="absolute -top-1 -right-1 min-w-[16px] h-[14px] px-[3px] inline-flex items-center justify-center rounded-sm bg-primary text-primary-foreground text-[9px] font-mono tabular-nums leading-none">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        sideOffset={8}
        className="w-[360px] p-0 rounded-md border-border"
      >
        {/* Header */}
        <div className="px-3 py-2.5 border-b border-border flex items-center gap-2">
          <div className="flex flex-col min-w-0">
            <span className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
              Inbox
            </span>
            <span className="text-[12.5px] font-medium text-foreground leading-tight">
              Notifications
              {unreadCount > 0 && (
                <span className="ml-1.5 inline-flex items-center justify-center min-w-[18px] h-[16px] px-1 rounded-sm bg-primary/15 text-primary text-[10px] font-mono tabular-nums">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </span>
          </div>
          <span className="flex-1" />
          {unreadCount > 0 && (
            <button
              type="button"
              className="h-7 px-2 inline-flex items-center gap-1.5 rounded-md text-[11px] font-mono text-muted-foreground hover:text-foreground hover:bg-foreground/5 transition-colors disabled:opacity-50"
              onClick={() => markAllReadMutation.mutate()}
              disabled={markAllReadMutation.isPending}
            >
              {markAllReadMutation.isPending ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <CheckCheck className="w-3 h-3" />
              )}
              Mark all read
            </button>
          )}
        </div>

        {/* Body */}
        <ScrollArea className="h-[320px]">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
            </div>
          ) : notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <Bell className="w-5 h-5 text-muted-foreground/40" />
              <p className="text-[11.5px] font-mono text-muted-foreground">
                no notifications
              </p>
            </div>
          ) : (
            <div>
              {notifications.map((notification) => {
                const Icon = NOTIFICATION_ICONS[notification.notification_type] || Bell;
                const tone =
                  NOTIFICATION_TONE[notification.notification_type] ?? 'attention';
                const isUnread = !notification.read_at;

                return (
                  <button
                    key={notification.id}
                    onClick={() => handleNotificationClick(notification)}
                    className={cn(
                      'w-full text-left px-3 py-2.5 border-b border-border/60 last:border-b-0 transition-colors',
                      'hover:bg-foreground/[0.025]',
                      isUnread && 'bg-primary/[0.04]',
                    )}
                  >
                    <div className="flex gap-2.5">
                      <div
                        className={cn(
                          'shrink-0 w-7 h-7 rounded-md flex items-center justify-center',
                          isUnread ? TONE_TILE[tone] : TONE_TILE.neutral,
                        )}
                      >
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start gap-2">
                          <p
                            className={cn(
                              'text-[12px] leading-snug line-clamp-2 break-words flex-1',
                              isUnread ? 'text-foreground font-medium' : 'text-foreground/80',
                            )}
                          >
                            {notification.title}
                          </p>
                          {isUnread && (
                            <span className="shrink-0 mt-1 w-1.5 h-1.5 rounded-full bg-primary" />
                          )}
                        </div>
                        {notification.message && (
                          <p className="text-[11px] text-muted-foreground line-clamp-2 break-words mt-0.5 leading-snug">
                            {notification.message}
                          </p>
                        )}
                        <p className="text-[10.5px] font-mono text-muted-foreground/70 mt-1 tabular-nums">
                          {formatDistanceToNow(new Date(notification.created_at), {
                            addSuffix: true,
                          })}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </ScrollArea>
      </PopoverContent>
    </Popover>
  );
}

export default NotificationBell;
