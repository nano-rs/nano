// SPDX-License-Identifier: AGPL-3.0-or-later

export const NOTIFICATIONS_VIEW_PERMISSION = 'notifications:view';

type HasPermission = (permission: string) => boolean;

export function canViewNotifications(hasPermission: HasPermission): boolean {
  return hasPermission(NOTIFICATIONS_VIEW_PERMISSION);
}

export function notificationCountQueryOptions<T>(
  enabled: boolean,
  queryFn: () => Promise<T>,
) {
  return {
    queryKey: ['notifications-count'] as const,
    queryFn,
    enabled,
    refetchInterval: enabled ? 30_000 : (false as const),
  };
}

export function notificationListQueryOptions<T>(
  enabled: boolean,
  queryFn: () => Promise<T>,
) {
  return {
    queryKey: ['notifications'] as const,
    queryFn,
    enabled,
  };
}
