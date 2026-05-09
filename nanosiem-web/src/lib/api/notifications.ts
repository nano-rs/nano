// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  Notification,
  NotificationListResponse,
  UnreadCountResponse,
  MarkAllReadResponse,
} from './types';

export class NotificationsApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>
  ) {}

  async getNotifications(limit?: number, unreadOnly?: boolean): Promise<NotificationListResponse> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (unreadOnly) params.set('unread_only', 'true');
    const query = params.toString();
    return this.request(`/api/notifications${query ? `?${query}` : ''}`);
  }

  async getUnreadNotificationCount(): Promise<UnreadCountResponse> {
    return this.request('/api/notifications/unread-count');
  }

  async markNotificationRead(id: string): Promise<Notification> {
    const response = await this.request<{ notification: Notification }>(`/api/notifications/${id}/read`, {
      method: 'POST',
    });
    return response.notification;
  }

  async markAllNotificationsRead(): Promise<MarkAllReadResponse> {
    return this.request('/api/notifications/read-all', {
      method: 'POST',
    });
  }
}
