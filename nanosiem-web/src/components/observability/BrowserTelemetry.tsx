// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';

/** Fixed page categories only: never send URLs, query strings or record IDs. */
export function browserPageCategory(path: string): string {
  if (path === '/') return 'home';
  const first = path.split('/')[1]?.toLowerCase();
  return ['search', 'observability', 'alerts', 'cases', 'rules', 'dashboards', 'settings'].includes(first)
    ? first : 'other';
}

/** The API's configured relay owns export and credentials; disabled by default. */
export function BrowserTelemetry() {
  const { isAuthenticated } = useAuth();
  const { pathname } = useLocation();
  useEffect(() => {
    if (!isAuthenticated) return;
    const timer = window.setTimeout(() => {
      void api.observability.recordBrowserPageview(browserPageCategory(pathname)).catch(() => {});
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [isAuthenticated, pathname]);
  return null;
}
