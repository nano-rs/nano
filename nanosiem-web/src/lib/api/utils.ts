// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * API utility functions and constants
 * Handles service URL routing for microservices architecture
 */

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';
const INGEST_URL = import.meta.env.VITE_INGEST_URL || API_BASE_URL;
const SEARCH_URL = import.meta.env.VITE_SEARCH_URL || API_BASE_URL;

/**
 * Get the appropriate base URL for a given API path
 * Routes to different services based on the endpoint
 */
export function getServiceUrl(path: string): string {
  // Ingest endpoints -> Ingest Service
  if (path.startsWith('/api/ingest')) {
    return INGEST_URL;
  }

  // Core search endpoints -> Search Service
  // Note: /api/search/history, /api/search/share, /api/search/shared, /api/search/explanation
  // stay on Main API (user-tied features)
  if (path === '/api/search' ||
      path === '/api/search/stream' ||
      path === '/api/search/sql' ||
      path === '/api/search/explain' ||
      path === '/api/search/log' ||
      path === '/api/search/field-stats' ||
      path === '/api/search/field-values' ||
      path === '/api/search/asset-events' ||
      path === '/api/search/asset-true-time-range' ||
      path === '/api/search/asset-artifacts' ||
      path.startsWith('/api/search/saved') ||
      path.startsWith('/api/search/jobs') ||
      path.startsWith('/api/search/admin')) {
    return SEARCH_URL;
  }

  // Everything else -> Main API
  return API_BASE_URL;
}

export { API_BASE_URL };
