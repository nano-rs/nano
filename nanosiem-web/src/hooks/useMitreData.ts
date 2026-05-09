// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hook for fetching and caching MITRE ATT&CK data
 */

import { useState, useEffect } from 'react';
import { getAccessToken } from '@/lib/auth-token';

interface MitreTactic {
  id: string;
  name: string;
  short_name: string;
  description?: string;
  url?: string;
}

interface MitreTechnique {
  id: string;
  name: string;
  description?: string;
  url?: string;
  is_subtechnique: boolean;
  parent_id?: string;
  tactic_ids: string[];
  deprecated: boolean;
}

interface MitreDataResponse {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  last_sync?: {
    last_sync_at: string;
    version?: string;
    technique_count: number;
    tactic_count: number;
  };
}

// Cache the data in memory
let cachedData: MitreDataResponse | null = null;
let fetchPromise: Promise<MitreDataResponse> | null = null;

// Use the same API base URL as the rest of the app
const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

export function useMitreData() {
  const [data, setData] = useState<MitreDataResponse | null>(cachedData);
  const [loading, setLoading] = useState(!cachedData);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (cachedData) {
      setData(cachedData);
      setLoading(false);
      return;
    }

    // Deduplicate concurrent requests
    if (!fetchPromise) {
      const token = getAccessToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Use absolute URL like the rest of the app
      fetchPromise = fetch(`${API_BASE_URL}/api/mitre`, { headers })
        .then(async (response) => {
          if (!response.ok) {
            throw new Error(`Failed to fetch MITRE data: ${response.statusText}`);
          }
          const data = await response.json();
          // Only cache if we got actual data
          if (data.tactics?.length > 0 || data.techniques?.length > 0) {
            cachedData = data;
          }
          return data;
        })
        .finally(() => {
          fetchPromise = null;
        });
    }

    fetchPromise
      .then((response) => {
        setData(response);
        setLoading(false);
      })
      .catch((err) => {
        console.error('[useMitreData] Error:', err);
        setError(err.message || 'Failed to load MITRE data');
        setLoading(false);
        // Clear the cache on error so next mount will retry
        cachedData = null;
      });
  }, []);

  return { data, loading, error };
}

// Convert MITRE data to autocomplete options format
export function tacticsToOptions(tactics: MitreTactic[]) {
  return tactics.map(t => ({
    value: t.id,
    label: `${t.id} - ${t.name}`,
    description: t.description?.substring(0, 100) || '',
  }));
}

export function techniquesToOptions(techniques: MitreTechnique[]) {
  return techniques.map(t => ({
    value: t.id,
    label: `${t.id} - ${t.name}`,
    description: t.description?.substring(0, 100) || '',
  }));
}

// Coverage types and hook
import type { MitreCoverageResponse, CoverageFilters } from '@/components/mitre/types';

export function useMitreCoverage(filters: CoverageFilters) {
  const [data, setData] = useState<MitreCoverageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchCoverage = async () => {
      setLoading(true);
      setError(null);

      try {
        const token = getAccessToken();
        const headers: HeadersInit = {
          'Content-Type': 'application/json',
        };
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        // Build query params
        const params = new URLSearchParams();
        if (filters.severity.length > 0) {
          params.set('severity', filters.severity.join(','));
        }
        if (filters.mode.length > 0) {
          params.set('mode', filters.mode.join(','));
        }

        const url = `${API_BASE_URL}/api/mitre/coverage${params.toString() ? '?' + params.toString() : ''}`;
        const response = await fetch(url, { headers });

        if (!response.ok) {
          throw new Error(`Failed to fetch MITRE coverage: ${response.statusText}`);
        }

        const data = await response.json();
        setData(data);
      } catch (err) {
        console.error('[useMitreCoverage] Error:', err);
        setError(err instanceof Error ? err.message : 'Failed to load coverage data');
      } finally {
        setLoading(false);
      }
    };

    fetchCoverage();
  }, [filters.severity.join(','), filters.mode.join(',')]);

  return { data, loading, error };
}
