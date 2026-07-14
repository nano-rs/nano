import { useEffect, useState } from 'react';

import { api } from './ipc';
import type { SchemaProfile } from './types';

/**
 * The active schema profile decides how a row is shaped: the same login event is
 * `user` / `src_ip` under UDM and `actor.user.name` / `src_endpoint.ip` under
 * OCSF. Fetched once per session — it cannot change under a running server.
 */
export function useSchemaProfile(): SchemaProfile {
  const [profile, setProfile] = useState<SchemaProfile>({
    isOcsf: false,
    knownFields: new Set<string>(),
  });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const response = await api.schemaFields();
        if (cancelled) return;
        setProfile({
          isOcsf: response.schema === 'ocsf',
          knownFields: new Set(response.fields.map((field) => field.name)),
        });
      } catch {
        // Fall back to UDM shaping; the row still renders, just with fewer
        // fields recognized as "Core".
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return profile;
}

/** The chips under each event body — the fields an analyst triages on. */
export function keyChipSpecs(isOcsf: boolean): { label: string; field: string; accent?: boolean }[] {
  return isOcsf
    ? [
        { label: 'sourcetype', field: 'source_type' },
        { label: 'src_ip', field: 'src_endpoint.ip' },
        { label: 'dest_ip', field: 'dst_endpoint.ip' },
        { label: 'user', field: 'user.name' },
        { label: 'status', field: 'status' },
        { label: 'activity', field: 'activity', accent: true },
      ]
    : [
        { label: 'sourcetype', field: 'source_type' },
        { label: 'src_ip', field: 'src_ip' },
        { label: 'src_host', field: 'src_host' },
        { label: 'dest_ip', field: 'dest_ip' },
        { label: 'dest_host', field: 'dest_host' },
        { label: 'user', field: 'user' },
        { label: 'dest_user', field: 'dest_user' },
        { label: 'event_type', field: 'event_type', accent: true },
      ];
}

/** Arrays of scalars read as a comma list; nested structures stay JSON. */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) {
    if (value.every((item) => item === null || typeof item !== 'object')) {
      return value
        .filter((item) => item !== null && item !== undefined)
        .map(String)
        .join(', ');
    }
    return JSON.stringify(value, null, 2);
  }
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}
