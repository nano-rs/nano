// SPDX-License-Identifier: AGPL-3.0-or-later
// On-demand threat-intel enrichment: the event contract between "Enrich"
// actions (search results, prevalence, case entities, pivt `@enrich`) and the
// single EnrichSheet host mounted in the app shell. Not Cases-coupled: the
// sheet calls POST /api/threat-intel/lookup directly.

import type { ThreatIntelArtifactType } from '@/lib/api/threat-intel';

export const ENRICH_ARTIFACT_EVENT = 'nano:enrich-artifact' as const;

export interface EnrichArtifactDetail {
  artifact: string;
  /** Omit to let the server detect the type. */
  artifactType?: ThreatIntelArtifactType;
  /** `pivt` labels the result "On demand · pivt". */
  origin?: 'analyst' | 'pivt';
}

export function openEnrich(detail: EnrichArtifactDetail): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent<EnrichArtifactDetail>(ENRICH_ARTIFACT_EVENT, { detail }));
}

const HEX_HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/** Best-effort client-side type guess from the value alone. The server
    normalizes and validates again (and refuses internal IPs / names). */
export function detectArtifactType(value: string): ThreatIntelArtifactType | null {
  const v = value.trim();
  if (!v || v.length > 2048) return null;
  if (/^https?:\/\//i.test(v)) return 'url';
  if (HEX_HASH.test(v)) return 'hash';
  if (IPV4.test(v) || (v.includes(':') && /^[0-9a-f:.]+$/i.test(v))) return 'ip';
  if (DOMAIN.test(v)) return 'domain';
  return null;
}

/** Map a field / entity kind to a lookup type, falling back to the value. */
export function enrichTypeFor(kind: string | null | undefined, value: string): ThreatIntelArtifactType | null {
  const detected = detectArtifactType(value);
  switch ((kind ?? '').toLowerCase()) {
    case 'ip':
    case 'ip_address':
      return detected === 'ip' ? 'ip' : null;
    case 'hash':
    case 'file_hash':
    case 'process_hash':
    case 'hash_md5':
    case 'hash_sha256':
    case 'hash_unknown':
      return detected === 'hash' ? 'hash' : null;
    case 'url':
      return detected === 'url' ? 'url' : null;
    case 'domain':
    case 'subdomain':
    case 'hostname':
    case 'host':
      // Remote hostnames are domains; bare workstation names are not.
      return detected === 'domain' ? 'domain' : null;
    case 'user':
    case 'process':
    case 'identity':
    case 'ip_address_private':
      return null;
    default:
      return detected === 'hash' || detected === 'url' ? detected : null;
  }
}
