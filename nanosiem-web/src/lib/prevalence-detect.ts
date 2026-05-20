// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Client-side artifact-type detection for the prevalence page's smart search
 * bar. Mirrors `ArtifactType::detect` in `nanosiem-core/src/prevalence/types.rs`
 * so the server and client agree on what counts as a hash / IP / domain.
 *
 * NAN-871.
 */

import type { PrevalenceArtifactType } from './api/types';

/** Detected artifact, ready to feed the lookup endpoints. */
export interface DetectedArtifact {
  /** Lowercased, trimmed canonical value. */
  value: string;
  /** Matches the server-side `PrevalenceArtifactType` wire format. */
  kind: PrevalenceArtifactType;
}

/**
 * Detect whether `input` is a recognizable single artifact.
 *
 * Returns `null` for empty input, free-text that doesn't fit any shape, or
 * partial input (e.g. half-typed hash). Callers route a `null` result back to
 * the free-text substring filter.
 */
export function detectArtifact(input: string): DetectedArtifact | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const lower = trimmed.toLowerCase();

  // Hash: 32 or 64 lowercase hex characters.
  if ((lower.length === 32 || lower.length === 64) && /^[0-9a-f]+$/.test(lower)) {
    return { value: lower, kind: lower.length === 32 ? 'hash_md5' : 'hash_sha256' };
  }

  // IP: covers v4 + v6. Private ranges flagged for the chip label. IPv6 is
  // lowercased to match the server's canonical storage form; IPv4 is
  // case-insensitive (decimal octets) so we preserve the user's input.
  const ipKind = detectIpKind(trimmed);
  if (ipKind) {
    const isIpv6 = trimmed.includes(':');
    return { value: isIpv6 ? trimmed.toLowerCase() : trimmed, kind: ipKind };
  }

  // Domain: per the server's `is_valid_domain` rules.
  if (isValidDomain(lower)) {
    const labels = lower.split('.');
    return { value: lower, kind: labels.length > 2 ? 'subdomain' : 'domain' };
  }

  return null;
}

/**
 * Pull multi-line paste into a list of detected artifacts.
 *
 * Returns only when ≥2 lines parse as valid artifacts — single-line input is
 * the lookup-mode case (use `detectArtifact` directly). Empty/whitespace lines
 * are skipped silently. Mixed lines (some valid, some not) return only the
 * valid ones; if fewer than 2 remain, returns `[]` so the caller can fall back
 * to free-text mode.
 */
export function detectBulkArtifacts(text: string): DetectedArtifact[] {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (lines.length < 2) return [];
  const detected: DetectedArtifact[] = [];
  for (const line of lines) {
    const d = detectArtifact(line);
    if (d) detected.push(d);
  }
  return detected.length >= 2 ? detected : [];
}

/**
 * Short human-facing label for the type chip. Matches the analyst lexicon
 * (`SHA256`, `MD5`, `IP`, `IP (private)`, `Domain`, `Subdomain`).
 */
export function artifactKindLabel(kind: PrevalenceArtifactType): string {
  switch (kind) {
    case 'hash_md5':
      return 'MD5';
    case 'hash_sha256':
      return 'SHA256';
    case 'hash_unknown':
      return 'Hash';
    case 'ip_address':
      return 'IP';
    case 'ip_address_private':
      return 'IP (private)';
    case 'domain':
      return 'Domain';
    case 'subdomain':
      return 'Subdomain';
  }
}

// --- internal -----------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Detect IP kind for `value`. Returns the typed kind on match, `null` otherwise.
 * IPv4 is case-insensitive (decimal); IPv6 hex digits may be mixed case in user
 * paste but are stored lowercase on the server, so the caller should lowercase
 * the canonical form of any IPv6 hit (see `detectArtifact`).
 */
function detectIpKind(value: string): PrevalenceArtifactType | null {
  const m = value.match(IPV4_RE);
  if (m) {
    const octets = m.slice(1, 5).map((s) => Number(s));
    if (octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      return isPrivateIpv4(octets) ? 'ip_address_private' : 'ip_address';
    }
    return null;
  }
  // IPv6 — accept anything URL accepts inside square brackets.
  if (value.includes(':')) {
    try {
      // `URL` is the simplest standards-compliant IPv6 parser available in
      // the browser; bracket-wrap to disambiguate from `host:port`.
      new URL(`http://[${value}]`);
      return isPrivateIpv6(value) ? 'ip_address_private' : 'ip_address';
    } catch {
      return null;
    }
  }
  return null;
}

function isPrivateIpv4(octets: number[]): boolean {
  const [a, b] = octets;
  // 10.0.0.0/8, 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local),
  // 172.16.0.0/12, 192.168.0.0/16 — matches `ArtifactType::is_private_ip`.
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIpv6(value: string): boolean {
  const lower = value.toLowerCase();
  // Loopback and unspecified.
  if (lower === '::1' || lower === '::') return true;
  // fc00::/7 (unique local) and fe80::/10 (link-local). String-prefix check is
  // sufficient for normalized inputs; we don't expand `::` because the chip
  // label is the only consumer and a false negative here just shows "IP".
  return /^fc[0-9a-f]{2}:/.test(lower) || /^fd[0-9a-f]{2}:/.test(lower) || /^fe[89ab][0-9a-f]:/.test(lower);
}

function isValidDomain(value: string): boolean {
  if (!value.includes('.')) return false;
  if (value.length > 253) return false;

  const parts = value.split('.');
  // Reject IPv4-shaped strings (already handled in `detectArtifact`, but the
  // server-side check is defensive about it too).
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) {
    return false;
  }

  const tld = parts[parts.length - 1];
  if (!tld || tld.length < 2) return false;
  if (/^\d+$/.test(tld)) return false;

  for (const label of parts) {
    if (!label) return false;
    if (label.length > 63) return false;
    if (!/^[a-z0-9]/.test(label) || !/[a-z0-9]$/.test(label)) return false;
    if (!/^[a-z0-9-]+$/.test(label)) return false;
  }

  return true;
}
