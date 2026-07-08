// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared formatters + health tone tables for the Observability surfaces
 * (NAN-1536). Ported from the design handoff's obs-data.jsx so the Services /
 * detail views render counts, durations, and percentages identically to the
 * mock — mono + tabular-nums everywhere per nano's density conventions.
 *
 * Note the design's `danger` health tone maps to the backend's `bad`; use
 * `toDesignHealth()` to translate the wire value before indexing HEALTH.
 */

import type { ServiceHealth } from '@/lib/api/observability';

/** Compact count: 1.2M / 3.4k / 128 / 4.2. */
export function fmtNum(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return '–';
  if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (Math.abs(v) >= 1e3) return (v / 1e3).toFixed(1) + 'k';
  if (Math.abs(v) >= 100) return String(Math.round(v));
  if (Math.abs(v) >= 10) return v.toFixed(0);
  return (Math.round(v * 10) / 10).toFixed(v % 1 === 0 ? 0 : 1);
}

/**
 * Request rate (req/s). Unlike fmtNum, this keeps SMALL nonzero rates visible
 * instead of flooring them to `0.0` — a low-traffic service (or a short burst
 * averaged over a wide time window) is genuinely a fraction of a req/s, and
 * showing `0.0` reads as "broken". Sub-0.01 collapses to `<0.01`.
 */
export function fmtRate(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return '–';
  if (v === 0) return '0';
  const a = Math.abs(v);
  if (a >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (a >= 1e3) return (v / 1e3).toFixed(1) + 'k';
  if (a >= 10) return v.toFixed(0);
  if (a >= 1) return v.toFixed(1);
  if (a >= 0.01) return v.toFixed(2);
  // Sub-0.01 but nonzero: keep the sign visible. A tiny negative rate must not
  // collapse to "<0.01" (which reads as a small POSITIVE value).
  return v > 0 ? '<0.01' : '>-0.01';
}

/** Duration in ms → `42.3ms` / `1.20s`. */
export function fmtMs(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return '–';
  return v >= 1000 ? (v / 1000).toFixed(2) + 's' : Math.round(v * 10) / 10 + 'ms';
}

/** Percentage value (already 0..100) → `0.42%` / `3.1%`. */
export function fmtPct(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return '–';
  return (v < 0.1 ? v.toFixed(2) : v.toFixed(1)) + '%';
}

/** Design health tone (the mock uses `danger`, the backend wire uses `bad`). */
export type DesignHealth = 'good' | 'warn' | 'danger';

/** Translate the backend `ServiceHealth` wire value to the design tone. */
export function toDesignHealth(h: ServiceHealth): DesignHealth {
  return h === 'bad' ? 'danger' : h;
}

interface HealthTone {
  dot: string;
  text: string;
  bg: string;
  label: string;
  /** Sort weight: worst (danger) first. */
  sev: number;
}

/** health → tailwind tone classes (1:1 with the design's HEALTH table). */
export const HEALTH: Record<DesignHealth, HealthTone> = {
  danger: { dot: 'bg-danger', text: 'text-danger', bg: 'bg-danger/12 border-danger/30', label: 'Critical', sev: 0 },
  warn: { dot: 'bg-warn', text: 'text-warn', bg: 'bg-warn/12 border-warn/30', label: 'Degraded', sev: 1 },
  good: { dot: 'bg-good', text: 'text-good', bg: 'bg-good/10 border-good/30', label: 'Healthy', sev: 2 },
};
