// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * UTC Date Utilities for NanoSIEM
 * 
 * All timestamps in NanoSIEM are stored and processed in UTC.
 * This module provides consistent UTC formatting across the application.
 */

import { formatDistanceToNow } from 'date-fns';
import { formatInTimeZone } from 'date-fns-tz';

/**
 * Format a date as UTC string for display
 * Example: "Dec 21, 2025, 14:30:45 UTC"
 */
export function formatUTC(date: Date | string | null | undefined): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return 'Invalid date';
  return formatInTimeZone(d, 'UTC', "MMM d, yyyy, HH:mm:ss 'UTC'");
}

/**
 * Format a date as short UTC string (no year)
 * Example: "Dec 21, 14:30:45 UTC"
 */
export function formatUTCShort(date: Date | string | null | undefined): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return 'Invalid date';
  return formatInTimeZone(d, 'UTC', "MMM d, HH:mm:ss 'UTC'");
}

/**
 * Format a date as compact UTC string (for tables/lists)
 * Example: "Dec 21, 14:30 UTC"
 */
export function formatUTCCompact(date: Date | string | null | undefined): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return 'Invalid date';
  return formatInTimeZone(d, 'UTC', "MMM d, HH:mm 'UTC'");
}

/**
 * Format a date as relative time with UTC context
 * Example: "5 minutes ago"
 */
export function formatRelativeUTC(date: Date | string | null | undefined): string {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return 'Invalid date';
  return formatDistanceToNow(d, { addSuffix: true });
}

/**
 * Format a date as compact relative time
 * Example: "5m ago", "2h ago", "3d ago"
 * Falls back to short date for older dates (>7 days)
 */
export function formatRelativeCompact(date: Date | string | null | undefined): string {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return '';

  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatInTimeZone(d, 'UTC', 'MMM d');
}

/**
 * Format a date for timeline/chart display (time only)
 * Example: "14:30"
 */
export function formatTimeUTC(date: Date | string | null | undefined): string {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return '';
  return formatInTimeZone(d, 'UTC', 'HH:mm');
}

/**
 * Format a date for timeline/chart display with adaptive format
 * - For ranges <= 2 hours: "HH:mm:ss" (e.g., "14:30:45")
 * - For ranges <= 24 hours: "HH:mm" (e.g., "14:30")
 * - For ranges > 24 hours: "MMM d HH:mm" (e.g., "Dec 21 14:00")
 */
export function formatTimelineLabel(date: Date | string | null | undefined, spansDays: boolean = false, showSeconds: boolean = false): string {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return '';
  
  if (spansDays) {
    return formatInTimeZone(d, 'UTC', 'MMM d HH:mm');
  }
  if (showSeconds) {
    return formatInTimeZone(d, 'UTC', 'HH:mm:ss');
  }
  return formatInTimeZone(d, 'UTC', 'HH:mm');
}

/**
 * Parse a timestamp string from the database as UTC
 * 
 * Database timestamps come in format "YYYY-MM-DD HH:MM:SS.ffffff" without timezone.
 * JavaScript's Date() interprets these as local time, which is incorrect.
 * This function ensures the timestamp is parsed as UTC.
 * 
 * @param timestamp - Timestamp string from database or ISO 8601 format
 * @returns Date object representing the UTC time
 */
export function parseUTCTimestamp(timestamp: string | null | undefined): Date {
  if (!timestamp) return new Date();
  
  // If it already has timezone info (Z or +/-), parse directly
  if (timestamp.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp);
  }
  
  // Database format: "YYYY-MM-DD HH:MM:SS.ffffff" - append Z to treat as UTC
  // Replace space with T for ISO 8601 compatibility and add Z suffix
  const isoString = timestamp.replace(' ', 'T') + 'Z';
  return new Date(isoString);
}

/**
 * Format number with locale-aware separators (for counts, not dates)
 */
export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '0';
  return value.toLocaleString();
}

/**
 * Format number in compact form (e.g., 200K, 1.5M, 50)
 */
export function formatCompactNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

/**
 * Build a 28-day rolling window of `{ date, value }` pairs (oldest first),
 * filling missing days with 0. Input is any array of `{ date, count }` where
 * `date` is an ISO yyyy-mm-dd string. Used by Prevalence + Risk row-level
 * activity sparklines.
 */
export function buildHeatmapDays(
  dailyCounts: { date: string; count: number }[] | undefined,
  windowDays = 28,
): { date: string; value: number }[] {
  const map = new Map<string, number>();
  if (dailyCounts) {
    for (const d of dailyCounts) map.set(d.date, d.count);
  }
  const days: { date: string; value: number }[] = [];
  const now = new Date();
  for (let i = windowDays - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const iso = d.toISOString().slice(0, 10);
    const label = `${d.getMonth() + 1}/${d.getDate()}`;
    days.push({ date: label, value: map.get(iso) ?? 0 });
  }
  return days;
}

/**
 * Expand a packed dense daily-counts array (oldest first, one entry per day
 * starting at `start`) into the `{date, count}[]` shape expected by
 * `buildHeatmapDays`. Used by Prevalence explorer items whose wire shape is
 * `daily_counts: number[]` + `daily_start: string` to halve network payload.
 */
export function expandPackedDaily(
  counts: number[] | undefined,
  start: string | undefined,
): { date: string; count: number }[] {
  if (!counts || !start || counts.length === 0) return [];
  // `start` is YYYY-MM-DD; treat as UTC midnight so day arithmetic is DST-safe.
  const base = new Date(`${start}T00:00:00Z`);
  if (Number.isNaN(base.getTime())) return [];
  const out: { date: string; count: number }[] = [];
  for (let i = 0; i < counts.length; i++) {
    const d = new Date(base);
    d.setUTCDate(d.getUTCDate() + i);
    out.push({ date: d.toISOString().slice(0, 10), count: counts[i] });
  }
  return out;
}

/**
 * Format bytes in human-readable format (B, KB, MB, GB, TB)
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
