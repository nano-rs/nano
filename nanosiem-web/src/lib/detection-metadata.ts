// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Detection rule metadata parser
 * 
 * Parses YAML frontmatter from detection queries:
 * ---
 * title: Rule Name
 * author: dan
 * severity: medium
 * mode: live
 * detection_mode: realtime
 * tags: auth, brute-force
 * risk_score: auto
 * risk_entity: auto-detect
 * ---
 * 
 * event.type = "login" AND auth_result = "failure"
 */

export interface DetectionMetadata {
  title?: string;
  description?: string;
  author?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  mode?: 'staging' | 'live' | 'alerting' | 'paused';
  detection_mode?: 'realtime' | 'scheduled';
  // NAN-1561: dataset this rule queries. 'logs' (default UDM/OCSF), 'spans', or
  // 'metrics'. Spans/metrics are scheduled-only — the editor forces scheduled
  // mode when this is set to a non-logs value.
  dataset?: 'logs' | 'spans' | 'metrics';
  schedule?: string;
  lookback?: string; // e.g., "24h", "1h", "30m"
  folder?: string; // organization folder: network, identity, endpoint, cloud, stash
  alert_mode?: 'grouped' | 'per_event'; // alert mode: grouped (default) or per_event (1:1 mapping)
  tags?: string;
  narrative?: string;
  mitre_tactics?: string;
  mitre_techniques?: string;
  reference_url?: string; // Reference URL for more info (e.g., Sigma rule source, threat intel)
  // NAN-453: playbook auto-attach shorthand. Encoded as:
  //   omitted / ""  — mode='none'
  //   "adaptive"    — Shadow Investigator composes on wrap
  //   "pb_<typeid>" — attach that specific library playbook at firing time
  // Decoded server-side into the two-column form: (playbook_selector_mode, playbook_id).
  playbook?: string;
  // NOTE: risk_score and risk_entity are now set in-query using the | risk command
  // Example: | risk score=50 entity=user weight=0.5
}

export interface ParsedDetection {
  metadata: DetectionMetadata;
  query: string;
}

const FRONTMATTER_REGEX = /^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/;

/**
 * Parse YAML frontmatter from a detection query
 */
export function parseDetectionMetadata(text: string): ParsedDetection {
  const match = text.match(FRONTMATTER_REGEX);
  
  if (!match) {
    // No frontmatter, return empty metadata
    return {
      metadata: {},
      query: text.trim(),
    };
  }
  
  const [, frontmatter, query] = match;
  const metadata: DetectionMetadata = {};
  
  // Parse simple YAML (key: value pairs)
  const lines = frontmatter.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) continue;
    
    const key = trimmed.substring(0, colonIndex).trim();
    let value = trimmed.substring(colonIndex + 1).trim();
    
    // Remove quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) || 
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    
    // Store in metadata
    (metadata as Record<string, string>)[key] = value;
  }
  
  return {
    metadata,
    query: query.trim(),
  };
}

/**
 * Serialize detection metadata and query into YAML frontmatter format
 */
export function serializeDetectionMetadata(metadata: DetectionMetadata, query: string): string {
  const lines: string[] = ['---'];
  
  // Add fields in a specific order for consistency
  // NOTE: risk_score and risk_entity removed - now set in-query using | risk command
  const orderedKeys: (keyof DetectionMetadata)[] = [
    'title',
    'description',
    'author',
    'severity',
    'mode',
    'detection_mode',
    'dataset',
    'schedule',
    'lookback',
    'folder',
    'alert_mode',
    'mitre_tactics',
    'mitre_techniques',
    'tags',
    'reference_url',
    'playbook',
  ];

  for (const key of orderedKeys) {
    const value = metadata[key];
    // Always include title, description, tags, and MITRE fields, even if empty (as placeholders for dropdowns)
    const alwaysInclude = ['title', 'description', 'tags', 'mitre_tactics', 'mitre_techniques', 'alert_mode', 'playbook'];
    if (alwaysInclude.includes(key) || (value !== undefined && value !== null && value !== '')) {
      // Quote strings that contain special characters or spaces
      const stringValue = String(value || '');
      const needsQuotes = stringValue.includes(':') ||
                         stringValue.includes('#') ||
                         stringValue.includes(',') ||
                         stringValue.includes('\n') ||
                         (key === 'description' && stringValue.length > 0);
      
      if (needsQuotes) {
        lines.push(`${key}: "${stringValue.replace(/"/g, '\\"')}"`);
      } else {
        lines.push(`${key}: ${stringValue}`);
      }
    }
  }
  
  lines.push('---');
  lines.push('');
  lines.push(query.trim());
  
  return lines.join('\n');
}

/**
 * NAN-453: encode (selectorMode, playbookId) into the YAML `playbook:` value.
 * Inverse of `decodePlaybookField`.
 */
export function encodePlaybookField(
  mode: 'none' | 'specific' | 'adaptive' | undefined,
  playbookId: string | null | undefined,
): string {
  if (mode === 'adaptive') return 'adaptive';
  if (mode === 'specific' && playbookId) return playbookId;
  return ''; // omitted — serializer drops empty values for the playbook key
}

/**
 * NAN-453: decode the YAML `playbook:` value into (selectorMode, playbookId).
 * Accepts the encoded forms written by `encodePlaybookField` plus author
 * typos — anything unrecognised degrades to mode='none' so a malformed YAML
 * can't silently pin a stale playbook.
 */
export function decodePlaybookField(raw: string | undefined | null): {
  mode: 'none' | 'specific' | 'adaptive';
  playbookId: string | null;
} {
  const s = (raw ?? '').trim();
  if (!s || s === 'none') return { mode: 'none', playbookId: null };
  if (s === 'adaptive') return { mode: 'adaptive', playbookId: null };
  if (/^pb_[0-9a-z]+$/i.test(s)) return { mode: 'specific', playbookId: s };
  return { mode: 'none', playbookId: null };
}

/**
 * Create a template for a new detection rule
 */
export function createDetectionTemplate(author: string = ''): string {
  const metadata: DetectionMetadata = {
    title: 'newrule',
    description: 'Describe what this detection identifies',
    author: author || 'Your Name',
    severity: 'medium',
    mode: 'staging',
    detection_mode: 'realtime',
    lookback: '15m',
    alert_mode: 'grouped',
    tags: 'tag1, tag2',
    mitre_tactics: 'TA0001',
    mitre_techniques: 'T1078',
  };

  // Template shows | risk command usage for dynamic risk scoring
  const query = `// Write your detection query here
source_type = "your_source"
| risk score=50 entity=user factor="Detection match"`;

  return serializeDetectionMetadata(metadata, query);
}

/**
 * Convert a string to snake_case format
 * Handles: "Brute Force Login", "brute-force-login", "BruteForceLogin" -> "brute_force_login"
 */
export function toSnakeCase(s: string): string {
  if (!s) return s;

  const trimmed = s.trim();

  // If already looks like valid snake_case, just normalize
  if (/^[a-z0-9_-]+$/.test(trimmed)) {
    return trimmed.replace(/-/g, '_');
  }

  // Convert from various formats
  let result = '';
  let prevWasSeparator = true;

  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];

    if (/[a-zA-Z0-9]/.test(c)) {
      // Insert underscore before uppercase if not at start and not after separator
      if (/[A-Z]/.test(c) && !prevWasSeparator && i > 0) {
        result += '_';
      }
      result += c.toLowerCase();
      prevWasSeparator = false;
    } else if (c === ' ' || c === '-' || c === '_') {
      if (!prevWasSeparator && result.length > 0) {
        result += '_';
      }
      prevWasSeparator = true;
    }
    // Skip other characters
  }

  // Clean up double underscores and trailing
  return result.replace(/__+/g, '_').replace(/^_|_$/g, '');
}

/**
 * Validate metadata fields
 */
/** Maximum lookback period in minutes (7 days) — must match backend MAX_LOOKBACK_MINUTES */
export const MAX_LOOKBACK_MINUTES = 10080;

export function validateMetadata(metadata: DetectionMetadata): string[] {
  const errors: string[] = [];
  
  if (metadata.title) {
    // Validate title format: no spaces, only lowercase letters, numbers, underscores, and hyphens
    if (!/^[a-z0-9_-]+$/.test(metadata.title)) {
      errors.push('title must use snake_case format (lowercase letters, numbers, underscores, and hyphens only - no spaces)');
    }
  }
  
  if (metadata.severity && !['critical', 'high', 'medium', 'low'].includes(metadata.severity)) {
    errors.push('severity must be one of: critical, high, medium, low');
  }
  
  if (metadata.mode && !['staging', 'live', 'alerting', 'paused'].includes(metadata.mode)) {
    errors.push('mode must be one of: staging, live, alerting, paused');
  }
  
  if (metadata.detection_mode && !['realtime', 'scheduled'].includes(metadata.detection_mode)) {
    errors.push('detection_mode must be one of: realtime, scheduled');
  }
  
  if (metadata.detection_mode === 'scheduled' && !metadata.schedule) {
    errors.push('schedule is required when detection_mode is scheduled');
  }

  // NAN-1561: dataset validation. Spans/metrics are scheduled-only.
  if (metadata.dataset && !['logs', 'spans', 'metrics'].includes(metadata.dataset)) {
    errors.push('dataset must be one of: logs, spans, metrics');
  }

  if (metadata.dataset && metadata.dataset !== 'logs' && metadata.detection_mode !== 'scheduled') {
    errors.push('spans/metrics datasets require detection_mode: scheduled');
  }

  if (metadata.lookback) {
    const lookbackMinutes = parseLookbackToMinutes(metadata.lookback);
    if (lookbackMinutes !== null && lookbackMinutes > MAX_LOOKBACK_MINUTES) {
      errors.push(`lookback cannot exceed 7 days (${MAX_LOOKBACK_MINUTES} minutes)`);
    }
  }

  return errors;
}

/**
 * Parse lookback duration string to minutes
 * Supports formats like: "24h", "1h", "30m", "1d"
 * Returns null if invalid or not provided
 */
export function parseLookbackToMinutes(lookback?: string): number | null {
  if (!lookback) return null;
  
  const match = lookback.match(/^(\d+)([smhd])$/i);
  if (!match) return null;
  
  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  
  switch (unit) {
    case 's': return Math.ceil(value / 60); // Convert seconds to minutes (round up)
    case 'm': return value;
    case 'h': return value * 60;
    case 'd': return value * 24 * 60;
    default: return null;
  }
}

/**
 * Format minutes to human-readable duration
 * e.g., 1440 -> "24h", 60 -> "1h", 30 -> "30m"
 */
export function formatMinutesToDuration(minutes: number): string {
  if (minutes >= 1440 && minutes % 1440 === 0) {
    return `${minutes / 1440}d`;
  }
  if (minutes >= 60 && minutes % 60 === 0) {
    return `${minutes / 60}h`;
  }
  return `${minutes}m`;
}
