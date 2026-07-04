// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 linting integration for detection rules
 * Provides client-side validation + debounced backend validation
 */
import { Diagnostic, linter, lintGutter } from '@codemirror/lint';
import { Extension, Text } from '@codemirror/state';
import { EditorView } from '@codemirror/view';
import { api } from '@/lib/api';
import type { ValidateDetectionResult } from '@/lib/api/types';

// Required YAML fields
const REQUIRED_YAML_FIELDS = ['title', 'description', 'author', 'severity', 'mitre_tactics', 'mitre_techniques'];

// Valid field values
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const VALID_MODES = ['staging', 'live', 'alerting', 'paused'];
const VALID_DETECTION_MODES = ['realtime', 'scheduled'];

/**
 * Strip comments from query text for validation purposes
 * Handles both line comments (//) and block comments
 */
function stripComments(text: string): string {
  let result = '';
  let i = 0;
  let inString = false;

  while (i < text.length) {
    // Handle strings (don't strip inside strings)
    if (text[i] === '"' && (i === 0 || text[i - 1] !== '\\')) {
      inString = !inString;
      result += text[i];
      i++;
      continue;
    }

    if (inString) {
      result += text[i];
      i++;
      continue;
    }

    // Check for line comment
    if (text[i] === '/' && text[i + 1] === '/') {
      // Skip until end of line
      while (i < text.length && text[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Check for block comment
    if (text[i] === '/' && text[i + 1] === '*') {
      i += 2; // Skip /*
      // Skip until */
      while (i < text.length - 1 && !(text[i] === '*' && text[i + 1] === '/')) {
        i++;
      }
      i += 2; // Skip */
      continue;
    }

    result += text[i];
    i++;
  }

  return result;
}

/**
 * Parse YAML section and return field values
 */
function parseYamlSection(doc: Text): Map<string, { value: string; line: number }> {
  const fields = new Map<string, { value: string; line: number }>();
  const text = doc.toString();

  const yamlMatch = text.match(/^---\n([\s\S]*?)\n---/);
  if (!yamlMatch) return fields;

  const yamlLines = yamlMatch[1].split('\n');
  const lineOffset = 1; // Account for first ---

  for (let i = 0; i < yamlLines.length; i++) {
    const line = yamlLines[i];
    const match = line.match(/^(\w+):\s*(.*)$/);
    if (match) {
      fields.set(match[1], {
        value: match[2].trim(),
        line: lineOffset + i,
      });
    }
  }

  return fields;
}

/**
 * Get line position info for a line number
 */
function getLineRange(doc: Text, lineNumber: number): { from: number; to: number } {
  const line = doc.line(lineNumber + 1); // 1-indexed
  return { from: line.from, to: line.to };
}

/**
 * Client-side validation (runs immediately)
 */
function clientSideValidation(doc: Text): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const text = doc.toString();

  // Parse YAML fields
  const yamlFields = parseYamlSection(doc);

  // Check required fields (use warnings for empty/missing, not errors)
  for (const field of REQUIRED_YAML_FIELDS) {
    const fieldInfo = yamlFields.get(field);
    if (!fieldInfo || !fieldInfo.value) {
      // Find line where field should be or report at first line after ---
      if (fieldInfo) {
        const range = getLineRange(doc, fieldInfo.line);
        diagnostics.push({
          from: range.from,
          to: range.to,
          severity: 'warning',
          message: `Required field "${field}" is empty`,
        });
      } else {
        // Field not present at all
        const yamlStart = text.indexOf('---');
        if (yamlStart !== -1) {
          diagnostics.push({
            from: yamlStart,
            to: yamlStart + 3,
            severity: 'warning',
            message: `Required field "${field}" is missing`,
          });
        }
      }
    }
  }

  // Validate title format (snake_case)
  const titleField = yamlFields.get('title');
  if (titleField && titleField.value && !/^[a-z0-9_-]+$/.test(titleField.value)) {
    const range = getLineRange(doc, titleField.line);
    diagnostics.push({
      from: range.from,
      to: range.to,
      severity: 'error',
      message: 'Title must use snake_case (lowercase, numbers, underscores, hyphens only)',
    });
  }

  // Validate severity
  const severityField = yamlFields.get('severity');
  if (severityField && severityField.value && !VALID_SEVERITIES.includes(severityField.value)) {
    const range = getLineRange(doc, severityField.line);
    diagnostics.push({
      from: range.from,
      to: range.to,
      severity: 'error',
      message: `Invalid severity "${severityField.value}". Use: ${VALID_SEVERITIES.join(', ')}`,
    });
  }

  // Validate mode
  const modeField = yamlFields.get('mode');
  if (modeField && modeField.value && !VALID_MODES.includes(modeField.value)) {
    const range = getLineRange(doc, modeField.line);
    diagnostics.push({
      from: range.from,
      to: range.to,
      severity: 'error',
      message: `Invalid mode "${modeField.value}". Use: ${VALID_MODES.join(', ')}`,
    });
  }

  // Validate detection_mode
  const detectionModeField = yamlFields.get('detection_mode');
  if (detectionModeField && detectionModeField.value && !VALID_DETECTION_MODES.includes(detectionModeField.value)) {
    const range = getLineRange(doc, detectionModeField.line);
    diagnostics.push({
      from: range.from,
      to: range.to,
      severity: 'error',
      message: `Invalid detection_mode "${detectionModeField.value}". Use: ${VALID_DETECTION_MODES.join(', ')}`,
    });
  }

  // Check for unbalanced quotes in query section (strip comments first)
  const yamlEndIndex = text.indexOf('---', text.indexOf('---') + 3);
  if (yamlEndIndex !== -1) {
    const querySection = text.substring(yamlEndIndex + 3);
    // Strip comments before checking balance
    const strippedQuery = stripComments(querySection);

    let quoteCount = 0;
    let parenCount = 0;
    let inString = false;

    for (let i = 0; i < strippedQuery.length; i++) {
      const char = strippedQuery[i];

      if (char === '"') {
        // Count preceding backslashes - only odd count means the quote is escaped
        let backslashCount = 0;
        let j = i - 1;
        while (j >= 0 && strippedQuery[j] === '\\') {
          backslashCount++;
          j--;
        }
        if (backslashCount % 2 === 0) {
          inString = !inString;
          quoteCount++;
        }
      }

      if (!inString) {
        if (char === '(') parenCount++;
        if (char === ')') parenCount--;
      }
    }

    if (quoteCount % 2 !== 0) {
      const queryStart = yamlEndIndex + 3;
      diagnostics.push({
        from: queryStart,
        to: queryStart + Math.min(50, querySection.length),
        severity: 'error',
        message: 'Unbalanced quotes in query',
      });
    }

    if (parenCount !== 0) {
      const queryStart = yamlEndIndex + 3;
      diagnostics.push({
        from: queryStart,
        to: queryStart + Math.min(50, querySection.length),
        severity: 'error',
        message: `Unbalanced parentheses in query (${parenCount > 0 ? 'missing closing' : 'extra closing'})`,
      });
    }
  }

  return diagnostics;
}

/**
 * Extract query section from document (strips comments for backend validation)
 */
function extractQuery(text: string): string {
  const yamlMatch = text.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
  const query = yamlMatch ? yamlMatch[1] : text;
  // Strip comments before sending to backend
  return stripComments(query).trim();
}

/**
 * Extract detection mode from YAML
 */
function extractDetectionMode(text: string): string | undefined {
  const match = text.match(/^detection_mode:\s*(\w+)/m);
  return match ? match[1] : undefined;
}

// Store for backend validation results
let lastBackendResult: ValidateDetectionResult | null = null;
let lastValidatedCacheKey = '';
let validationRequestId = 0;
let isValidationStale = false; // Set true when doc changes, false when validation completes

/**
 * Shorten verbose backend messages for compact display
 */
function shortenInfoMessage(message: string): string {
  // Map common verbose messages to shorter versions
  if (message.includes('simple filter query will create a ClickHouse materialized view')) {
    return 'Creates MV for fast alerting';
  }
  if (message.includes('piped commands') && message.includes('not supported in real-time')) {
    return 'Pipes require scheduled mode';
  }
  if (message.includes('Auto-converted to scheduled')) {
    return 'Auto-switched to scheduled';
  }
  if (message.includes('keyword searches require full-text search')) {
    return 'Full-text search requires scheduled';
  }
  if (message.includes('Scheduled mode') && message.includes('cron schedule')) {
    return 'Runs on cron schedule';
  }
  if (message.includes('Real-time mode') && message.includes('materialized view')) {
    return 'Creates MV for real-time';
  }
  // Return original if no match (truncated if too long)
  return message.length > 40 ? message.substring(0, 37) + '...' : message;
}

/**
 * Backend validation (runs debounced)
 */
async function backendValidation(view: EditorView): Promise<Diagnostic[]> {
  const text = view.state.doc.toString();
  const query = extractQuery(text);
  const detectionMode = extractDetectionMode(text);

  // Skip if no query
  if (!query.trim()) {
    lastBackendResult = null;
    lastValidatedCacheKey = '';
    return [];
  }

  // Cache key includes both query and detection mode
  const cacheKey = `${detectionMode}:${query}`;

  // Skip if nothing has changed
  if (cacheKey === lastValidatedCacheKey && lastBackendResult) {
    isValidationStale = false;
    return mapBackendResultToDiagnostics(view, lastBackendResult);
  }

  // Track this request to handle race conditions
  const currentRequestId = ++validationRequestId;

  try {
    const result = await api.validateDetection(query, detectionMode);

    // Only update if this is still the latest request (handles race conditions)
    if (currentRequestId !== validationRequestId) {
      // A newer request was started, discard this result
      return [];
    }

    lastBackendResult = result;
    lastValidatedCacheKey = cacheKey;
    isValidationStale = false;

    return mapBackendResultToDiagnostics(view, result);
  } catch (error) {
    // Only show error if this is still the latest request
    if (currentRequestId !== validationRequestId) {
      return [];
    }

    // Handle API errors gracefully
    const errorMessage = error instanceof Error ? error.message : 'Validation failed';

    // Find query section start
    const text = view.state.doc.toString();
    const yamlEndIndex = text.indexOf('---', text.indexOf('---') + 3);
    const queryStart = yamlEndIndex !== -1 ? yamlEndIndex + 4 : 0;

    return [{
      from: queryStart,
      to: queryStart + Math.min(50, text.length - queryStart),
      severity: 'error',
      message: errorMessage,
    }];
  }
}

/**
 * Map backend validation result to CodeMirror diagnostics
 */
function mapBackendResultToDiagnostics(view: EditorView, result: ValidateDetectionResult): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const text = view.state.doc.toString();

  // Find query section start
  const yamlEndIndex = text.indexOf('---', text.indexOf('---') + 3);
  const queryStart = yamlEndIndex !== -1 ? yamlEndIndex + 4 : 0;
  const queryEnd = text.length;

  // Ensure errors is an array (backend might return null/undefined/string)
  const errors = Array.isArray(result.errors) ? result.errors :
    (result.errors ? [String(result.errors)] : []);

  // Add errors
  for (const error of errors) {
    let from = queryStart;
    let to = queryStart + 1;

    // Try to find line number in error message
    const lineMatch = error.match(/line (\d+)/i);
    const colMatch = error.match(/column (\d+)/i);

    // Try to extract problematic token from error (e.g., "Unexpected token '='" or "Unknown field 'foo'")
    const tokenMatch = error.match(/['"]([^'"]+)['"]/);
    const token = tokenMatch ? tokenMatch[1] : null;

    const queryText = text.substring(queryStart);
    const queryLines = queryText.split('\n');

    if (lineMatch) {
      const errorLine = parseInt(lineMatch[1], 10);
      let offset = queryStart;

      // Find the start of the error line
      for (let i = 0; i < errorLine - 1 && i < queryLines.length; i++) {
        offset += queryLines[i].length + 1;
      }

      const lineText = queryLines[errorLine - 1] || '';
      from = offset;

      if (colMatch) {
        // If we have column info, use it
        const col = parseInt(colMatch[1], 10) - 1;
        from = offset + Math.min(col, lineText.length);
        // Find the word/token at this position
        const afterCol = lineText.substring(col);
        const wordMatch = afterCol.match(/^(\S+)/);
        to = from + (wordMatch ? wordMatch[1].length : 1);
      } else if (token && lineText.includes(token)) {
        // Try to find the token on this line
        const tokenIndex = lineText.indexOf(token);
        from = offset + tokenIndex;
        to = from + token.length;
      } else {
        // Highlight the whole line (trimmed)
        const trimStart = lineText.length - lineText.trimStart().length;
        from = offset + trimStart;
        to = offset + lineText.trimEnd().length + trimStart;
      }
    } else if (token) {
      // No line number, but we have a token - search for it in the query
      const tokenIndex = queryText.indexOf(token);
      if (tokenIndex !== -1) {
        from = queryStart + tokenIndex;
        to = from + token.length;
      }
    } else {
      // Fallback: find first non-empty, non-comment line
      let offset = queryStart;
      for (const line of queryLines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*')) {
          const trimStart = line.length - line.trimStart().length;
          from = offset + trimStart;
          to = offset + line.trimEnd().length + trimStart;
          break;
        }
        offset += line.length + 1;
      }
    }

    diagnostics.push({
      from: Math.min(from, queryEnd),
      to: Math.min(Math.max(to, from + 1), queryEnd),
      severity: 'error',
      message: error,
    });
  }

  // Info messages (mode auto-correction, MV info) are shown in the UI header,
  // not as inline diagnostics. See ValidationState.info field.

  return diagnostics;
}

/**
 * Create client-side linter (runs on every change)
 */
export function clientLinter(): Extension {
  return linter((view) => {
    return clientSideValidation(view.state.doc);
  }, {
    delay: 300, // 300ms debounce for client-side
  });
}

/**
 * Create backend linter (runs debounced)
 */
export function backendLinter(): Extension {
  return linter(backendValidation, {
    delay: 500, // 500ms debounce for backend validation
  });
}

/**
 * Combined linting extension with gutter
 */
export function detectionLinter(): Extension {
  return [
    clientLinter(),
    backendLinter(),
    lintGutter(),
  ];
}

/**
 * Callback interface for validation state
 */
export interface ValidationState {
  valid: boolean;
  error?: string;
  warning?: string;
  info?: string;
  matchCount?: number;
  detectionMode?: 'realtime' | 'scheduled';
  createsMaterializedView?: boolean;
  /** NAN-1688: query shape qualifies for real-time mode, independent of the
   * requested mode. Drives the "switch to real-time" nudge on scheduled rules. */
  realtimeEligible?: boolean;
  realtimeEligibleReason?: string;
}

/**
 * Mark validation as stale (call when document changes)
 */
export function markValidationStale(): void {
  isValidationStale = true;
}

/**
 * Get current validation state from last backend result
 */
export function getValidationState(): ValidationState | null {
  // Return null if validation is stale (document changed since last validation)
  if (isValidationStale || !lastBackendResult) return null;

  // Determine info message (mode auto-correction or MV info)
  // Shorten verbose backend messages for display
  let info: string | undefined;
  if (lastBackendResult.warning) {
    info = shortenInfoMessage(lastBackendResult.warning);
  } else if (lastBackendResult.mode_reason && lastBackendResult.mode_reason !== 'User-selected mode') {
    // Don't show error-related mode reasons when query is actually valid
    const isErrorReason = lastBackendResult.mode_reason.toLowerCase().includes('error');
    if (!isErrorReason || !lastBackendResult.valid) {
      info = shortenInfoMessage(lastBackendResult.mode_reason);
    }
  }

  // Determine detection mode (backend returns 'real-time' with hyphen)
  const effectiveMode = lastBackendResult.effective_mode?.toLowerCase()?.trim()?.replace('-', '');
  let detectionMode: 'realtime' | 'scheduled' | undefined;

  if (effectiveMode === 'realtime' || effectiveMode === 'scheduled') {
    detectionMode = effectiveMode;
  } else if (lastBackendResult.valid) {
    // If valid but no explicit mode, infer from creates_materialized_view
    // MV = scheduled (piped queries), no MV = realtime (simple queries)
    detectionMode = lastBackendResult.creates_materialized_view ? 'scheduled' : 'realtime';
  }

  // Handle errors being undefined (backend sometimes returns undefined instead of [])
  const errors = lastBackendResult.errors || [];

  return {
    valid: lastBackendResult.valid,
    error: errors.length > 0 ? errors[0] : undefined,
    info,
    detectionMode,
    createsMaterializedView: lastBackendResult.creates_materialized_view,
    realtimeEligible: lastBackendResult.realtime_eligible,
    realtimeEligibleReason: lastBackendResult.realtime_eligible_reason,
  };
}

/**
 * Reset validation cache (call when switching rules)
 */
export function resetValidationCache(): void {
  lastBackendResult = null;
  lastValidatedCacheKey = '';
  validationRequestId++;
}

export default detectionLinter;
