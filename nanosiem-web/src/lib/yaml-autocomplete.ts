// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * YAML autocomplete for detection rule metadata
 * Provides suggestions for field values in YAML frontmatter
 */

export interface AutocompleteOption {
  value: string;
  label: string;
  description?: string;
}

export interface AutocompleteSuggestion {
  field: string;
  options: AutocompleteOption[];
  position: { line: number; column: number };
}

// Default MITRE ATT&CK Tactics (fallback if API not available)
const DEFAULT_MITRE_TACTICS: AutocompleteOption[] = [
  { value: 'TA0001', label: 'TA0001 - Initial Access', description: 'Techniques to gain initial foothold' },
  { value: 'TA0002', label: 'TA0002 - Execution', description: 'Techniques to run malicious code' },
  { value: 'TA0003', label: 'TA0003 - Persistence', description: 'Techniques to maintain presence' },
  { value: 'TA0004', label: 'TA0004 - Privilege Escalation', description: 'Techniques to gain higher permissions' },
  { value: 'TA0005', label: 'TA0005 - Defense Evasion', description: 'Techniques to avoid detection' },
  { value: 'TA0006', label: 'TA0006 - Credential Access', description: 'Techniques to steal credentials' },
  { value: 'TA0007', label: 'TA0007 - Discovery', description: 'Techniques to explore the environment' },
  { value: 'TA0008', label: 'TA0008 - Lateral Movement', description: 'Techniques to move through environment' },
  { value: 'TA0009', label: 'TA0009 - Collection', description: 'Techniques to gather data' },
  { value: 'TA0010', label: 'TA0010 - Exfiltration', description: 'Techniques to steal data' },
  { value: 'TA0011', label: 'TA0011 - Command and Control', description: 'Techniques to communicate with compromised systems' },
  { value: 'TA0040', label: 'TA0040 - Impact', description: 'Techniques to disrupt availability' },
  { value: 'TA0042', label: 'TA0042 - Resource Development', description: 'Techniques to establish resources' },
  { value: 'TA0043', label: 'TA0043 - Reconnaissance', description: 'Techniques to gather information' },
];

// Default MITRE ATT&CK Techniques (fallback - common subset)
const DEFAULT_MITRE_TECHNIQUES: AutocompleteOption[] = [
  { value: 'T1566', label: 'T1566 - Phishing', description: 'Spearphishing via email' },
  { value: 'T1190', label: 'T1190 - Exploit Public-Facing Application', description: 'Exploiting web apps' },
  { value: 'T1078', label: 'T1078 - Valid Accounts', description: 'Using legitimate credentials' },
  { value: 'T1059', label: 'T1059 - Command and Scripting Interpreter', description: 'PowerShell, cmd, bash' },
  { value: 'T1053', label: 'T1053 - Scheduled Task/Job', description: 'Scheduled tasks, cron' },
  { value: 'T1110', label: 'T1110 - Brute Force', description: 'Password guessing' },
  { value: 'T1003', label: 'T1003 - OS Credential Dumping', description: 'LSASS, SAM, etc.' },
  { value: 'T1021', label: 'T1021 - Remote Services', description: 'RDP, SSH, SMB' },
  { value: 'T1071', label: 'T1071 - Application Layer Protocol', description: 'HTTP, DNS C2' },
  { value: 'T1486', label: 'T1486 - Data Encrypted for Impact', description: 'Ransomware' },
];

// Dynamic MITRE options (populated from API)
let dynamicMitreTactics: AutocompleteOption[] | null = null;
let dynamicMitreTechniques: AutocompleteOption[] | null = null;

/**
 * Set MITRE tactics from API data
 */
export function setMitreTactics(tactics: AutocompleteOption[]) {
  dynamicMitreTactics = tactics;
}

/**
 * Set MITRE techniques from API data
 */
export function setMitreTechniques(techniques: AutocompleteOption[]) {
  dynamicMitreTechniques = techniques;
}

/**
 * Get current MITRE tactics (API data or fallback)
 */
export function getMitreTactics(): AutocompleteOption[] {
  return dynamicMitreTactics || DEFAULT_MITRE_TACTICS;
}

/**
 * Get current MITRE techniques (API data or fallback)
 */
export function getMitreTechniques(): AutocompleteOption[] {
  return dynamicMitreTechniques || DEFAULT_MITRE_TECHNIQUES;
}

// Static field options (non-MITRE fields)
const STATIC_FIELD_OPTIONS: Record<string, AutocompleteOption[]> = {
  severity: [
    { value: 'critical', label: 'Critical', description: 'Immediate action required' },
    { value: 'high', label: 'High', description: 'Urgent attention needed' },
    { value: 'medium', label: 'Medium', description: 'Standard priority' },
    { value: 'low', label: 'Low', description: 'Informational' },
  ],
  mode: [
    { value: 'staging', label: 'Staging', description: 'Development/testing - not executed' },
    { value: 'live', label: 'Live', description: 'Runs but does not create alerts' },
    { value: 'alerting', label: 'Alerting', description: 'Runs and creates alerts on matches' },
  ],
  detection_mode: [
    { value: 'realtime', label: 'Real-time', description: 'Fast detection (10-30s latency)' },
    { value: 'scheduled', label: 'Scheduled', description: 'Cron-based execution' },
  ],
  schedule: [
    { value: '*/30 * * * * *', label: 'Every 30 seconds', description: '6-field cron (with seconds)' },
    { value: '*/1 * * * *', label: 'Every 1 minute', description: 'Default schedule' },
    { value: '*/2 * * * *', label: 'Every 2 minutes', description: 'Light-frequency polling' },
    { value: '*/5 * * * *', label: 'Every 5 minutes', description: 'Standard detection interval' },
    { value: '*/10 * * * *', label: 'Every 10 minutes', description: 'Moderate-frequency polling' },
    { value: '*/15 * * * *', label: 'Every 15 minutes', description: 'Quarter-hour interval' },
    { value: '*/30 * * * *', label: 'Every 30 minutes', description: 'Half-hour interval' },
    { value: '0 * * * *', label: 'Every hour', description: 'Hourly execution' },
  ],
  // NOTE: risk_score and risk_entity are now set in-query using the | risk command
  // Example: | risk score=50 entity=user weight=0.5
  lookback: [
    { value: '15m', label: '15 minutes', description: 'Default lookback' },
    { value: '1h', label: '1 hour', description: 'Short-term analysis' },
    { value: '6h', label: '6 hours', description: 'Medium-term analysis' },
    { value: '24h', label: '24 hours', description: 'Daily analysis (for prevalence)' },
    { value: '7d', label: '7 days', description: 'Weekly analysis' },
  ],
};

/**
 * Get field options dynamically (uses API data for MITRE fields)
 */
function getFieldOptions(field: string): AutocompleteOption[] | undefined {
  if (field === 'mitre_tactics') {
    return getMitreTactics();
  }
  if (field === 'mitre_techniques') {
    return getMitreTechniques();
  }
  return STATIC_FIELD_OPTIONS[field];
}

/**
 * Get autocomplete suggestions for the current cursor position
 */
export function getAutocompleteSuggestions(
  text: string,
  cursorPosition: number
): AutocompleteSuggestion | null {
  // Find the line and column
  const lines = text.substring(0, cursorPosition).split('\n');
  const line = lines.length - 1;
  const column = lines[lines.length - 1].length;
  const currentLine = lines[line];
  
  // Check if we're in the YAML frontmatter (between --- markers)
  const beforeCursor = text.substring(0, cursorPosition);
  const frontmatterStart = beforeCursor.indexOf('---');
  const frontmatterEnd = beforeCursor.indexOf('---', frontmatterStart + 3);
  
  if (frontmatterStart === -1 || (frontmatterEnd !== -1 && frontmatterEnd < cursorPosition)) {
    return null; // Not in frontmatter
  }
  
  // Match pattern: "field: value" - cursor anywhere on the line
  const valueMatch = currentLine.match(/^(\w+):\s*(.*)$/);
  if (valueMatch) {
    const field = valueMatch[1];
    const options = getFieldOptions(field);
    if (options) {
      // If there's a current value and cursor is on/after it, show all options
      // This allows clicking on existing values to change them
      return { field, options, position: { line, column } };
    }
  }
  
  // Match pattern: "field: " or "field:" at the end of the line
  const fieldMatch = currentLine.match(/^(\w+):\s*$/);
  if (fieldMatch) {
    const field = fieldMatch[1];
    const options = getFieldOptions(field);
    if (options) {
      return { field, options, position: { line, column } };
    }
  }
  
  return null;
}

/**
 * Apply an autocomplete suggestion to the text
 */
export function applyAutocompleteSuggestion(
  text: string,
  cursorPosition: number,
  value: string
): { newText: string; newCursorPosition: number } {
  const lines = text.split('\n');
  const beforeCursor = text.substring(0, cursorPosition);
  const linesBefore = beforeCursor.split('\n');
  const lineIndex = linesBefore.length - 1;
  const currentLine = lines[lineIndex];
  
  // Replace the current line's value
  const colonIndex = currentLine.indexOf(':');
  if (colonIndex !== -1) {
    const newLine = currentLine.substring(0, colonIndex + 1) + ' ' + value;
    lines[lineIndex] = newLine;
    
    const newText = lines.join('\n');
    const newCursorPosition = beforeCursor.substring(0, beforeCursor.lastIndexOf('\n') + 1).length + newLine.length;
    
    return { newText, newCursorPosition };
  }
  
  return { newText: text, newCursorPosition: cursorPosition };
}
