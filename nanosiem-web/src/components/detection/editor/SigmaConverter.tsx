// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sigma Rule Converter Component
 *
 * Converts Sigma detection rules to nano format (YAML frontmatter + nPL query)
 * https://github.com/SigmaHQ/sigma
 */

import { useState, useMemo } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CircleAlert, CircleCheck, Copy, ArrowRight, FileCode, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import YAML from 'yaml';

interface SigmaConverterProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onApply?: (content: string) => void;
}

interface SigmaRule {
  title?: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  date?: string;
  modified?: string;
  references?: string[];
  tags?: string[];
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
  };
  detection?: Record<string, unknown>;
  falsepositives?: string[];
  level?: string;
  fields?: string[];
}

interface ConversionResult {
  success: boolean;
  output: string;
  warnings: string[];
  errors: string[];
}

// Common Sigma field to UDM field mappings
const FIELD_MAPPINGS: Record<string, string> = {
  // Process fields
  'Image': 'process_path',
  'OriginalFileName': 'process_name',
  'CommandLine': 'command_line',
  'ParentImage': 'parent_process_path',
  'ParentCommandLine': 'parent_command_line',
  'User': 'user',
  'ProcessId': 'process_id',
  'ParentProcessId': 'parent_process_id',
  'IntegrityLevel': 'integrity_level',
  'Hashes': 'process_hash',
  'md5': 'file_hash_md5',
  'sha1': 'file_hash_sha1',
  'sha256': 'file_hash_sha256',
  'imphash': 'file_hash_imphash',

  // Network fields
  'DestinationIp': 'dest_ip',
  'DestinationPort': 'dest_port',
  'DestinationHostname': 'dest_host',
  'SourceIp': 'src_ip',
  'SourcePort': 'src_port',
  'SourceHostname': 'src_host',
  'Protocol': 'protocol',

  // File fields
  'TargetFilename': 'file_path',
  'FileName': 'file_name',
  'FilePath': 'file_path',

  // Registry fields
  'TargetObject': 'registry_path',
  'Details': 'registry_value_data',
  'EventType': 'registry_action',

  // Authentication
  'LogonType': 'logon_type',
  'TargetUserName': 'dest_user',
  'TargetDomainName': 'dest_domain',
  'SubjectUserName': 'src_user',
  'SubjectDomainName': 'src_domain',
  'IpAddress': 'src_ip',
  'WorkstationName': 'src_host',
  'Status': 'status',

  // DNS
  'QueryName': 'dns_query',
  'QueryResults': 'dns_answers',
  'query': 'dns_query',

  // Web/Proxy
  'cs-uri-query': 'url',
  'c-uri': 'url',
  'cs-method': 'http_method',
  'cs-host': 'dest_host',
  'cs-User-Agent': 'http_user_agent',

  // Generic
  'EventID': 'event_id',
  'Channel': 'log_source',
  'Provider_Name': 'provider',
  'Computer': 'host',
  'ComputerName': 'host',
};

// Logsource to source_type mappings
const LOGSOURCE_MAPPINGS: Record<string, string> = {
  // Windows
  'windows_security': 'windows_security',
  'windows_system': 'windows_system',
  'windows_application': 'windows_application',
  'windows_sysmon': 'sysmon',
  'windows_powershell': 'powershell',
  'windows_powershell_classic': 'powershell',
  'windows_defender': 'defender',
  'windows_firewall': 'windows_firewall',
  'windows_dns': 'windows_dns',

  // Linux
  'linux_auth': 'linux_auth',
  'linux_syslog': 'syslog',
  'linux_audit': 'auditd',

  // Network
  'firewall': 'firewall',
  'proxy': 'proxy',
  'dns': 'dns',
  'webserver': 'webserver',

  // Cloud
  'aws_cloudtrail': 'cloudtrail',
  'azure_activitylogs': 'azure_activity',
  'gcp_audit': 'gcp_audit',
  'okta': 'okta',
  'm365': 'o365',

  // Endpoint
  'process_creation': 'process',
  'file_event': 'file',
  'network_connection': 'network',
  'registry_event': 'registry',
  'dns_query': 'dns',
  'image_load': 'image_load',
  'pipe_created': 'pipe',
};

function toSnakeCase(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
}

function mapField(field: string, unmappedFields?: Set<string>): string {
  const mapped = FIELD_MAPPINGS[field];
  if (mapped) {
    return mapped;
  }
  // Field not in our mapping - track it and convert to snake_case
  const converted = field.toLowerCase().replace(/[^a-z0-9_]/gi, '_');
  if (unmappedFields) {
    unmappedFields.add(`${field} → ${converted}`);
  }
  return converted;
}

function escapeValue(value: string): string {
  // Escape double quotes and backslashes
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function parseModifiers(fieldName: string): { baseName: string; modifiers: string[] } {
  const parts = fieldName.split('|');
  return {
    baseName: parts[0],
    modifiers: parts.slice(1),
  };
}

function convertValueWithModifiers(
  field: string,
  value: string | number | boolean,
  modifiers: string[],
  warnings: string[],
  unmappedFields?: Set<string>
): string {
  const mappedField = mapField(field, unmappedFields);
  let strValue = String(value);

  // Handle wildcards in value
  const hasStartWildcard = strValue.startsWith('*');
  const hasEndWildcard = strValue.endsWith('*') && !strValue.endsWith('\\*');

  // Remove wildcards for processing
  if (hasStartWildcard) strValue = strValue.slice(1);
  if (hasEndWildcard) strValue = strValue.slice(0, -1);

  // Check modifiers
  const hasContains = modifiers.includes('contains') || (hasStartWildcard && hasEndWildcard);
  const hasStartswith = modifiers.includes('startswith') || (!hasStartWildcard && hasEndWildcard);
  const hasEndswith = modifiers.includes('endswith') || (hasStartWildcard && !hasEndWildcard);
  const hasRe = modifiers.includes('re');
  const hasCidr = modifiers.includes('cidr');
  const hasCased = modifiers.includes('cased');
  const hasBase64 = modifiers.includes('base64') || modifiers.includes('base64offset');

  if (hasBase64) {
    warnings.push(`base64 modifier on "${field}" - may need manual adjustment`);
  }

  if (hasRe) {
    // Regex match
    const flags = hasCased ? '' : 'i';
    return `${mappedField} =~ /${escapeValue(strValue)}/${flags}`;
  }

  if (hasCidr) {
    return `cidrmatch(${mappedField}, "${escapeValue(strValue)}")`;
  }

  if (hasContains) {
    return `${mappedField} CONTAINS "${escapeValue(strValue)}"`;
  }

  if (hasStartswith) {
    return `${mappedField} STARTSWITH "${escapeValue(strValue)}"`;
  }

  if (hasEndswith) {
    return `${mappedField} ENDSWITH "${escapeValue(strValue)}"`;
  }

  // Handle remaining wildcards in value
  if (strValue.includes('*') || strValue.includes('?')) {
    // Convert to LIKE pattern
    const likePattern = strValue.replace(/\*/g, '%').replace(/\?/g, '_');
    return `${mappedField} LIKE "${escapeValue(likePattern)}"`;
  }

  // Simple equality
  if (typeof value === 'number') {
    return `${mappedField}=${value}`;
  }

  return `${mappedField}="${escapeValue(strValue)}"`;
}

function convertSelection(
  name: string,
  selection: unknown,
  warnings: string[],
  unmappedFields?: Set<string>
): { condition: string; isKeyword: boolean } {
  if (typeof selection === 'string') {
    // Keyword search
    return { condition: `"${escapeValue(selection)}"`, isKeyword: true };
  }

  if (Array.isArray(selection)) {
    // Array of keywords
    const keywords = selection.map(k => `"${escapeValue(String(k))}"`);
    return { condition: `(${keywords.join(' OR ')})`, isKeyword: true };
  }

  if (typeof selection !== 'object' || selection === null) {
    warnings.push(`Unknown selection format for "${name}"`);
    return { condition: '*', isKeyword: false };
  }

  // Object with field conditions
  const conditions: string[] = [];

  for (const [rawField, rawValue] of Object.entries(selection)) {
    const { baseName, modifiers } = parseModifiers(rawField);
    const hasAll = modifiers.includes('all');

    if (Array.isArray(rawValue)) {
      // Multiple values
      const valueConditions = rawValue.map(v =>
        convertValueWithModifiers(baseName, v, modifiers, warnings, unmappedFields)
      );

      if (hasAll) {
        // AND all values together
        conditions.push(`(${valueConditions.join(' AND ')})`);
      } else {
        // OR values together
        if (valueConditions.length === 1) {
          conditions.push(valueConditions[0]);
        } else {
          conditions.push(`(${valueConditions.join(' OR ')})`);
        }
      }
    } else if (rawValue !== null && rawValue !== undefined) {
      conditions.push(convertValueWithModifiers(baseName, rawValue as string | number | boolean, modifiers, warnings, unmappedFields));
    }
  }

  if (conditions.length === 0) {
    return { condition: '*', isKeyword: false };
  }

  if (conditions.length === 1) {
    return { condition: conditions[0], isKeyword: false };
  }

  // AND all field conditions together (standard Sigma behavior)
  return { condition: `(${conditions.join(' AND ')})`, isKeyword: false };
}

function parseCondition(
  condition: string,
  selections: Map<string, { condition: string; isKeyword: boolean }>,
  warnings: string[]
): string {
  let result = condition;

  const selectionNames = Array.from(selections.keys()).sort((a, b) => b.length - a.length);

  // IMPORTANT: Handle special patterns FIRST, before replacing individual selection names

  // Handle "1 of them" pattern
  result = result.replace(/\b1 of them\b/gi, () => {
    const conditions = Array.from(selections.values()).map(s => s.condition);
    return `(${conditions.join(' OR ')})`;
  });

  // Handle "all of them" pattern
  result = result.replace(/\ball of them\b/gi, () => {
    const conditions = Array.from(selections.values()).map(s => s.condition);
    return `(${conditions.join(' AND ')})`;
  });

  // Handle "1 of selection*" pattern (matches any selection starting with prefix)
  result = result.replace(/\b1 of (\w+)\*\b/gi, (_, prefix) => {
    const matchingSelections = selectionNames.filter(n => n.startsWith(prefix));
    if (matchingSelections.length === 0) {
      warnings.push(`No selections match pattern "${prefix}*"`);
      return 'false';
    }
    const conditions = matchingSelections.map(n => selections.get(n)?.condition || '*');
    return `(${conditions.join(' OR ')})`;
  });

  // Handle "all of selection*" pattern
  result = result.replace(/\ball of (\w+)\*\b/gi, (_, prefix) => {
    const matchingSelections = selectionNames.filter(n => n.startsWith(prefix));
    if (matchingSelections.length === 0) {
      warnings.push(`No selections match pattern "${prefix}*"`);
      return 'true';
    }
    const conditions = matchingSelections.map(n => selections.get(n)?.condition || '*');
    return `(${conditions.join(' AND ')})`;
  });

  // NOW replace remaining individual selection names with their conditions
  for (const name of selectionNames) {
    const sel = selections.get(name);
    if (sel) {
      const regex = new RegExp(`\\b${name}\\b`, 'g');
      result = result.replace(regex, sel.condition);
    }
  }

  // Convert logical operators
  result = result.replace(/\band\b/gi, 'AND');
  result = result.replace(/\bor\b/gi, 'OR');
  result = result.replace(/\bnot\b/gi, 'NOT');

  return result;
}

function convertSigmaRule(sigmaYaml: string, currentUser?: string): ConversionResult {
  const warnings: string[] = [];
  const errors: string[] = [];

  let rule: SigmaRule;

  try {
    rule = YAML.parse(sigmaYaml) as SigmaRule;
  } catch (e) {
    return {
      success: false,
      output: '',
      warnings: [],
      errors: [`Failed to parse YAML: ${(e as Error).message}`],
    };
  }

  if (!rule.detection) {
    return {
      success: false,
      output: '',
      warnings: [],
      errors: ['No detection section found in Sigma rule'],
    };
  }

  // Build the frontmatter
  const frontmatter: Record<string, unknown> = {};

  // Title (convert to snake_case)
  frontmatter.title = rule.title ? toSnakeCase(rule.title) : 'sigma_converted_rule';

  // Description (quoted)
  if (rule.description) {
    frontmatter.description = `"${rule.description.replace(/"/g, '\\"')}"`;
  }

  // Author - use current user, store original for comment
  const originalAuthor = rule.author;
  if (currentUser) {
    frontmatter.author = currentUser;
  }

  // Severity (map Sigma level)
  const levelMap: Record<string, string> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'low',
  };
  frontmatter.severity = levelMap[rule.level || 'medium'] || 'medium';

  // Mode defaults
  frontmatter.mode = 'staging';
  frontmatter.detection_mode = 'scheduled';
  frontmatter.schedule = '*/30 * * * * *';
  frontmatter.lookback = '15m';

  // Extract MITRE tags
  const mitreTactics: string[] = [];
  const mitreTechniques: string[] = [];
  const otherTags: string[] = [];

  if (rule.tags) {
    for (const tag of rule.tags) {
      if (tag.startsWith('attack.t')) {
        // Technique (e.g., attack.t1059.001 -> T1059.001)
        mitreTechniques.push(tag.replace('attack.', '').toUpperCase());
      } else if (tag.match(/^attack\.[\w-]+$/) && !tag.match(/^attack\.t\d/i)) {
        // Tactic name (e.g., attack.execution, attack.defense-evasion)
        // Map common tactic names to IDs
        const tacticMap: Record<string, string> = {
          'reconnaissance': 'TA0043',
          'resource_development': 'TA0042',
          'initial_access': 'TA0001',
          'execution': 'TA0002',
          'persistence': 'TA0003',
          'privilege_escalation': 'TA0004',
          'defense_evasion': 'TA0005',
          'credential_access': 'TA0006',
          'discovery': 'TA0007',
          'lateral_movement': 'TA0008',
          'collection': 'TA0009',
          'command_and_control': 'TA0011',
          'exfiltration': 'TA0010',
          'impact': 'TA0040',
        };
        const tacticName = tag.replace('attack.', '').replace(/-/g, '_');
        if (tacticMap[tacticName]) {
          mitreTactics.push(tacticMap[tacticName]);
        }
      } else if (!tag.startsWith('attack.') && !tag.startsWith('cve.') && !tag.startsWith('tlp.')) {
        otherTags.push(tag);
      }
    }
  }

  if (mitreTactics.length > 0) {
    frontmatter.mitre_tactics = `"${mitreTactics.join(', ')}"`;
  }
  if (mitreTechniques.length > 0) {
    frontmatter.mitre_techniques = `"${mitreTechniques.join(', ')}"`;
  }
  if (otherTags.length > 0) {
    frontmatter.tags = otherTags.join(', ');
  }

  // Build the query
  const queryParts: string[] = [];

  // Determine source_type from logsource
  if (rule.logsource) {
    const { category, product, service } = rule.logsource;
    let sourceType = '';

    // Try to find a mapping
    if (category) {
      sourceType = LOGSOURCE_MAPPINGS[category] || '';
    }
    if (!sourceType && product && service) {
      sourceType = LOGSOURCE_MAPPINGS[`${product}_${service}`] || '';
    }
    if (!sourceType && product) {
      sourceType = LOGSOURCE_MAPPINGS[product] || '';
    }

    if (sourceType) {
      queryParts.push(`source_type="${sourceType}"`);
    } else {
      // Generate a source_type from logsource components
      const parts = [product, service, category].filter(Boolean);
      if (parts.length > 0) {
        const generatedType = parts.join('_').toLowerCase().replace(/[^a-z0-9_]/g, '_');
        queryParts.push(`source_type="${generatedType}"`);
        warnings.push(`Generated source_type "${generatedType}" from logsource - verify this matches your data`);
      }
    }
  }

  // Process detection section
  const detection = rule.detection;
  const condition = detection.condition as string | undefined;

  if (!condition) {
    errors.push('No condition found in detection section');
    return { success: false, output: '', warnings, errors };
  }

  // Build selection map - track unmapped fields
  const selections = new Map<string, { condition: string; isKeyword: boolean }>();
  const unmappedFields = new Set<string>();

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition' || key === 'timeframe') continue;

    const converted = convertSelection(key, value, warnings, unmappedFields);
    selections.set(key, converted);
  }

  // Warn about unmapped fields that need manual review
  if (unmappedFields.size > 0) {
    warnings.push(`Unmapped fields (verify these match your UDM): ${Array.from(unmappedFields).join(', ')}`);
  }

  // Parse and convert the condition
  const queryCondition = parseCondition(condition, selections, warnings);

  // Combine source filter with detection logic
  // Only wrap in parens if not already wrapped and has multiple parts
  const needsParens = queryParts.length > 0 &&
    !queryCondition.startsWith('(') &&
    (queryCondition.includes(' OR ') || queryCondition.includes(' AND '));

  if (queryParts.length > 0) {
    queryParts.push(needsParens ? `(${queryCondition})` : queryCondition);
  } else {
    queryParts.push(queryCondition);
  }

  // Check for timeframe
  if (detection.timeframe) {
    warnings.push(`Timeframe "${detection.timeframe}" specified - may need to add aggregation with time window`);
  }

  // Build the final query - combine source filter and detection condition with space
  const query = queryParts.join(' ');

  // Add a basic stats command for aggregation-style rules
  if (rule.description?.toLowerCase().includes('count') ||
      rule.description?.toLowerCase().includes('multiple') ||
      rule.description?.toLowerCase().includes('brute')) {
    warnings.push('Consider adding aggregation (| stats count() by ...) based on detection intent');
  }

  // Build the output
  const frontmatterYaml = Object.entries(frontmatter)
    .map(([key, value]) => `${key}: ${typeof value === 'string' && value.includes('\n') ? `|\n  ${value.replace(/\n/g, '\n  ')}` : value}`)
    .join('\n');

  // Add original Sigma author as comment if available
  const authorComment = originalAuthor ? `// Sigma rule by: ${originalAuthor}\n` : '';

  const output = `---
${frontmatterYaml}
---

${authorComment}${query}`;

  return {
    success: true,
    output,
    warnings,
    errors,
  };
}

export function SigmaConverter({ open, onOpenChange, onApply }: SigmaConverterProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const [sigmaInput, setSigmaInput] = useState('');
  const [activeTab, setActiveTab] = useState<'input' | 'output'>('input');

  const conversionResult = useMemo(() => {
    if (!sigmaInput.trim()) {
      return null;
    }
    return convertSigmaRule(sigmaInput, user?.name);
  }, [sigmaInput, user?.name]);

  const handleConvert = () => {
    if (conversionResult?.success) {
      setActiveTab('output');
    }
  };

  const handleCopy = () => {
    if (conversionResult?.output) {
      navigator.clipboard.writeText(conversionResult.output);
      toast({ title: 'Copied to clipboard' });
    }
  };

  const handleApply = () => {
    if (conversionResult?.output && onApply) {
      onApply(conversionResult.output);
      onOpenChange(false);
      setSigmaInput('');
      setActiveTab('input');
    }
  };

  const handleClose = () => {
    onOpenChange(false);
    setSigmaInput('');
    setActiveTab('input');
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="bg-card border-border text-foreground rounded-2xl max-w-4xl h-[85vh] flex flex-col p-0">
        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
          <DialogTitle className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-blue-400" />
            Sigma Rule Converter
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Paste a Sigma rule to convert it to nano detection format.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'input' | 'output')} className="flex-1 flex flex-col overflow-hidden">
          <TabsList className="mx-6 mt-4 mb-2 w-fit">
            <TabsTrigger value="input" className="gap-2">
              <FileCode className="w-4 h-4" />
              Sigma Input
            </TabsTrigger>
            <TabsTrigger value="output" className="gap-2" disabled={!conversionResult?.success}>
              <ArrowRight className="w-4 h-4" />
              Converted Output
              {conversionResult?.success && (
                <Badge variant="outline" className="ml-1 text-xs border-green-500/30 text-green-400">Ready</Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="input" className="flex-1 overflow-hidden px-6 pb-4 mt-0">
            <div className="h-full flex flex-col gap-4">
              <Textarea
                value={sigmaInput}
                onChange={(e) => setSigmaInput(e.target.value)}
                placeholder={`Paste your Sigma rule here...

Example:
title: Suspicious PowerShell Encoded Command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
  condition: selection
level: medium`}
                className="flex-1 font-mono text-sm border-border rounded-xl resize-none"
              />

              {/* Conversion status */}
              {sigmaInput.trim() && (
                <div className="space-y-2">
                  {conversionResult?.success ? (
                    <div className="flex items-center gap-2 text-green-400">
                      <CircleCheck className="w-4 h-4" />
                      <span className="text-sm">Rule parsed successfully</span>
                    </div>
                  ) : conversionResult?.errors.length ? (
                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <div className="flex items-center gap-2 text-red-400 mb-2">
                        <CircleAlert className="w-4 h-4" />
                        <span className="text-sm font-medium">Conversion Errors</span>
                      </div>
                      <ul className="text-sm text-red-300 list-disc list-inside space-y-1">
                        {conversionResult.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  {conversionResult?.warnings.length ? (
                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                      <div className="flex items-center gap-2 text-yellow-400 mb-2">
                        <AlertTriangle className="w-4 h-4" />
                        <span className="text-sm font-medium">Warnings ({conversionResult.warnings.length})</span>
                      </div>
                      <ul className="text-sm text-yellow-700 dark:text-yellow-300 list-disc list-inside space-y-1">
                        {conversionResult.warnings.map((warn, i) => (
                          <li key={i}>{warn}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="output" className="flex-1 overflow-hidden px-6 pb-4 mt-0">
            <div className="h-full flex flex-col gap-4">
              <div className="flex-1 relative">
                <Textarea
                  value={conversionResult?.output || ''}
                  readOnly
                  className="h-full font-mono text-sm border-border rounded-xl resize-none text-green-400 bg-muted/30"
                />
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleCopy}
                  className="absolute top-2 right-2"
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>

              {conversionResult?.warnings.length ? (
                <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                  <div className="flex items-center gap-2 text-yellow-400 mb-2">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm font-medium">Review These Items</span>
                  </div>
                  <ul className="text-sm text-yellow-700 dark:text-yellow-300 list-disc list-inside space-y-1">
                    {conversionResult.warnings.map((warn, i) => (
                      <li key={i}>{warn}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </TabsContent>
        </Tabs>

        <div className="flex items-center justify-between px-6 py-4 border-t border-border flex-shrink-0">
          <Button variant="outline" onClick={handleClose} className="rounded-xl">
            Cancel
          </Button>
          <div className="flex items-center gap-2">
            {activeTab === 'input' ? (
              <Button
                onClick={handleConvert}
                disabled={!conversionResult?.success}
                className="bg-blue-600 hover:bg-blue-700 rounded-xl"
              >
                <ArrowRight className="w-4 h-4 mr-2" />
                View Converted Rule
              </Button>
            ) : (
              <>
                <Button variant="outline" onClick={handleCopy} className="rounded-xl">
                  <Copy className="w-4 h-4 mr-2" />
                  Copy
                </Button>
                {onApply && (
                  <Button onClick={handleApply} className="bg-blue-600 hover:bg-blue-700 rounded-xl">
                    <ArrowRight className="w-4 h-4 mr-2" />
                    Apply to Editor
                  </Button>
                )}
              </>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Export the conversion function for use elsewhere
export { convertSigmaRule };
