// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * TestResultRow — Reusable parsed output display with field-level diffing.
 *
 * Renders a collapsible row showing a raw log input and its parsed fields.
 * When a `currentParse` is provided, shows side-by-side comparison with
 * color-coded diff (green = added, red = removed, yellow = changed).
 */

import { CircleCheck, XCircle, ChevronRight, ChevronDown } from 'lucide-react';

interface TestResultRowProps {
  input: string;
  newParse: { success: boolean; output?: Record<string, unknown>; error?: string };
  currentParse?: { success: boolean; output?: Record<string, unknown>; error?: string };
  expanded: boolean;
  onToggle: () => void;
}

/** Extract flat field key-value pairs from parser output, flattening .udm and .ext */
export function extractFields(output: Record<string, unknown> | undefined): Record<string, string> {
  if (!output) return {};
  const fields: Record<string, string> = {};
  const udm = output.udm as Record<string, unknown> | undefined;
  const ext = output.ext as Record<string, unknown> | undefined;
  const source = udm || output;
  for (const [k, v] of Object.entries(source)) {
    if (v != null && typeof v !== 'object') {
      fields[k] = String(v);
    }
  }
  if (ext) {
    for (const [k, v] of Object.entries(ext)) {
      if (v != null && typeof v !== 'object') {
        fields[`ext.${k}`] = String(v);
      }
    }
  }
  return fields;
}

export function TestResultRow({ input, newParse, currentParse, expanded, onToggle }: TestResultRowProps) {
  const newFields = extractFields(newParse.output);
  const currentFields = extractFields(currentParse?.output);
  const allKeys = [...new Set([...Object.keys(newFields), ...Object.keys(currentFields)])].sort();

  return (
    <div className={`rounded-md border ${newParse.success ? 'border-border' : 'border-red-500/30'} bg-card`}>
      <button
        className="w-full flex items-center gap-2 px-3 py-2 text-left text-[11.5px] hover:bg-muted/30 rounded-md transition-colors"
        onClick={onToggle}
      >
        {newParse.success ? (
          <CircleCheck className="w-3.5 h-3.5 text-green-400 shrink-0" />
        ) : (
          <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
        )}
        <span className="font-mono text-[11px] text-muted-foreground truncate flex-1">
          {input.slice(0, 150)}{input.length > 150 ? '...' : ''}
        </span>
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-border/50">
          {newParse.error && (
            <p className="text-red-400 text-[11px] px-3 py-2">{newParse.error}</p>
          )}
          {allKeys.length > 0 && (
            <div className="overflow-auto max-h-80">
              <table className="w-full text-[11px]">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left px-3 py-1.5 text-muted-foreground font-medium w-1/4">Field</th>
                    {currentParse?.output && (
                      <th className="text-left px-3 py-1.5 text-muted-foreground font-medium w-[37.5%]">Current Parse</th>
                    )}
                    <th className="text-left px-3 py-1.5 text-muted-foreground font-medium w-[37.5%]">
                      {currentParse?.output ? 'New Parse' : 'Parsed Value'}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {allKeys.map(key => {
                    const curr = currentFields[key];
                    const next = newFields[key];
                    const isNew = !curr && next;
                    const isRemoved = curr && !next;
                    const isChanged = curr && next && curr !== next;

                    return (
                      <tr key={key} className={`border-b border-border/20 ${isNew ? 'bg-green-500/5' : isRemoved ? 'bg-red-500/5' : isChanged ? 'bg-yellow-500/5' : ''}`}>
                        <td className="px-3 py-1 font-mono text-muted-foreground">{key}</td>
                        {currentParse?.output && (
                          <td className={`px-3 py-1 font-mono ${isRemoved ? 'text-red-400' : 'text-foreground'}`}>
                            {curr || <span className="text-muted-foreground/30">—</span>}
                          </td>
                        )}
                        <td className={`px-3 py-1 font-mono ${isNew ? 'text-green-400' : isChanged ? 'text-yellow-400' : 'text-foreground'}`}>
                          {next || <span className="text-muted-foreground/30">—</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
