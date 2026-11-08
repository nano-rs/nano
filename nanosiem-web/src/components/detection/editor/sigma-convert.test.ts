// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4903: Sigma conversion is profile-total and grammar-correct. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SIGMA_FIELD_MAPPINGS, SIGMA_OCSF_TARGETS, convertSigmaRule } from './sigma-convert';

const query = (output: string) => output.split('\n').filter((l) => l && !l.startsWith('//')).pop() as string;

const WIN_4688 = `
title: Suspicious cmd spawned by Office
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\\cmd.exe'
    ParentProcessName|endswith: '\\WINWORD.EXE'
    SubjectUserName: 'bob'
  condition: selection
level: high
`;

describe('Sigma field translation is total for OCSF', () => {
  it('every UDM target has an explicit OCSF entry (string or null)', () => {
    const missing = [...new Set(Object.values(SIGMA_FIELD_MAPPINGS))].filter((udm) => !(udm in SIGMA_OCSF_TARGETS));
    expect(missing).toEqual([]);
  });

  it('every non-null OCSF target is a promoted column or a documented event attribute', () => {
    const promotedPath = fileURLToPath(
      new URL('../../../../../nanosiem-core/docs/ocsf/events/promoted.json', import.meta.url),
    );
    const promoted = new Set(
      (JSON.parse(readFileSync(promotedPath, 'utf8')) as { ocsf_path: string }[]).map((e) => e.ocsf_path),
    );
    // OCSF 1.9 attributes that are valid but not promoted (resolve via the event tail).
    const eventAttributes = new Set(['process.integrity', 'connection_info.protocol_name', 'status_code']);
    const unknown = Object.values(SIGMA_OCSF_TARGETS).filter(
      (c): c is string => c !== null && !promoted.has(c) && !eventAttributes.has(c),
    );
    expect(unknown).toEqual([]);
  });
});

describe('Windows 4688 rule', () => {
  it('on OCSF targets metadata.event_code and OCSF process columns', () => {
    const r = convertSigmaRule(WIN_4688, 'ocsf');
    expect(r.errors).toEqual([]);
    expect(r.success).toBe(true);
    const q = query(r.output);
    expect(q).toContain('metadata.log_source="windows_security"');
    expect(q).toContain('metadata.event_code=4688');
    expect(q).toContain('process.file.path ENDSWITH "\\\\cmd.exe"');
    expect(q).toContain('actor.process.file.path ENDSWITH "\\\\WINWORD.EXE"');
    expect(q).toContain('actor.user.name="bob"');
    expect(q).not.toMatch(/\bevent_id\b|\bprocess_path\b|\bsrc_user\b/);
  });

  it('on UDM keeps the UDM columns', () => {
    const q = query(convertSigmaRule(WIN_4688, 'udm').output);
    expect(q).toContain('source_type="windows_security"');
    expect(q).toContain('event_id=4688');
    expect(q).toContain('process_path ENDSWITH "\\\\cmd.exe"');
  });
});

describe('fields with no OCSF equivalent fail the OCSF conversion', () => {
  const rule = `
title: imphash
logsource: { category: image_load, product: windows }
detection:
  selection:
    imphash: 'abc'
    EventType: SetValue
  condition: selection
`;
  it('is unsuccessful and names the fields on OCSF', () => {
    const r = convertSigmaRule(rule, 'ocsf');
    expect(r.success).toBe(false);
    expect(r.errors.join(' ')).toMatch(/No OCSF equivalent for: .*imphash.*EventType/);
  });
  it('still converts on UDM', () => {
    expect(convertSigmaRule(rule, 'udm').success).toBe(true);
  });
});

describe('hash values', () => {
  it('reduces Sysmon ALGO=value to the value on OCSF only', () => {
    const rule = `
title: h
logsource: { category: process_creation, product: windows }
detection:
  selection:
    Hashes|contains: 'SHA256=ABCDEF'
  condition: selection
`;
    expect(query(convertSigmaRule(rule, 'ocsf').output)).toContain('process.file.hashes.value CONTAINS "ABCDEF"');
    expect(query(convertSigmaRule(rule, 'udm').output)).toContain('process_hash CONTAINS "SHA256=ABCDEF"');
  });
});

describe('nPL serialization (not YAML escaping)', () => {
  const rule = `
title: Encoded PowerShell
description: 'Runs "powershell" with \\ paths'
logsource: { category: process_creation, product: windows }
detection:
  selection:
    CommandLine|contains: 'powershell -Command "Get-Process"'
  keywords:
    - 'C:\\\\Users\\\\Public'
  re_sel:
    CommandLine|re: 'cmd\\.exe /c "[a-z]+"'
  condition: selection or keywords or re_sel
`;
  it('quoted command lines use a single-quoted nPL literal, never \\"', () => {
    const r = convertSigmaRule(rule, 'ocsf');
    expect(r.success).toBe(true);
    const q = query(r.output);
    expect(q).toContain(`process.cmd_line CONTAINS 'powershell -Command "Get-Process"'`);
    expect(q).not.toContain('\\"');
  });

  it('keywords double backslashes (nPL collapses \\\\ to \\)', () => {
    expect(query(convertSigmaRule(rule, 'ocsf').output)).toContain('"C:\\\\\\\\Users\\\\\\\\Public"');
  });

  it('|re emits an =~ string operand (no /…/ slash escaping)', () => {
    expect(query(convertSigmaRule(rule, 'ocsf').output)).toContain(`process.cmd_line =~ '(?i)cmd\\\\.exe /c "[a-z]+"'`);
  });

  it('a compound condition stays inside the log-source scope', () => {
    const q = query(convertSigmaRule(rule, 'ocsf').output);
    const prefix = 'metadata.log_source="process" (';
    expect(q.startsWith(prefix)).toBe(true);
    // The group opened after the source filter closes at the very end (quotes
    // skipped), so no OR leg escapes the scope.
    let depth = 0;
    let quote: string | null = null;
    let closedAt = -1;
    for (let i = prefix.length - 1; i < q.length; i++) {
      const c = q[i];
      if (quote) { if (c === quote) quote = null; continue; }
      if (c === '"' || c === "'") { quote = c; continue; }
      if (c === '(') depth++;
      if (c === ')' && --depth === 0) { closedAt = i; break; }
    }
    expect(closedAt).toBe(q.length - 1);
  });

  it('a condition that merely STARTS with a group is still wrapped', () => {
    const r = `
title: s
logsource: { category: process_creation, product: windows }
detection:
  a:
    Image|endswith: '\\a.exe'
    User: 'x'
  b:
    Image|endswith: '\\b.exe'
  condition: a or b
`;
    const q = query(convertSigmaRule(r, 'udm').output);
    expect(q).toMatch(/^source_type="process" \(\(.*\) OR .*\)$/);
  });

  it('YAML frontmatter still uses YAML escaping', () => {
    expect(convertSigmaRule(rule, 'ocsf').output).toContain('description: "Runs \\"powershell\\" with \\\\ paths"');
  });

  it('a value with both quote kinds is flagged, not silently altered', () => {
    const both = `
title: q
logsource: { product: windows }
detection:
  selection:
    CommandLine: 'echo "it''s"'
  condition: selection
`;
    const r = convertSigmaRule(both, 'udm');
    expect(r.success).toBe(false);
    expect(r.errors.join(' ')).toMatch(/cannot express/);
  });
});
