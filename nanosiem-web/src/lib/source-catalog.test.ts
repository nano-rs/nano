// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-5264: the Add source wizard defaults a repository source's key to the parser's match value. */
import { describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/api', () => ({ api: {} }));

import { parserMatchValue, parserSlug } from './source-catalog';

const repoParser = (name: string | null, raw_content: string, file_path = `parsers-ocsf/${name ?? 'x'}/parser.yaml`) =>
  ({ name, file_path, raw_content });

describe('parserMatchValue', () => {
  it('uses the first YAML match value, not the parser name', () => {
    const sysmon = repoParser('windows_sysmon_ocsf', [
      'name: windows_sysmon_ocsf',
      'display_name: Microsoft Sysmon (OCSF)',
      'match_values:',
      '  - windows_sysmon',
      'parser_vrl: |',
      '  . = {}',
    ].join('\n'));
    expect(parserSlug(sysmon)).toBe('windows_sysmon_ocsf');
    expect(parserMatchValue(sysmon)).toBe('windows_sysmon');
  });

  it('takes the primary of several match values', () => {
    const apache = repoParser('apache_ocsf', 'name: apache_ocsf\nmatch_values: [apache_access, apache]\n');
    expect(parserMatchValue(apache)).toBe('apache_access');
  });

  it('skips a value the backend would drop and falls back to the name when none is usable', () => {
    expect(parserMatchValue(repoParser('p', 'match_values: ["bad value", ok_key]'))).toBe('ok_key');
    expect(parserMatchValue(repoParser('custom_parser', 'name: custom_parser\n'))).toBe('custom_parser');
    expect(parserMatchValue(repoParser('custom_parser', 'match_values: [": : not yaml'))).toBe('custom_parser');
    expect(parserMatchValue(repoParser(null, '', 'parsers/zeek_conn/parser.yaml'))).toBe('parser');
  });
});
