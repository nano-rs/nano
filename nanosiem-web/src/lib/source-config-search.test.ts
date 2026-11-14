// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { readSearchFragment } from '@/lib/search-fragment';
import { sourceConfigSearchUrl } from '@/lib/source-config-search';

function queryOf(url: string): string | null {
  const [path, hash = ''] = url.split('#');
  expect(path).toBe('/search');
  return readSearchFragment('', hash ? `#${hash}` : '').get('q');
}

describe('sourceConfigSearchUrl', () => {
  it('filters on the OCSF routing key through the q fragment Search reads', () => {
    expect(queryOf(sourceConfigSearchUrl('metadata.log_source', ['windows_sysmon']))).toBe(
      'metadata.log_source="windows_sysmon"',
    );
  });

  it('ORs every distinct routing target', () => {
    expect(
      queryOf(sourceConfigSearchUrl('metadata.log_source', ['aws_cloudtrail', 'okta', 'aws_cloudtrail', ' '])),
    ).toBe('metadata.log_source IN ("aws_cloudtrail", "okta")');
  });

  it('uses the UDM routing key on a UDM deployment', () => {
    expect(queryOf(sourceConfigSearchUrl('source_type', ['apache_access']))).toBe('source_type="apache_access"');
  });

  it('keeps a hostile value inside its literal', () => {
    expect(queryOf(sourceConfigSearchUrl('metadata.log_source', ['a" OR x="1']))).toBe(
      `metadata.log_source='a" OR x="1'`,
    );
  });

  it('opens Search unfiltered when no rule routes anywhere', () => {
    expect(sourceConfigSearchUrl('metadata.log_source', [])).toBe('/search');
  });
});
