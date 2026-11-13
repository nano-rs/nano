import { describe, expect, it } from 'vitest';
import { extractLogSource } from './saved-query-log-source';

// NAN-5326: saved queries are grouped by OCSF log source.
describe('extractLogSource', () => {
  it('reads metadata.log_source', () => {
    expect(extractLogSource('metadata.log_source="defender_edr" actor.user.name="x"')).toBe('defender_edr');
    expect(extractLogSource("metadata.log_source = 'okta' | stats count")).toBe('okta');
  });
  it('still reads the legacy spellings', () => {
    expect(extractLogSource('source_type=apache_access')).toBe('apache_access');
    expect(extractLogSource('sourcetype="sysmon"')).toBe('sysmon');
  });
  it('falls back to other', () => {
    expect(extractLogSource('actor.user.name="bob"')).toBe('other');
  });
});
