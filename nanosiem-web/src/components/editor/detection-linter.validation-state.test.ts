import { describe, expect, it } from 'vitest';
import { Text } from '@codemirror/state';
import { buildValidationState } from './detection-linter';
import type { ValidateDetectionResult } from '@/lib/api/types';

const ok = { valid: true, errors: [] } as unknown as ValidateDetectionResult;
const doc = (title: string, query = 'metadata.log_source = "edr"') =>
  Text.of(`---\ntitle: ${title}\nseverity: high\n---\n${query}`.split('\n'));

// NAN-5327
describe('buildValidationState', () => {
  it('is invalid and lists the frontmatter error when the backend query check passes', () => {
    const s = buildValidationState(ok, doc('de udm probe'));
    expect(s.valid).toBe(false);
    expect(s.error).toContain('Title must use snake_case');
  });

  it('stays valid for a clean frontmatter (missing-field warnings do not block)', () => {
    const s = buildValidationState(ok, doc('de_udm_probe'));
    expect(s.valid).toBe(true);
    expect(s.error).toBeUndefined();
  });

  it('lists every backend error, not just the first', () => {
    const res = {
      valid: false,
      errors: ["Unknown field 'actor.usr.name'", "Unknown field 'src_endpoint.ipp'"],
    } as unknown as ValidateDetectionResult;
    const s = buildValidationState(res, doc('x'));
    expect(s.error).toContain('actor.usr.name');
    expect(s.error).toContain('src_endpoint.ipp');
  });

  it('does not double-list query-body client checks', () => {
    const res = { valid: false, errors: ['Query syntax error: unbalanced'] } as unknown as ValidateDetectionResult;
    const s = buildValidationState(res, doc('x', 'a = "b'));
    expect(s.error).not.toContain('Unbalanced quotes');
  });
});
