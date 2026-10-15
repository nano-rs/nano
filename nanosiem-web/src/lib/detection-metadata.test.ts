// SPDX-License-Identifier: AGPL-3.0-or-later
/** Lean audit #2: the hosted-shared rule source round-trips and previews. */
import { describe, expect, it } from 'vitest';
import { deriveQuerySource, parseDetectionMetadata, serializeDetectionMetadata } from '@/lib/detection-metadata';

describe('rule source metadata', () => {
  it('round-trips the source key through the frontmatter', () => {
    const text = serializeDetectionMetadata({ title: 'r', source: 'conduit_proxy' }, 'class_uid=4002');
    expect(text).toContain('source: conduit_proxy');
    expect(parseDetectionMetadata(text).metadata.source).toBe('conduit_proxy');
  });

  it('omits an unset source', () => {
    expect(serializeDetectionMetadata({ title: 'r' }, 'x')).not.toContain('source:');
  });

  it('derives only an unambiguous query source', () => {
    expect(deriveQuerySource('metadata.log_source="conduit_proxy" | stats count')).toBe('conduit_proxy');
    expect(deriveQuerySource("metadata.log_source = 'Apache_Access'")).toBe('apache_access');
    expect(deriveQuerySource('class_uid=4002')).toBeNull();
    expect(deriveQuerySource('metadata.log_source="a" OR metadata.log_source="b"')).toBeNull();
  });
});
