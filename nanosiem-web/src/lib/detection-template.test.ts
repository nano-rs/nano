// NAN-5317: the new-rule template was UDM (`source_type`, `entity=user`) and
// declared `detection_mode: realtime` while its body carries a `| risk` pipe,
// which only scheduled rules can run.
import { describe, expect, it } from 'vitest';
import { createDetectionTemplate, parseDetectionMetadata } from './detection-metadata';

describe('createDetectionTemplate', () => {
  const tpl = createDetectionTemplate('analyst');

  it('uses OCSF field names, not UDM', () => {
    expect(tpl).toContain('metadata.log_source = "your_source"');
    expect(tpl).toContain('entity=actor.user.name');
    expect(tpl).not.toMatch(/\bsource_type\s*=/);
    expect(tpl).not.toMatch(/entity=user\b/);
  });

  it('declares a mode its own query can run in', () => {
    const { metadata, query } = parseDetectionMetadata(tpl);
    expect(query).toContain('|');
    expect(metadata.detection_mode).toBe('scheduled');
    expect(metadata.schedule).toBeTruthy();
  });
});
