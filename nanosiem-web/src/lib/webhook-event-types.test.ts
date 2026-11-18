// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { BUILTIN_EVENT_TYPES, eventTypeLabel, eventTypeOptions } from './webhook-event-types';

describe('webhook event types', () => {
  it('labels built-ins as before and unknown names readably', () => {
    expect(eventTypeLabel('siem_alert')).toBe('SIEM alerts');
    expect(eventTypeLabel('hunt_escalation')).toBe('Hunt escalations');
    expect(eventTypeLabel('thing.changed')).toBe('Thing changed');
    expect(eventTypeLabel('reports')).toBe('Reports');
  });

  it('builds options from the server list, built-ins first, no duplicates, falling back to the built-ins', () => {
    expect(eventTypeOptions(null).map((o) => o.value)).toEqual(BUILTIN_EVENT_TYPES.map((o) => o.value));
    const opts = eventTypeOptions([
      { name: 'hunt_escalation', extension: true },
      { name: 'siem_alert', extension: false },
      { name: 'case', extension: false },
      { name: 'case', extension: false },
    ]);
    expect(opts).toEqual([
      { value: 'siem_alert', label: 'SIEM alerts', extension: false },
      { value: 'case', label: 'Cases', extension: false },
      { value: 'hunt_escalation', label: 'Hunt escalations', extension: true },
    ]);
  });
});
