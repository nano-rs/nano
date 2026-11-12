// @vitest-environment jsdom

// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5300: alert-detail matched events carry OCSF columns as FLAT dotted keys
// (`"process.name"`). EventViewer used to walk every field as nested objects,
// so each such key resolved to undefined and was dropped from both the preview
// and the expanded field grid.

import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { EventViewer } from './EventViewer';
import { resolveEventPath } from './helpers';

vi.mock('@/hooks/useSchemaFieldMap', async () => {
  const { schemaFieldMap } = await import('@/lib/schema-fields');
  return {
    useSchemaFieldMap: () => ({
      ...schemaFieldMap('ocsf'),
      ready: true,
      unresolved: false,
      error: false,
      unresolvedReason: null,
      retry: () => {},
      guard: <A extends unknown[]>(fn: (...a: A) => void) => fn,
    }),
  };
});

describe('resolveEventPath', () => {
  it('resolves a flat dotted key', () => {
    expect(resolveEventPath({ 'process.name': 'powershell.exe' }, 'process.name')).toBe('powershell.exe');
  });
  it('resolves a nested path', () => {
    expect(resolveEventPath({ process: { name: 'cmd.exe' } }, 'process.name')).toBe('cmd.exe');
  });
  it('resolves a mixed flat/nested shape', () => {
    expect(resolveEventPath({ metadata: { 'product.name': 'Defender' } }, 'metadata.product.name')).toBe('Defender');
    expect(resolveEventPath({ 'actor.user': { name: 'eve' } }, 'actor.user.name')).toBe('eve');
  });
  it('returns undefined for a missing path', () => {
    expect(resolveEventPath({ 'process.name': 'x' }, 'process.pid')).toBeUndefined();
    expect(resolveEventPath({ process: 'x' }, 'process.name')).toBeUndefined();
  });
});

describe('EventViewer with flat OCSF keys', () => {
  const event = {
    id: 'ev1',
    timestamp: '2026-11-12T00:00:00Z',
    'process.name': 'powershell.exe',
    'process.cmd_line': 'powershell -enc AAAA',
    'actor.user.name': 'eve',
    'device.hostname': 'ws-042',
    'dst_endpoint.ip': '10.9.8.7',
    source_type: 'defender_edr',
  };

  it('shows OCSF fields in the preview and the expanded grid', () => {
    render(
      <EventViewer
        events={[event]}
        matchDetectedAt={new Date('2026-11-12T00:01:00Z')}
        hoveredId={null}
        onHover={() => {}}
      />,
    );
    // Preview resolves OCSF concepts instead of falling back to source_type.
    expect(screen.getByText('actor.user.name:')).toBeTruthy();
    expect(screen.getAllByText('eve').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('#1'));
    expect(screen.getAllByText('process.cmd_line:').length).toBeGreaterThan(0);
    expect(screen.getAllByText('powershell -enc AAAA').length).toBeGreaterThan(0);
    expect(screen.getAllByText('device.hostname:').length).toBeGreaterThan(0);
    expect(screen.getAllByText('ws-042').length).toBeGreaterThan(0);
  });
});
