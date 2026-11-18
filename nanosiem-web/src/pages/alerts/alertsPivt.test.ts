// NAN-5588: alert triage actions target only alerts the page shows, bind the
// targets once, and run through pivtApi (the analyst's session, marked pivt).
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { Alert } from '@/lib/api/types';

const mock = vi.hoisted(() => ({ ack: vi.fn(), close: vi.fn() }));
vi.mock('@/lib/api/pivt-api', () => ({
  pivtApi: { acknowledgeAlert: mock.ack, closeAlert: mock.close },
}));

import { alertActions, alertSummary, MAX_TARGETS, projectEvent } from './alertsPivt';

const alert = (id: string, over: Partial<Alert> = {}): Alert =>
  ({ id, rule_name: `rule ${id}`, severity: 'high', status: 'new', matched_events: [], created_at: '2026-11-17T12:00:00Z', ...over }) as Alert;

const visible = [alert('alrt_a'), alert('alrt_b'), alert('alrt_c')];

beforeEach(() => {
  vi.clearAllMocks();
  mock.ack.mockResolvedValue({});
  mock.close.mockResolvedValue({});
});

function spec(name: string, targets: Parameters<typeof alertActions>[0]) {
  const s = alertActions(targets).find((a) => a.name === name);
  if (!s) throw new Error(name);
  return s;
}

describe('alert triage actions', () => {
  it('need the alert permissions the REST routes enforce, and change state', () => {
    const [ack, close] = alertActions({ visible: () => visible });
    expect([ack.permission, ack.mutates]).toEqual(['alerts:acknowledge', true]);
    expect([close.permission, close.mutates]).toEqual(['alerts:close', true]);
  });

  it('target the selection, restricted to alerts on the page', () => {
    const s = spec('alerts.acknowledge', { visible: () => visible, selected: () => ['alrt_b', 'alrt_forged'] });
    expect(s.bind!({})).toEqual({ alert_ids: ['alrt_b'] });
  });

  it('refuse an alert id that is not on the page', () => {
    const s = spec('alerts.close', { visible: () => visible });
    expect(() => s.bind!({ alert_id: 'alrt_from_a_log_line', disposition: 'false_positive' })).toThrow(/not on this page/);
    expect(() => s.bind!({ disposition: 'false_positive' })).toThrow(/Select the alerts first/);
  });

  it('on the detail page, only the open alert can be targeted', () => {
    const s = spec('alerts.close', { visible: () => [visible[0]], fixed: () => visible[0] });
    expect(s.params.alert_id).toBeUndefined();
    expect(s.bind!({ disposition: 'benign' })).toEqual({ disposition: 'benign', alert_ids: ['alrt_a'] });
  });

  it('bound targets survive later page changes and run through pivtApi', async () => {
    let shown = visible;
    let sel = ['alrt_a', 'alrt_c'];
    const onChanged = vi.fn();
    const s = spec('alerts.close', { visible: () => shown, selected: () => sel, onChanged });
    const bound = s.bind!({ disposition: 'false_positive' });
    // The analyst changes the selection and the list refreshes after the card showed.
    sel = ['alrt_b'];
    shown = [alert('alrt_b')];
    const r = await s.run(bound);
    expect(mock.close.mock.calls.map((c) => c[0])).toEqual(['alrt_a', 'alrt_c']);
    expect(mock.close).toHaveBeenCalledWith('alrt_a', { disposition: 'false_positive' });
    expect(onChanged).toHaveBeenCalled();
    expect(r.summary).toBe('Closed 2 as false positive');
  });

  it('reports partial failure and fails when nothing changed', async () => {
    const s = spec('alerts.acknowledge', { visible: () => visible, selected: () => ['alrt_a', 'alrt_b'] });
    mock.ack.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error('403'));
    expect((await s.run(s.bind!({}))).summary).toBe('Acknowledged 1, 1 failed');
    mock.ack.mockRejectedValue(new Error('403'));
    await expect(s.run(s.bind!({}))).rejects.toThrow('No alert was acknowledged.');
  });

  it('previews every target with its state', async () => {
    const s = spec('alerts.close', { visible: () => visible, selected: () => ['alrt_a'] });
    const preview = await s.preview!(s.bind!({ disposition: 'true_positive' }));
    expect(preview.summary).toBe('Close 1 alert as true positive');
    expect(preview.rows).toEqual([['alrt_a', 'high · new · rule alrt_a']]);
  });

  it('summaries are compact and carry no raw events', () => {
    const s = alertSummary(alert('alrt_a', { matched_events: [{ big: 'x'.repeat(10_000) }], matched_event_count: 4 }));
    expect(s).toMatchObject({ id: 'alrt_a', events: 4 });
    expect(JSON.stringify(s).length).toBeLessThan(400);
  });

  it('offers no triage where the page offers none (Cases tenants, NAN-1066)', () => {
    expect(alertActions({ visible: () => visible }, { triageAllowed: false })).toEqual([]);
  });

  it('fits the alert state: no acknowledge once acknowledged, nothing once closed', () => {
    const names = (status: Alert['status']) =>
      alertActions({ visible: () => visible, fixed: () => visible[0] }, { triageAllowed: true, status }).map((a) => a.name);
    expect(names('new')).toEqual(['alerts.acknowledge', 'alerts.close']);
    expect(names('acknowledged')).toEqual(['alerts.close']);
    expect(names('closed')).toEqual([]);
  });

  it('refuses a selection larger than the cap, and the close takes no unsaved note', () => {
    const many = Array.from({ length: MAX_TARGETS + 1 }, (_, i) => alert(`alrt_${i}`));
    const s = spec('alerts.close', { visible: () => many, selected: () => many.map((a) => a.id) });
    expect(() => s.bind!({ disposition: 'benign' })).toThrow(/at most 25/);
    expect(s.params.notes).toBeUndefined();
  });

  it('matched events are projected to triage fields and trimmed', () => {
    const e = projectEvent({
      time: 1,
      src_endpoint: { ip: '10.0.0.1', hostname: 'h1' },
      actor: { user: { name: 'bob' } },
      unmapped: { huge: 'x'.repeat(5000) },
      message: 'm'.repeat(500),
    });
    expect(e).toMatchObject({ time: '1', 'src_endpoint.ip': '10.0.0.1', 'actor.user.name': 'bob', 'src_endpoint.hostname': 'h1' });
    expect(e.message.length).toBeLessThanOrEqual(201);
    expect(JSON.stringify(e)).not.toContain('xxxx');
  });
});
