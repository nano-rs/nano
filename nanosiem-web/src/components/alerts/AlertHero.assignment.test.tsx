// @vitest-environment jsdom

// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5314: an assigned alert rendered the raw user typeid and the Triage card
// still read "No triage actions yet". The card must show the assignee's name
// and the assigner, and the label helper must prefer the resolved name.

import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { AlertHero } from './AlertHero';
import { alertAssigneeLabel } from '@/lib/alert-assignee';
import { fromApiAlert } from '@/hooks/use-api';
import type { Alert } from '@/lib/api/types';

afterEach(cleanup);

const USER_ID = 'user_4cktwkrqtd8k5s0pvac1vgyjs3';

function apiAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'alert_299zv02wng9bevdbaefhyw7gmp',
    rule_id: 'rule_one',
    rule_name: 'powershell_encoded',
    severity: 'high',
    status: 'new',
    matched_events: [],
    created_at: '2026-11-12T00:00:00Z',
    ...overrides,
  } as Alert;
}

describe('alertAssigneeLabel', () => {
  it('prefers the server-resolved name over the typeid', () => {
    expect(alertAssigneeLabel({ assigned_to: USER_ID, assignee_name: 'Ada Analyst' })).toBe('Ada Analyst');
  });
  it('falls back to the raw value when unresolved', () => {
    expect(alertAssigneeLabel({ assigned_to: 'legacy-bob' })).toBe('legacy-bob');
  });
  it('is undefined when unassigned', () => {
    expect(alertAssigneeLabel({})).toBeUndefined();
  });
});

describe('AlertHero triage card', () => {
  function renderHero(a: Alert) {
    const v = fromApiAlert(a);
    render(
      <MemoryRouter>
        <AlertHero
          alert={{
            id: v.id,
            ruleId: v.ruleId,
            ruleName: v.ruleName,
            severity: v.severity,
            status: v.status as 'open' | 'acknowledged' | 'closed',
            matchedEventCount: v.matchedEventCount,
            matchedEvents: v.matchedEvents,
            timestamp: v.timestamp,
            acknowledgedAt: v.acknowledgedAt,
            acknowledgedBy: v.acknowledgedBy,
            assignee: v.assignee,
            assignedAt: v.assignedAt,
            assignedBy: v.assignedBy,
            closedAt: v.closedAt,
            closedBy: v.closedBy,
          }}
          rule={null}
          linkedNotebookCount={0}
        />
      </MemoryRouter>,
    );
  }

  it('shows the assignee name and assigner, not the typeid', () => {
    renderHero(
      apiAlert({
        assigned_to: USER_ID,
        assignee_name: 'Ada Analyst',
        assigned_by: 'lead@example.com',
        assigned_at: '2026-11-12T00:05:00Z',
      }),
    );
    expect(screen.getByText('Ada Analyst')).toBeTruthy();
    expect(screen.getByText('lead@example.com')).toBeTruthy();
    expect(screen.queryByText(USER_ID)).toBeNull();
    expect(screen.queryByText('No triage actions yet.')).toBeNull();
  });

  it('still says no triage actions for an untouched alert', () => {
    renderHero(apiAlert());
    expect(screen.getByText('No triage actions yet.')).toBeTruthy();
  });
});
