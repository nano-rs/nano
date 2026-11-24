// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5774: an alert assigned to a deleted user read `user_5swm…`. The server
// now names it "deleted user"; the label never shows a raw user id.

import { describe, expect, it } from 'vitest';
import { alertAssigneeLabel, pickableAssignee } from './alert-assignee';
import { alertSummary } from '@/pages/alerts/alertsPivt';
import type { Alert } from '@/lib/api/types';

const USER_ID = 'user_5swmzx1tza89a9ftg3q1zedrk5';

describe('alertAssigneeLabel for a deleted assignee', () => {
  it('shows the server label "deleted user"', () => {
    expect(alertAssigneeLabel({ assigned_to: USER_ID, assignee_name: 'deleted user' })).toBe('deleted user');
  });
  it('never shows a raw user typeid or UUID the server could not name', () => {
    expect(alertAssigneeLabel({ assigned_to: USER_ID })).toBe('unknown user');
    expect(alertAssigneeLabel({ assigned_to: '0199a1b2-3c4d-7e5f-8a9b-0c1d2e3f4a5b' })).toBe('unknown user');
  });
  it('keeps a legacy free-text assignee as is', () => {
    expect(alertAssigneeLabel({ assigned_to: 'legacy-bob' })).toBe('legacy-bob');
  });
  it('pivt page context gets the label, not the id', () => {
    const a = { id: 'alert_x', severity: 'high', status: 'new', created_at: '', assigned_to: USER_ID } as unknown as Alert;
    expect(alertSummary(a).assignee).toBe('unknown user');
  });
});

describe('pickableAssignee (the /alerts assign dialog)', () => {
  const users = [{ id: 'user_01aaaaaaaaaaaaaaaaaaaaaaaa' }];
  it('never preselects or re-submits a deleted assignee', () => {
    expect(pickableAssignee(users, USER_ID)).toBe('');
    expect(pickableAssignee([], USER_ID)).toBe('');
  });
  it('keeps an active assignee', () => {
    expect(pickableAssignee(users, 'user_01aaaaaaaaaaaaaaaaaaaaaaaa')).toBe('user_01aaaaaaaaaaaaaaaaaaaaaaaa');
  });
});
