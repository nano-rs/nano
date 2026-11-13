import { describe, it, expect } from 'vitest';
import { dashboardHasVariables } from './dashboard-first-run-hint';
import { EMPTY_BLANK_DASHBOARD_DRAFT } from '@/components/dashboard/BlankDashboardForm';

describe('dashboardHasVariables (NAN-5328)', () => {
  it('is false for a dashboard without variables', () => {
    expect(dashboardHasVariables(undefined)).toBe(false);
    expect(dashboardHasVariables([])).toBe(false);
    expect(dashboardHasVariables({})).toBe(false);
  });
  it('is true when variables exist', () => {
    expect(dashboardHasVariables([{ name: 'host' }])).toBe(true);
  });
});

describe('blank dashboard draft (NAN-5328)', () => {
  it('starts private', () => {
    expect(EMPTY_BLANK_DASHBOARD_DRAFT.visibility).toBe('private');
  });
});
