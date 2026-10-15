// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3512: the 80% / 100% AI allowance notices. */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { AiAllowanceNotice } from './AiAllowanceBanner';
import {
  AI_NOT_ENABLED_MESSAGE,
  aiAllowancePausedMessage,
  aiAllowanceState,
  nextAiAllowanceReset,
  RAISE_AI_URL,
} from '@/lib/ai-allowance';

const NOW = new Date('2026-10-10T15:00:00Z');

afterEach(cleanup);

describe('aiAllowanceState', () => {
  it('is ok when unlimited or under 80%', () => {
    expect(aiAllowanceState(10_000_000, null)).toBe('ok');
    expect(aiAllowanceState(0, 1000)).toBe('ok');
    expect(aiAllowanceState(799, 1000)).toBe('ok');
  });
  it('warns from 80% and pauses at 100%', () => {
    expect(aiAllowanceState(800, 1000)).toBe('warning');
    expect(aiAllowanceState(999, 1000)).toBe('warning');
    expect(aiAllowanceState(1000, 1000)).toBe('paused');
    expect(aiAllowanceState(1010, 1000)).toBe('paused');
  });
  it('treats a zero allowance (No AI, or an ended plan) as AI off, not a pause', () => {
    expect(aiAllowanceState(0, 0)).toBe('off');
    expect(aiAllowanceState(40, 0)).toBe('off');
  });
  it('raises AI on the lean plan page', () => {
    expect(new URL(RAISE_AI_URL).searchParams.get('lean')).toBe('1');
  });
});

describe('pause copy', () => {
  it('names the first day of the next UTC month', () => {
    expect(nextAiAllowanceReset(NOW).toISOString()).toBe('2026-11-01T00:00:00.000Z');
    expect(nextAiAllowanceReset(new Date('2026-12-31T23:59:59Z')).toISOString()).toBe('2027-01-01T00:00:00.000Z');
    expect(aiAllowancePausedMessage(NOW)).toBe(
      "You've used this month's AI allowance. AI features are paused until November 1, 2026 or until you raise your AI allowance. Search, detection and alerting keep running.",
    );
  });
});

describe('AiAllowanceNotice', () => {
  it('renders nothing when unlimited or under 80%', () => {
    const { container, rerender } = render(<AiAllowanceNotice used={50} limit={null} canRaise now={NOW} />);
    expect(container.innerHTML).toBe('');
    rerender(<AiAllowanceNotice used={50} limit={1000} canRaise now={NOW} />);
    expect(container.innerHTML).toBe('');
  });

  it('shows a dismissable 80% warning with counts', () => {
    render(<AiAllowanceNotice used={20_000} limit={25_000} canRaise now={NOW} />);
    const banner = screen.getByTestId('ai-allowance-banner');
    expect(banner.dataset.state).toBe('warning');
    expect(banner.textContent).toContain('20,000 / 25,000 (80%)');
    fireEvent.click(screen.getByLabelText('Dismiss AI allowance notice'));
    expect(screen.queryByTestId('ai-allowance-banner')).toBeNull();
  });

  it('shows the non-dismissable pause notice with a Raise AI link at 100%', () => {
    render(<AiAllowanceNotice used={25_000} limit={25_000} canRaise now={NOW} />);
    const banner = screen.getByTestId('ai-allowance-banner');
    expect(banner.dataset.state).toBe('paused');
    expect(banner.textContent).toContain(aiAllowancePausedMessage(NOW));
    expect(screen.getByRole('link', { name: 'Raise AI' }).getAttribute('href')).toBe(RAISE_AI_URL);
    expect(screen.queryByLabelText('Dismiss AI allowance notice')).toBeNull();
  });

  it('shows the AI-disabled notice (the server 403 text) for a zero allowance', () => {
    render(<AiAllowanceNotice used={0} limit={0} canRaise now={NOW} />);
    const banner = screen.getByTestId('ai-allowance-banner');
    expect(banner.dataset.state).toBe('off');
    expect(banner.textContent).toContain(AI_NOT_ENABLED_MESSAGE);
    expect(banner.textContent).not.toContain("You've used this month's AI allowance");
    expect(screen.getByRole('link', { name: 'Raise AI' }).getAttribute('href')).toBe(RAISE_AI_URL);
  });

  it('hides Raise AI where the portal cannot raise it', () => {
    render(<AiAllowanceNotice used={25_000} limit={25_000} canRaise={false} now={NOW} />);
    expect(screen.getByTestId('ai-allowance-banner').dataset.state).toBe('paused');
    expect(screen.queryByRole('link', { name: 'Raise AI' })).toBeNull();
  });
});
