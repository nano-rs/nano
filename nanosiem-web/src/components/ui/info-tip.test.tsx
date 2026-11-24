// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-5796: InfoTip is the one shared help affordance. It must be a real,
// focusable button with an accessible name, open on keyboard focus and on
// tap, describe itself via aria-describedby, and never bubble clicks.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { InfoTip } from './info-tip';

afterEach(cleanup);

describe('InfoTip', () => {
  it('renders a button with an accessible name and a stroke-only icon', () => {
    render(<InfoTip label="About feed state">Feeds go stale after 7 days.</InfoTip>);
    const button = screen.getByRole('button', { name: 'About feed state' });
    expect(button.getAttribute('type')).toBe('button');
    const svg = button.querySelector('svg');
    expect(svg?.getAttribute('viewBox')).toBe('0 0 24 24');
    expect(svg?.getAttribute('stroke-width')).toBe('1.5');
    expect(svg?.getAttribute('fill')).toBe('none');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
    // Closed by default: the body is not in the document.
    expect(screen.queryByText('Feeds go stale after 7 days.')).toBeNull();
  });

  it('defaults the accessible name to "More info"', () => {
    render(<InfoTip>Body</InfoTip>);
    expect(screen.getByRole('button', { name: 'More info' })).toBeTruthy();
  });

  it('opens on keyboard focus and wires aria-describedby to the tooltip', async () => {
    const user = userEvent.setup();
    render(<InfoTip label="About hard expiry">Past its hard expiry a feed stops stamping.</InfoTip>);
    await user.tab();
    const button = screen.getByRole('button', { name: 'About hard expiry' });
    expect(document.activeElement).toBe(button);
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip.textContent).toContain('Past its hard expiry a feed stops stamping.');
    expect(button.getAttribute('aria-describedby')).toBe(tooltip.id);
  });

  it('closes on Escape', async () => {
    const user = userEvent.setup();
    render(<InfoTip label="Help">Body text</InfoTip>);
    await user.tab();
    await screen.findByRole('tooltip');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('toggles on tap (touch has no hover)', () => {
    render(<InfoTip label="Help">Tap body</InfoTip>);
    const button = screen.getByRole('button', { name: 'Help' });
    act(() => {
      fireEvent.pointerDown(button, { pointerType: 'touch' });
      fireEvent.click(button);
    });
    expect(screen.getByRole('tooltip').textContent).toContain('Tap body');
    act(() => {
      fireEvent.pointerDown(button, { pointerType: 'touch' });
      fireEvent.click(button);
    });
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('does not bubble clicks to a clickable parent', () => {
    const onParentClick = vi.fn();
    render(
      <div onClick={onParentClick}>
        <InfoTip label="Help">Body</InfoTip>
      </div>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    expect(onParentClick).not.toHaveBeenCalled();
  });

  it('keeps the accessible name to the label: the body is never repeated on the trigger', async () => {
    const user = userEvent.setup();
    render(<InfoTip label="About scopes">Scopes limit what a group can search.</InfoTip>);
    const button = screen.getByRole('button', { name: 'About scopes' });
    expect(button.textContent).toBe('');
    await user.tab();
    await screen.findByRole('tooltip');
    expect(button.getAttribute('aria-label')).toBe('About scopes');
  });

  describe('with a Learn more link (popover)', () => {
    const origin = window.location.origin;

    it('opens on Enter, puts the single link in the tab order, and Escape returns focus', async () => {
      const user = userEvent.setup();
      render(
        <InfoTip label="About scopes" learnMoreHref="https://docs.example.com/scopes">
          <span className="font-mono">source_type</span> scopes limit what a group can search.
        </InfoTip>,
      );
      const button = screen.getByRole('button', { name: 'About scopes' });
      await user.tab();
      expect(document.activeElement).toBe(button);
      // Focus alone does not open the popover.
      expect(screen.queryByRole('link')).toBeNull();
      await user.keyboard('{Enter}');
      const links = await screen.findAllByRole('link', { name: 'Learn more' });
      expect(links).toHaveLength(1);
      expect(links[0].getAttribute('href')).toBe('https://docs.example.com/scopes');
      expect(links[0].getAttribute('target')).toBe('_blank');
      expect(links[0].getAttribute('rel')).toBe('noopener noreferrer');
      expect(screen.getByText('source_type')).toBeTruthy();
      expect(button.getAttribute('aria-describedby')).toBeTruthy();
      expect(document.getElementById(button.getAttribute('aria-describedby')!)?.textContent).toContain(
        'scopes limit what a group can search.',
      );
      await user.tab();
      expect(document.activeElement).toBe(links[0]);
      await user.keyboard('{Escape}');
      expect(screen.queryByRole('link')).toBeNull();
      expect(document.activeElement).toBe(button);
    });

    it('does not bubble clicks from the trigger or the popover body', async () => {
      const user = userEvent.setup();
      const onParentClick = vi.fn();
      render(
        <div onClick={onParentClick}>
          <InfoTip label="Help" learnMoreHref="/docs/search">
            Body
          </InfoTip>
        </div>,
      );
      await user.click(screen.getByRole('button', { name: 'Help' }));
      await user.click(await screen.findByText('Body'));
      expect(onParentClick).not.toHaveBeenCalled();
    });

    it('keeps a same-origin link in the same tab', async () => {
      const user = userEvent.setup();
      render(
        <InfoTip label="Help" learnMoreHref={`${origin}/docs/search?x=1#y`} learnMoreLabel="Search docs">
          Body
        </InfoTip>,
      );
      await user.click(screen.getByRole('button', { name: 'Help' }));
      const link = await screen.findByRole('link', { name: 'Search docs' });
      expect(link.getAttribute('href')).toBe('/docs/search?x=1#y');
      expect(link.getAttribute('target')).toBeNull();
    });

    it.each([
      ['javascript:alert(1)'],
      ['data:text/html,<script>alert(1)</script>'],
      ['//evil.com'],
      ['/\\evil.com'],
      ['/\t/evil.com'],
      ['/\n/evil.com'],
      ['http://evil.com/docs'],
    ])('drops an unsafe href %j and falls back to a text tooltip', async (href) => {
      const user = userEvent.setup();
      render(
        <InfoTip label="Help" learnMoreHref={href}>
          Body
        </InfoTip>,
      );
      await user.tab();
      await screen.findByRole('tooltip');
      expect(screen.queryByRole('link')).toBeNull();
    });
  });

  it('uses a smaller icon for the inline variant', () => {
    render(<InfoTip label="Help" variant="inline">Body</InfoTip>);
    const svg = screen.getByRole('button', { name: 'Help' }).querySelector('svg');
    expect(svg?.getAttribute('class')).toContain('h-2.5');
  });
});
