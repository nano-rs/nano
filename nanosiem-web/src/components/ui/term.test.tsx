// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-5867: <Term> shows a glossary definition. Without a docs link it is a
// tooltip (hover, focus, tap). With one it is a popover whose link is in the
// tab order (never a link inside role="tooltip"). Inside a control it is
// never its own tab stop, never blocks the control's click, and inside a
// <label> a click shows the definition instead of toggling the input.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { Term } from './term';
import { GLOSSARY } from '@/lib/glossary';

afterEach(cleanup);

// `signal` has no docs link (tooltip); `ocsf` has one (popover).
const TIP = GLOSSARY.signal;
const LINKED = GLOSSARY.ocsf;

describe('Term without a docs link (tooltip)', () => {
  it('renders the given text with a dotted underline and no tooltip until asked', () => {
    render(<Term id="signal">signals</Term>);
    const el = screen.getByText('signals');
    expect(el.className).toContain('decoration-dotted');
    expect(el.getAttribute('tabindex')).toBe('0');
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('defaults the label to the glossary term', () => {
    render(<Term id="signal" />);
    expect(screen.getByText(TIP.term)).toBeTruthy();
  });

  it('opens on keyboard focus with the short and more lines, closes on Escape, and has no link', async () => {
    const user = userEvent.setup();
    render(<Term id="signal" />);
    await user.tab();
    const tip = await screen.findByRole('tooltip');
    expect(tip.textContent).toContain(TIP.short);
    expect(tip.textContent).toContain(TIP.more);
    expect(document.activeElement?.getAttribute('aria-describedby')).toBe(tip.id);
    expect(screen.queryByRole('link')).toBeNull();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('toggles on tap', () => {
    render(<Term id="signal" />);
    const el = screen.getByText(TIP.term);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'touch' });
      fireEvent.click(el);
    });
    expect(screen.getByRole('tooltip').textContent).toContain(TIP.short);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'touch' });
      fireEvent.click(el);
    });
    expect(screen.queryByRole('tooltip')).toBeNull();
  });
});

describe('Term with a docs link (popover)', () => {
  it('describes itself with the definition, and focus alone opens nothing', async () => {
    const user = userEvent.setup();
    render(<Term id="ocsf" />);
    await user.tab();
    const el = screen.getByRole('button', { name: LINKED.term });
    expect(document.activeElement).toBe(el);
    const desc = document.getElementById(el.getAttribute('aria-describedby')!);
    expect(desc?.textContent).toContain(LINKED.short);
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('opens on Enter with a focusable Docs link outside any tooltip, and Escape returns focus', async () => {
    const user = userEvent.setup();
    render(<Term id="ocsf" />);
    await user.tab();
    const el = screen.getByRole('button', { name: LINKED.term });
    await user.keyboard('{Enter}');
    const link = await screen.findByRole('link', { name: 'Docs' });
    expect(link.getAttribute('href')).toBe(LINKED.docsHref);
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(link.getAttribute('tabindex')).toBeNull();
    expect(link.closest('[role="tooltip"]')).toBeNull();
    expect(screen.getByText(LINKED.short)).toBeTruthy();
    // The link is reachable by keyboard.
    if (document.activeElement !== link) await user.tab();
    expect(document.activeElement).toBe(link);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('link')).toBeNull();
    expect(document.activeElement).toBe(el);
  });

  it('opens on click', async () => {
    const user = userEvent.setup();
    render(<Term id="ocsf" />);
    await user.click(screen.getByRole('button', { name: LINKED.term }));
    expect(await screen.findByRole('link', { name: 'Docs' })).toBeTruthy();
  });
});

describe('Term inside a control', () => {
  it('is never its own tab stop or a popover, even without nested', () => {
    render(
      <a href="/hunts">
        <Term id="ocsf" />
      </a>,
    );
    const el = screen.getByText(LINKED.term);
    expect(el.getAttribute('tabindex')).toBeNull();
    expect(el.getAttribute('role')).toBeNull();
  });

  it('never prevents the parent link from navigating', () => {
    render(
      <a href="/hunts">
        <Term id="ocsf" />
      </a>,
    );
    const el = screen.getByText(LINKED.term);
    fireEvent.pointerDown(el, { pointerType: 'mouse' });
    const ev = new MouseEvent('click', { bubbles: true, cancelable: true });
    el.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(false);
  });

  it('lets clicks reach a parent button', () => {
    const onParent = vi.fn();
    render(
      <button type="button" onClick={onParent}>
        <Term id="signal" />
      </button>,
    );
    fireEvent.click(screen.getByText(TIP.term));
    expect(onParent).toHaveBeenCalledTimes(1);
  });

  it('opens while the parent control has keyboard focus and describes it', async () => {
    const user = userEvent.setup();
    render(
      <button type="button">
        <Term id="signal" /> settings
      </button>,
    );
    await user.tab();
    const button = screen.getByRole('button');
    expect(document.activeElement).toBe(button);
    expect((await screen.findByRole('tooltip')).textContent).toContain(TIP.short);
    const desc = document.getElementById(button.getAttribute('aria-describedby')!.split(' ')[0]);
    expect(desc?.textContent).toContain(TIP.short);
  });

  it('inside a label, a click shows the definition and does not toggle the input', () => {
    const onChange = vi.fn();
    render(
      <label>
        <input type="checkbox" onChange={onChange} /> Review with the <Term id="signal" />
      </label>,
    );
    const el = screen.getByText(TIP.term);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'mouse' });
      fireEvent.click(el);
    });
    expect(onChange).not.toHaveBeenCalled();
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
    expect(screen.getByRole('tooltip').textContent).toContain(TIP.short);
  });

  it("never adds the definition to the surrounding text", () => {
    const { container } = render(
      <h2>
        <Term id="ocsf" /> and <Term id="signal" />
      </h2>,
    );
    expect(container.textContent).toBe(`${LINKED.term} and ${TIP.term}`);
  });

  it('inside a label with a wrapped input: opens when the input has focus and describes the input', async () => {
    const user = userEvent.setup();
    render(
      <label>
        <input type="checkbox" /> Review with the <Term id="signal" />
      </label>,
    );
    const el = screen.getByText(TIP.term);
    expect(el.getAttribute('tabindex')).toBeNull();
    await user.tab();
    const box = screen.getByRole('checkbox');
    expect(document.activeElement).toBe(box);
    expect((await screen.findByRole('tooltip')).textContent).toContain(TIP.short);
    const ids = box.getAttribute('aria-describedby')!.split(' ');
    expect(ids.map((id) => document.getElementById(id)?.textContent).join(' ')).toContain(TIP.short);
    expect((box as HTMLInputElement).checked).toBe(false);
  });

  it('inside a label with htmlFor: describes the named input', async () => {
    const user = userEvent.setup();
    render(
      <>
        <label htmlFor="pk">
          <Term id="signal" /> key
        </label>
        <input id="pk" />
      </>,
    );
    await user.tab();
    const input = screen.getByRole('textbox');
    expect(document.activeElement).toBe(input);
    const ids = input.getAttribute('aria-describedby')!.split(' ');
    expect(ids.map((id) => document.getElementById(id)?.textContent).join(' ')).toContain(TIP.short);
  });

  it('inside a label that names no input: stays focusable so a keyboard can reach it', async () => {
    const user = userEvent.setup();
    render(
      <label>
        <Term id="signal" /> level
      </label>,
    );
    await user.tab();
    const el = screen.getByText(TIP.term);
    expect(document.activeElement).toBe(el);
    expect((await screen.findByRole('tooltip')).textContent).toContain(TIP.short);
  });

  it('ignores nested when no control is around it: it stays focusable and keeps its Docs link', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <Term id="ocsf" nested />
      </div>,
    );
    const el = screen.getByRole('button', { name: LINKED.term });
    expect(el.getAttribute('tabindex')).toBe('0');
    await user.tab();
    await user.keyboard('{Enter}');
    expect(await screen.findByRole('link', { name: 'Docs' })).toBeTruthy();
  });
});

describe('Term inside a table row', () => {
  it('a click on the term opens it and never reaches a clickable row', () => {
    const onRow = vi.fn();
    render(
      <table>
        <tbody>
          <tr onClick={onRow}>
            <td>
              12 <Term id="signal" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    const el = screen.getByText(TIP.term);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'mouse' });
      fireEvent.click(el);
    });
    expect(onRow).not.toHaveBeenCalled();
    expect(screen.getByRole('tooltip').textContent).toContain(TIP.short);
  });

  it('a click on the Docs link in its popover never reaches the row', async () => {
    const user = userEvent.setup();
    const onRow = vi.fn();
    render(
      <table>
        <tbody>
          <tr onClick={onRow}>
            <td>
              <Term id="ocsf" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    await user.click(screen.getByRole('button', { name: LINKED.term }));
    const link = await screen.findByRole('link', { name: 'Docs' });
    link.addEventListener('click', (e) => e.preventDefault());
    await user.click(link);
    expect(onRow).not.toHaveBeenCalled();
  });

  it('in a focusable clickable row, a click or tap on the term shows the definition and never opens the row', () => {
    const onRow = vi.fn();
    render(
      <table>
        <tbody>
          <tr tabIndex={0} onClick={onRow}>
            <td>
              <Term id="signal" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    const el = screen.getByText(TIP.term);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'mouse' });
      fireEvent.click(el);
    });
    expect(onRow).not.toHaveBeenCalled();
    expect(screen.getByRole('tooltip').textContent).toContain(TIP.short);
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'touch' });
      fireEvent.click(el);
    });
    expect(screen.queryByRole('tooltip')).toBeNull();
    act(() => {
      fireEvent.pointerDown(el, { pointerType: 'touch' });
      fireEvent.click(el);
    });
    expect(screen.getByRole('tooltip').textContent).toContain(TIP.short);
    expect(onRow).not.toHaveBeenCalled();
  });

  it('a row with tabIndex -1 is not a tab stop, so the term keeps its own', () => {
    render(
      <table>
        <tbody>
          <tr tabIndex={-1}>
            <td>
              <Term id="signal" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    expect(screen.getByText(TIP.term).getAttribute('tabindex')).toBe('0');
  });

  it('in a focusable row, the row is the one tab stop and its focus opens the term', async () => {
    const user = userEvent.setup();
    render(
      <table>
        <tbody>
          <tr tabIndex={0}>
            <td>
              <Term id="signal" />
            </td>
          </tr>
        </tbody>
      </table>,
    );
    const el = screen.getByText(TIP.term);
    expect(el.getAttribute('tabindex')).toBeNull();
    await user.tab();
    expect(document.activeElement?.tagName).toBe('TR');
    expect((await screen.findByRole('tooltip')).textContent).toContain(TIP.short);
  });
});
