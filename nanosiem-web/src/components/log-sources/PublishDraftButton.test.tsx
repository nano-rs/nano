// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4912 (port of main's NAN-4847 tooltips): Publish says what it does to
 * incoming events, and a disabled Publish says why it is disabled.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { TooltipProvider } from '@/components/ui/tooltip';
import {
  PUBLISH_DRAFT_TOOLTIP,
  PUBLISH_NEEDS_VALIDATION_TOOLTIP,
  PublishDraftButton,
} from './PublishDraftButton';

afterEach(cleanup);

function renderButton(props: { publishing?: boolean; validated?: boolean; onPublish?: () => void }) {
  return render(
    <TooltipProvider delayDuration={0}>
      <PublishDraftButton
        label="Publish"
        publishing={props.publishing ?? false}
        validated={props.validated ?? true}
        onPublish={props.onPublish ?? (() => {})}
      />
    </TooltipProvider>,
  );
}

async function tooltipFor(button: HTMLElement): Promise<string> {
  fireEvent.focus(button.parentElement!);
  const tips = await screen.findAllByRole('tooltip');
  return tips[0].textContent ?? '';
}

describe('PublishDraftButton', () => {
  it('publishes a validated draft and explains that it goes live', async () => {
    const onPublish = vi.fn();
    renderButton({ onPublish });
    const button = screen.getByRole('button', { name: 'Publish' });
    expect((button as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(button);
    expect(onPublish).toHaveBeenCalledOnce();
    expect(await tooltipFor(button)).toBe(PUBLISH_DRAFT_TOOLTIP);
  });

  it('is disabled until the parser validates, and says so', async () => {
    const onPublish = vi.fn();
    renderButton({ validated: false, onPublish });
    const button = screen.getByRole('button', { name: 'Publish' });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(button);
    expect(onPublish).not.toHaveBeenCalled();
    expect(await tooltipFor(button)).toBe(PUBLISH_NEEDS_VALIDATION_TOOLTIP);
  });

  it('is disabled while publishing', () => {
    renderButton({ publishing: true });
    expect((screen.getByRole('button', { name: 'Publish' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
