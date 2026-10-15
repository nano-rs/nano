// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3208: `pivt:open-tuning-wizard` must open the tuning wizard for the focused rule. */
import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { TUNING_WIZARD_EVENT, useTuningWizardListener } from './use-tuning-wizard-listener';

const fire = (detail?: Record<string, unknown>) =>
  act(() => {
    window.dispatchEvent(new CustomEvent(TUNING_WIZARD_EVENT, { detail }));
  });

describe('useTuningWizardListener', () => {
  it('opens for the rule-editor event addressed to the focused rule', () => {
    const { result } = renderHook(() => useTuningWizardListener('rule_a', true));
    expect(result.current.request).toBeNull();
    fire({ ruleId: 'rule_a' });
    expect(result.current.request).toEqual({ seq: 1, prompt: undefined });
  });

  it('opens for pivt @tune (no ruleId) and carries the prompt', () => {
    const { result } = renderHook(() => useTuningWizardListener('rule_a', true));
    fire({ prompt: 'too noisy from the scanner subnet' });
    expect(result.current.request?.prompt).toBe('too noisy from the scanner subnet');
  });

  it('ignores events for another rule, blank prompts, and missing detail', () => {
    const { result } = renderHook(() => useTuningWizardListener('rule_a', true));
    fire({ ruleId: 'rule_b' });
    expect(result.current.request).toBeNull();
    fire();
    expect(result.current.request).toEqual({ seq: 1, prompt: undefined });
    fire({ prompt: '   ' });
    expect(result.current.request).toEqual({ seq: 2, prompt: undefined });
  });

  it('closes, re-opens on a repeat request, and resets when the rule changes', () => {
    const { result, rerender } = renderHook(({ id }) => useTuningWizardListener(id, true), {
      initialProps: { id: 'rule_a' as string | undefined },
    });
    fire({ ruleId: 'rule_a' });
    act(() => result.current.close());
    expect(result.current.request).toBeNull();
    fire({ ruleId: 'rule_a' });
    expect(result.current.request).not.toBeNull();
    rerender({ id: 'rule_b' });
    expect(result.current.request).toBeNull();
    fire({ ruleId: 'rule_a' });
    expect(result.current.request).toBeNull();
  });

  it('does not listen when disabled or without a saved rule', () => {
    const disabled = renderHook(() => useTuningWizardListener('rule_a', false));
    const unsaved = renderHook(() => useTuningWizardListener(undefined, true));
    fire({ ruleId: 'rule_a' });
    fire();
    expect(disabled.result.current.request).toBeNull();
    expect(unsaved.result.current.request).toBeNull();
  });
});
