// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { useState } from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { EditorView } from '@codemirror/view';
import { isPreviewBoilerplate, PREVIEW_SCOPE_NOTE, stepPreviewStatus, withoutPreviewBoilerplate } from '@/lib/pipeline-model';
import { PipelineCapturePanel } from './PipelineCapture';
import { PipelinePreviewPanel } from './PipelinePreview';
import { PipelineStepList, PipelineStepSettings } from './PipelineSteps';
import { PipelineReleaseHistory, PipelineReleaseReview } from './PipelineReleases';
import { PipelineEditor } from './PipelineEditor';
import type { PipelineEditorProps } from './types';
import type {
  PipelineCapabilities,
  PipelineReleasePlan,
  PipelineStep,
} from '@/lib/pipeline-types';

const capabilities: PipelineCapabilities = {
  supportedSteps: ['vrl', 'fields'],
  capture: { available: true, maxEvents: 100, maxDurationSeconds: 30 },
  preview: true,
  ai: false,
};
beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: () => ({
      matches: false,
      addEventListener: () => {},
      removeEventListener: () => {},
    }),
  });
});
afterEach(cleanup);

describe('Capture permissions and bounds', () => {
  it('does not offer a successful save before the current capture has been frozen', () => {
    const save = vi.fn();
    render(
      <PipelineCapturePanel
        sourceId="s1"
        sourceName="Firewall"
        activeRevision={7}
        capture={{
          state: 'stopped',
          sourceId: 's1',
          point: 'input',
          events: [{ id: 'event-1', input: { message: 'raw' } }],
        }}
        capabilities={capabilities}
        canCapture
        busy={false}
        canSaveSample={false}
        onSaveSample={save}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onFreeze={vi.fn()}
      />
    );
    const button = screen.getByRole('button', { name: 'Save as sample' });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(button);
    expect(save).not.toHaveBeenCalled();
  });
  it('pins observed events to the captured bundle when the active version changes', () => {
    render(
      <PipelineCapturePanel
        sourceId="s1"
        sourceName="Firewall"
        activeRevision={99}
        capture={{
          state: 'completed',
          sourceId: 's1',
          point: 'input',
          sessionId: 'capture-1',
          activeBundleSha256: 'abcdef1234567890',
          events: [{ id: 'event-1', input: { event: 'captured' } }],
        }}
        capabilities={capabilities}
        canCapture
        busy={false}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onFreeze={vi.fn()}
      />
    );
    expect(
      screen.getByText('Observed input · bundle abcdef123456')
    ).toBeTruthy();
    expect(screen.queryByText(/active version 99/)).toBeNull();
  });
  it('does not render event payloads or permit capture without source-event permission', () => {
    render(
      <PipelineCapturePanel
        sourceId="s1"
        sourceName="Firewall"
        activeRevision={7}
        capture={{
          state: 'completed',
          sourceId: 's1',
          point: 'input',
          events: [
            {
              id: 'event-secret',
              input: { password: 'secret-capture-payload' },
            },
          ],
        }}
        capabilities={capabilities}
        canCapture={false}
        busy={false}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onFreeze={vi.fn()}
      />
    );
    expect(screen.queryByText(/secret-capture-payload/)).toBeNull();
    expect(
      (
        screen.getByRole('button', {
          name: 'Capture again',
        }) as HTMLButtonElement
      ).disabled
    ).toBe(true);
    expect(screen.getByText('Source-event permission required')).toBeTruthy();
  });

  it('rejects manually entered capture values outside advertised runtime limits', () => {
    const start = vi.fn();
    render(
      <PipelineCapturePanel
        sourceId="s1"
        sourceName="Firewall"
        activeRevision={7}
        capabilities={capabilities}
        canCapture
        busy={false}
        onStart={start}
        onStop={vi.fn()}
        onFreeze={vi.fn()}
      />
    );
    fireEvent.change(screen.getByLabelText(/^Capture up to \(events\)/), {
      target: { value: '101' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Start capture' }));
    expect(start).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toContain('whole numbers');
    fireEvent.change(screen.getByLabelText(/^Capture up to \(events\)/), {
      target: { value: '20' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Start capture' }));
    expect(start).toHaveBeenCalledWith({
      sourceId: 's1',
      point: 'input',
      durationSeconds: 30,
      eventLimit: 20,
    });
  });

  it('does not infer a dropped event from absence in a live capture', () => {
    render(
      <PipelineCapturePanel
        sourceId="s1"
        sourceName="Firewall"
        activeRevision={7}
        capture={{
          state: 'no_traffic',
          sourceId: 's1',
          point: 'input',
          events: [],
        }}
        capabilities={capabilities}
        canCapture
        busy={false}
        onStart={vi.fn()}
        onStop={vi.fn()}
        onFreeze={vi.fn()}
      />
    );
    expect(
      screen.getByText('No source traffic observed during this capture')
    ).toBeTruthy();
    expect(screen.queryByText(/Dropped/)).toBeNull();
  });
});

describe('Runtime preview outcomes', () => {
  it('compares the previous step output with the selected step output and retains final output mode', () => {
    render(
      <PipelinePreviewPanel
        samples={[]}
        revision={8}
        pending={false}
        canViewEvents
        available
        selectedStepId="second"
        onSampleSelect={vi.fn()}
        onPreview={vi.fn()}
        preview={{
          revision: 8,
          fingerprint: 'h1',
          stale: false,
          inputCount: 1,
          outputCount: 1,
          events: [
            {
              inputId: 'in-1',
              input: { value: 0 },
              outcome: 'retained',
              outputs: [{ value: 2 }],
              trace: [
                { stepId: 'first', outputs: [{ value: 1 }] },
                { stepId: 'second', outputs: [{ value: 2 }] },
              ],
            },
          ],
        }}
      />
    );
    expect(screen.getByText('0')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Preview stage'), {
      target: { value: 'selected' },
    });
    expect(screen.getByText('1')).toBeTruthy();
    expect(screen.queryByText('0')).toBeNull();
    expect(screen.getByText('Prefix before → prefix through step second')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Preview stage'), {
      target: { value: 'final' },
    });
    expect(screen.getByText('0')).toBeTruthy();
  });
  it('labels stale preview results with the edit that actually produced them', () => {
    render(
      <PipelinePreviewPanel
        samples={[]}
        revision={9}
        pending={false}
        canViewEvents
        available
        selectedStepId={null}
        onSampleSelect={vi.fn()}
        onPreview={vi.fn()}
        preview={{
          revision: 8,
          fingerprint: 'h1',
          stale: true,
          inputCount: 1,
          outputCount: 1,
          events: [
            {
              inputId: 'in-1',
              input: { a: 1 },
              outcome: 'retained',
              outputs: [{ a: 2 }],
            },
          ],
        }}
      />
    );
    expect(
      screen.getByText('Computed draft · edit 8 · current draft edit 9')
    ).toBeTruthy();
    expect(screen.getByText('Preview out of date')).toBeTruthy();
  });
  it('shows runtime split lineage and lets users inspect each output', () => {
    render(
      <PipelinePreviewPanel
        sample={{ id: 'sample', name: 'Frozen sample', events: [] }}
        samples={[]}
        revision={8}
        pending={false}
        canViewEvents
        available
        selectedStepId={null}
        onSampleSelect={vi.fn()}
        onPreview={vi.fn()}
        preview={{
          revision: 8,
          fingerprint: 'h1',
          stale: false,
          inputCount: 1,
          outputCount: 2,
          events: [
            {
              inputId: 'in-1',
              input: { kind: 'before' },
              outcome: 'split',
              outputs: [{ kind: 'first-output' }, { kind: 'second-output' }],
            },
          ],
        }}
      />
    );
    expect(screen.getByText('Sample results · 1 IN → 2 OUT')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Output event'), {
      target: { value: '1' },
    });
    expect(screen.getByText('"second-output"')).toBeTruthy();
    expect(screen.queryByText('"first-output"')).toBeNull();
  });

  it('keeps pending aggregation distinct from dropped events', () => {
    render(
      <PipelinePreviewPanel
        samples={[]}
        revision={8}
        pending={false}
        canViewEvents
        available
        selectedStepId={null}
        onSampleSelect={vi.fn()}
        onPreview={vi.fn()}
        preview={{
          revision: 8,
          fingerprint: 'h1',
          stale: false,
          inputCount: 1,
          outputCount: 0,
          events: [
            {
              inputId: 'in-1',
              input: { message: 'held' },
              outcome: 'pending',
              outputs: [],
            },
          ],
        }}
      />
    );
    expect(screen.getByText('No output yet; waiting for flush.')).toBeTruthy();
    expect(screen.queryByText(/Filtered by/)).toBeNull();
  });

  it('clears rendered payloads when source-event permission is revoked', () => {
    const props = {
      samples: [],
      revision: 8,
      pending: false,
      available: true,
      selectedStepId: null,
      onSampleSelect: vi.fn(),
      onPreview: vi.fn(),
      preview: {
        revision: 8,
        fingerprint: 'h1',
        stale: false,
        inputCount: 1,
        outputCount: 1,
        events: [
          {
            inputId: 'in-1',
            input: { password: 'secret-preview' },
            outcome: 'retained' as const,
            outputs: [{ password: 'secret-preview' }],
          },
        ],
      },
    };
    const { rerender } = render(
      <PipelinePreviewPanel {...props} canViewEvents />
    );
    expect(screen.getAllByText('"secret-preview"').length).toBeGreaterThan(0);
    rerender(<PipelinePreviewPanel {...props} canViewEvents={false} />);
    expect(screen.queryByText('"secret-preview"')).toBeNull();
  });
});

describe('Ordered step editing', () => {
  it('preserves identity and selection when a step moves by keyboard', () => {
    function Steps() {
      const [steps, setSteps] = useState<PipelineStep[]>([
        {
          id: 'a',
          name: 'First',
          kind: 'vrl',
          enabled: true,
          config: { code: '' },
        },
        {
          id: 'b',
          name: 'Second',
          kind: 'vrl',
          enabled: true,
          config: { code: '' },
        },
      ]);
      return (
        <PipelineStepList
          steps={steps}
          selectedId="a"
          supportedSteps={['vrl']}
          readOnly={false}
          onSelect={vi.fn()}
          onChange={setSteps}
          onConfigure={vi.fn()}
        />
      );
    }
    render(<Steps />);
    fireEvent.keyDown(screen.getByRole('option', { name: /First/ }), {
      key: 'ArrowDown',
      altKey: true,
    });
    const rows = screen.getAllByRole('option');
    expect(rows[0].id).toBe('pipeline-step-b');
    expect(rows[1].id).toBe('pipeline-step-a');
    expect(rows[1].getAttribute('aria-selected')).toBe('true');
  });

  it('disables unsupported runtime settings', () => {
    render(
      <PipelineStepSettings
        step={{
          id: 'a',
          name: 'Sampling',
          kind: 'sample',
          enabled: true,
          config: { ratio: 10 },
        }}
        readOnly={false}
        supported={false}
        onChange={vi.fn()}
      />
    );
    expect(
      (screen.getByLabelText('Keep 1 in every N events') as HTMLInputElement).disabled
    ).toBe(true);
    expect(screen.getByText('Unavailable in this runtime')).toBeTruthy();
  });
});

describe('VRL step editor (NAN-3446)', () => {
  const vrlStep = (code: string): PipelineStep => ({
    id: 'v',
    name: 'Parser',
    kind: 'vrl',
    enabled: true,
    config: { code },
  });
  const vrlContent = () =>
    screen.getByRole('textbox', { name: 'Vector Remap Language' });
  /** jsdom cannot type into contenteditable; drive the CodeMirror view directly. */
  const typeVrl = (text: string) => {
    const view = EditorView.findFromDOM(vrlContent());
    if (!view) throw new Error('no CodeMirror view');
    act(() => {
      view.dispatch({
        changes: { from: view.state.doc.length, insert: text },
        userEvent: 'input.type',
      });
    });
  };

  it('renders a highlighted CodeMirror editor instead of a plain textarea', () => {
    const { container } = render(
      <PipelineStepSettings
        step={vrlStep('# parse\n.x = parse_json!(.message)')}
        readOnly={false}
        supported
        onChange={vi.fn()}
      />
    );
    expect(container.querySelector('textarea')).toBeNull();
    const content = vrlContent();
    expect(content.getAttribute('aria-readonly')).toBeNull();
    const lines = content.querySelectorAll('.cm-line');
    expect(lines.length).toBe(2);
    expect(lines[0].querySelector('span')?.textContent).toBe('# parse');
    expect(
      Array.from(lines[1].querySelectorAll('span')).map((s) => s.textContent)
    ).toContain('parse_json!');
  });

  it('reports edits as a controlled config.code change', () => {
    function Settings() {
      const [step, setStep] = useState(vrlStep('.a = 1'));
      return (
        <>
          <PipelineStepSettings
            step={step}
            readOnly={false}
            supported
            onChange={setStep}
          />
          <output data-testid="code">{String(step.config.code)}</output>
        </>
      );
    }
    render(<Settings />);
    typeVrl('\n.b = 2');
    expect(screen.getByTestId('code').textContent).toBe('.a = 1\n.b = 2');
  });

  it.each([
    { readOnly: true, supported: true },
    { readOnly: false, supported: false },
  ])('is read-only without edit permission or runtime support: %j', (flags) => {
    render(
      <PipelineStepSettings
        step={vrlStep('.a = 1')}
        {...flags}
        onChange={vi.fn()}
      />
    );
    const content = vrlContent();
    expect(content.getAttribute('aria-readonly')).toBe('true');
    const view = EditorView.findFromDOM(content);
    expect(view?.state.readOnly).toBe(true);
  });

  it('flows edits into the draft and follows a reloaded server draft', () => {
    const draft = {
      name: 'Firewall',
      description: '',
      revision: 4,
      steps: [vrlStep('.mine = true')],
    };
    const onDraftChange = vi.fn();
    const props: PipelineEditorProps = {
      pipeline: { id: 's1', name: 'Firewall', description: '', sourceId: 's1', sourceName: 'Firewall', sourceType: 'firewall', activeRevision: 3, draftRevision: 4, hasDraft: true, health: 'healthy', latestRelease: null },
      draft, capabilities, permissions: { view: true, edit: true, capture: true, release: true }, dirty: false, samples: [],
      onDraftChange, onSave: vi.fn(), onValidate: vi.fn(), onReview: vi.fn(), onHistory: vi.fn(), onCaptureStart: vi.fn(), onCaptureStop: vi.fn(),
      onFreeze: vi.fn(), onSampleSelect: vi.fn(), onPreview: vi.fn(),
    };
    const { rerender } = render(<PipelineEditor {...props} />);
    if (!screen.queryByRole('textbox', { name: 'Vector Remap Language' })) {
      fireEvent.click(screen.getByRole('option', { name: /Parser/ }));
    }
    typeVrl('\n.theirs = false');
    expect(onDraftChange).toHaveBeenLastCalledWith(
      expect.objectContaining({
        steps: [expect.objectContaining({ config: { code: '.mine = true\n.theirs = false' } })],
      })
    );
    // Reload latest swaps in the server draft; the editor must show it.
    rerender(
      <PipelineEditor {...props} draft={{ ...draft, revision: 5, steps: [vrlStep('.server = 1')] }} />
    );
    expect(vrlContent().textContent).toBe('.server = 1');
  });
});

describe('Release review gates', () => {
  const plan: PipelineReleasePlan = {
    revision: 8,
    fingerprint: 'plan-1',
    activeVrl: '.a = 1',
    compiledVrl: '.a = 2',
    validation: { valid: true, errors: [], warnings: [] },
  };
  it.each([
    { canPublish: false, stale: false },
    { canPublish: true, stale: true },
  ])(
    'blocks publication when permission or plan freshness disallows it: %j',
    (gating) => {
      const publish = vi.fn();
      render(
        <PipelineReleaseReview
          open
          plan={plan}
          {...gating}
          onOpenChange={vi.fn()}
          onPublish={publish}
        />
      );
      const button = screen.getByRole('button', { name: 'Publish release' });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(button);
      expect(publish).not.toHaveBeenCalled();
    }
  );

  it('offers no capture-sample option when the reviewed sample is not a capture', () => {
    const publish = vi.fn();
    render(<PipelineReleaseReview open plan={plan} canPublish onOpenChange={vi.fn()} onPublish={publish} />);
    expect(screen.queryByRole('checkbox')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Publish release' }));
    expect(publish).toHaveBeenCalledWith({ persistCapturedSamples: false });
  });

  it('keeps captured events out of the release unless the reviewer explicitly opts in', () => {
    const publish = vi.fn();
    const captured = { ...plan, capturedSampleCount: 12 };
    const { rerender } = render(<PipelineReleaseReview open plan={captured} canPublish onOpenChange={vi.fn()} onPublish={publish} />);
    const option = screen.getByRole('checkbox', { name: /Save the 12 captured events as this version's test samples/ });
    expect(option.getAttribute('aria-checked')).toBe('false');
    expect(screen.getByText(/may contain sensitive data/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Publish release' }));
    expect(publish).toHaveBeenLastCalledWith({ persistCapturedSamples: false });
    fireEvent.click(option);
    fireEvent.click(screen.getByRole('button', { name: 'Publish release' }));
    expect(publish).toHaveBeenLastCalledWith({ persistCapturedSamples: true });
    // A new review plan starts unchecked again.
    rerender(<PipelineReleaseReview open plan={{ ...captured, fingerprint: 'plan-2' }} canPublish onOpenChange={vi.fn()} onPublish={publish} />);
    expect(screen.getByRole('checkbox').getAttribute('aria-checked')).toBe('false');
  });
});

describe('Release history', () => {
  const release = { id: 'rollout-1', revision: 3, state: 'live', createdAt: '2026-10-09T10:00:00Z', versionId: 33 };
  it('formats timestamps with the shared UTC formatter and keeps the machine value', () => {
    render(<PipelineReleaseHistory open pipelineName="Firewall" releases={[release]} canRollback onOpenChange={vi.fn()} onRollback={vi.fn()} />);
    const time = screen.getByText('Oct 9, 10:00:00 UTC');
    expect(time.tagName).toBe('TIME');
    expect(time.getAttribute('dateTime')).toBe('2026-10-09T10:00:00Z');
  });
  it('warns that rollback replaces unsaved and saved-unpublished edits and echoes the confirmation', () => {
    const rollback = vi.fn();
    render(<PipelineReleaseHistory open pipelineName="Firewall" releases={[release]} canRollback unsavedEdits savedDraft onOpenChange={vi.fn()} onRollback={rollback} />);
    fireEvent.click(screen.getByRole('button', { name: /Rollback/ }));
    const dialog = screen.getByRole('alertdialog');
    expect(within(dialog).getByText(/your unsaved edits in this editor and the saved draft that has not been published/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Replace and roll back' }));
    expect(rollback).toHaveBeenCalledWith(release, { unsavedEdits: true });
  });
  it('keeps load failures and rollback failures distinct', () => {
    render(<PipelineReleaseHistory open pipelineName="Firewall" releases={[]} canRollback error="stale_draft" onOpenChange={vi.fn()} onRollback={vi.fn()} />);
    expect(screen.getByText('Rollback was not requested')).toBeTruthy();
    expect(screen.queryByText('Release history could not be loaded')).toBeNull();
  });
});

describe('Editor conflicts, errors, and permissions', () => {
  const draft = { name: 'Firewall', description: '', revision: 4, steps: [{ id: 'vrl', name: 'Parser', kind: 'vrl' as const, enabled: true, config: { code: '.mine = true' } }] };
  const props = (overrides: Partial<PipelineEditorProps> = {}): PipelineEditorProps => ({
    pipeline: { id: 's1', name: 'Firewall', description: '', sourceId: 's1', sourceName: 'Firewall', sourceType: 'firewall', activeRevision: 3, draftRevision: 4, hasDraft: true, health: 'healthy', latestRelease: null },
    draft, capabilities, permissions: { view: true, edit: true, capture: true, release: true }, dirty: true, samples: [],
    onDraftChange: vi.fn(), onSave: vi.fn(), onValidate: vi.fn(), onReview: vi.fn(), onHistory: vi.fn(), onCaptureStart: vi.fn(), onCaptureStop: vi.fn(),
    onFreeze: vi.fn(), onSampleSelect: vi.fn(), onPreview: vi.fn(), ...overrides,
  });
  it('offers reload, keep, copy, and discard on a conflict and blocks saving until resolved', () => {
    const reload = vi.fn(), keep = vi.fn(), discard = vi.fn();
    render(<PipelineEditor {...props({ conflict: { operation: 'save', message: 'Changed elsewhere.' }, errors: { save: 'stale_draft' }, onReloadLatest: reload, onKeepLocalEdits: keep, onDiscardDraft: discard })} />);
    expect(screen.getByText('This pipeline changed on the server')).toBeTruthy();
    expect(screen.getByText('stale_draft')).toBeTruthy();
    expect(screen.queryByText('Draft could not be saved')).toBeNull();
    expect((screen.getByRole('button', { name: 'Save draft' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole('button', { name: 'Copy my VRL' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Keep my edits' }));
    expect(keep).toHaveBeenCalled();
    // Dirty edits are confirmed before reload replaces them.
    fireEvent.click(screen.getByRole('button', { name: 'Reload latest' }));
    expect(reload).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Discard and reload' }));
    expect(reload).toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Discard my draft' }));
    fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Discard draft' }));
    expect(discard).toHaveBeenCalled();
  });
  it('titles each failure by its operation and keeps preview failures out of the editor banner', () => {
    render(<PipelineEditor {...props({ dirty: false, errors: { validate: 'compiler unavailable' }, previewError: 'Preview worker failed' })} />);
    expect(screen.getByText('Validation could not run')).toBeTruthy();
    expect(screen.queryByText('Pipeline operation failed')).toBeNull();
    expect(screen.queryByText('Preview worker failed')).toBeNull();
  });
  it('lets a release manager without edit permission review a saved draft', () => {
    const review = vi.fn();
    render(<PipelineEditor {...props({ dirty: false, permissions: { view: true, edit: false, capture: false, release: true }, onReview: review })} />);
    const button = screen.getByRole('button', { name: 'Review release' }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    expect(review).toHaveBeenCalled();
    expect((screen.getByRole('button', { name: 'Save draft' }) as HTMLButtonElement).disabled).toBe(true);
  });
  it('shows a preview failure in the preview panel', () => {
    render(<PipelinePreviewPanel samples={[]} revision={1} pending={false} canViewEvents available error="Preview capacity is busy." selectedStepId={null} onSampleSelect={vi.fn()} onPreview={vi.fn()} />);
    expect(screen.getByText('Preview failed')).toBeTruthy();
    expect(screen.getByText('Preview capacity is busy.')).toBeTruthy();
  });
});

describe('Capture snapshot retention', () => {
  it('explains an expired snapshot and offers a new capture', () => {
    const start = vi.fn();
    render(<PipelineCapturePanel sourceId="s1" sourceName="Firewall" activeRevision={7} capabilities={capabilities} canCapture busy={false} onStart={start} onStop={vi.fn()} onFreeze={vi.fn()}
      capture={{ state: 'expired', sourceId: 's1', point: 'input', events: [], sessionId: 'session-1', startedAt: '2026-10-09T10:00:00Z', observedEvents: 4, retainUntil: '2026-10-09T10:10:00Z', reason: 'Capture snapshots are kept for 10 minutes and then purged.' }} />);
    expect(screen.getByText('Captured events expired')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Capture again' }));
    expect(start).toHaveBeenCalled();
  });
});

describe('Preview input without capture (NAN-3447)', () => {
  const base = { samples: [], revision: 1, pending: false, canViewEvents: true, available: true, selectedStepId: null, onSampleSelect: vi.fn(), onPreview: vi.fn() };
  it('makes load recent and paste the primary actions of the empty state', () => {
    const load = vi.fn();
    const paste = vi.fn();
    render(<PipelinePreviewPanel {...base} onLoadRecent={load} onPasteSample={paste} />);
    const empty = screen.getByTestId('pipeline-preview-empty');
    expect(within(empty).getByText('No preview input yet')).toBeTruthy();
    fireEvent.click(within(empty).getByRole('button', { name: 'Load recent events' }));
    expect(load).toHaveBeenCalledWith(20);
    fireEvent.click(within(empty).getByRole('button', { name: 'Paste sample' }));
    fireEvent.change(screen.getByLabelText('Raw events to paste'), { target: { value: 'a\nb' } });
    fireEvent.click(screen.getByRole('button', { name: 'Use as input' }));
    expect(paste).toHaveBeenCalledWith('a\nb');
  });
  it('bounds the load count and shows paste errors inline', () => {
    const load = vi.fn();
    render(<PipelinePreviewPanel {...base} onLoadRecent={load} onPasteSample={() => { throw new Error('Paste at most 100 events.'); }} />);
    fireEvent.change(screen.getByLabelText('Recent events to load'), { target: { value: '101' } });
    expect((screen.getByRole('button', { name: 'Load recent events' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Load 1–100 recent events.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Paste sample' }));
    fireEvent.change(screen.getByLabelText('Raw events to paste'), { target: { value: 'x' } });
    fireEvent.click(screen.getByRole('button', { name: 'Use as input' }));
    expect(screen.getByText('Paste at most 100 events.')).toBeTruthy();
    expect(load).not.toHaveBeenCalled();
  });
  it('lists loaded inputs, explains an empty load, and keeps payloads hidden without event permission', () => {
    const sample = { id: 'recent-1', name: 'Recent events · 2', origin: 'recent' as const, events: [{ id: 'recent-1', input: { message: 'first raw line' } }, { id: 'recent-2', input: { message: 'second raw line' } }] };
    const { rerender } = render(<PipelinePreviewPanel {...base} sample={sample} onLoadRecent={vi.fn()} sampleNotice="No stored events with raw text for this source in the last 24 hours." />);
    expect(screen.getByText(/Browser-only input/)).toBeTruthy();
    const list = screen.getByRole('listbox', { name: 'Preview inputs' });
    expect(within(list).getAllByRole('option')).toHaveLength(2);
    expect(screen.getByText('No recent events')).toBeTruthy();
    rerender(<PipelinePreviewPanel {...base} canViewEvents={false} sample={sample} onLoadRecent={vi.fn()} />);
    expect(screen.queryByText('first raw line')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Load recent events' })).toBeNull();
    expect(screen.getByText('Source-event permission required')).toBeTruthy();
  });
});

describe('Pipe page layout and copy (NAN-3452)', () => {
  const vrl = (id: string, name: string): PipelineStep => ({ id, name, kind: 'vrl', enabled: true, config: { code: '' } });
  function Steps({ initial = 'a' }: { initial?: string }) {
    const [selected, setSelected] = useState<string>(initial);
    const [steps, setSteps] = useState<PipelineStep[]>([vrl('a', 'First'), vrl('b', 'Second'), vrl('c', 'Third')]);
    return <PipelineStepList steps={steps} selectedId={selected} supportedSteps={['vrl']} readOnly={false} status={{ b: { errors: 2, changed: 0 } }} onSelect={setSelected} onChange={setSteps} onConfigure={vi.fn()} />;
  }
  const expanded = () => screen.getAllByRole('option').map((row) => !row.hasAttribute('data-collapsed'));

  it('auto-collapses every step except the selected one and shows status on collapsed rows', () => {
    render(<Steps />);
    expect(expanded()).toEqual([true, false, false]);
    expect(screen.getByRole('button', { name: 'Move up First' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Move up Second' })).toBeNull();
    expect(screen.getByText('2 err')).toBeTruthy();
    fireEvent.click(screen.getByRole('option', { name: /Second/ }));
    expect(expanded()).toEqual([false, true, false]);
  });

  it('toggles single steps and expands or collapses all', () => {
    render(<Steps />);
    fireEvent.click(screen.getByRole('button', { name: 'Expand Third' }));
    expect(expanded()).toEqual([true, false, true]);
    fireEvent.click(screen.getByRole('button', { name: 'Expand all steps' }));
    expect(expanded()).toEqual([true, true, true]);
    fireEvent.click(screen.getByRole('button', { name: 'Collapse all steps' }));
    expect(expanded()).toEqual([false, false, false]);
    fireEvent.keyDown(screen.getByRole('option', { name: /Second/ }), { key: 'ArrowRight' });
    expect(expanded()).toEqual([false, true, false]);
    fireEvent.keyDown(screen.getByRole('option', { name: /Second/ }), { key: 'ArrowLeft' });
    expect(expanded()).toEqual([false, false, false]);
  });

  it('counts per-step errors and changes from preview traces, and ignores stale previews', () => {
    const preview = { revision: 1, fingerprint: 'f', inputCount: 2, outputCount: 1, stale: false, events: [
      { inputId: '1', input: { m: 1 }, outputs: [{ m: 2 }], outcome: 'retained' as const, trace: [{ stepId: 'a', outputs: [{ m: 1 }] }, { stepId: 'b', outputs: [{ m: 2 }] }] },
      { inputId: '2', input: { m: 1 }, outputs: [], outcome: 'error' as const, trace: [{ stepId: 'a', outputs: [{ m: 3 }] }, { stepId: 'b', outputs: [], error: 'boom' }] },
    ] };
    expect(stepPreviewStatus(preview)).toEqual({ a: { errors: 0, changed: 1 }, b: { errors: 1, changed: 1 } });
    expect(stepPreviewStatus({ ...preview, stale: true })).toEqual({});
  });

  it('replaces the stacked preview disclaimers with one short line', () => {
    render(<PipelinePreviewPanel samples={[]} revision={1} pending={false} canViewEvents available selectedStepId={null} onSampleSelect={vi.fn()} onPreview={vi.fn()} />);
    expect(screen.getByText(PREVIEW_SCOPE_NOTE)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'What draft preview excludes' })).toBeTruthy();
    expect(screen.queryByText(/Native VRL sample preview/)).toBeNull();
    expect(withoutPreviewBoilerplate([
      'Draft preview executes native VRL only. Platform normalization, production sampling, stateful Vector transforms, and sinks are excluded.',
      'Step traces replay cumulative draft prefixes independently; time and random functions can differ between traces.',
      'Implicit preview timezones use UTC; specify a timezone in VRL when required.',
      'Preview evaluates the first 100 of 101 input events.',
    ])).toEqual(['Preview evaluates the first 100 of 101 input events.']);
    expect(isPreviewBoilerplate('Something new from the runtime.')).toBe(false);
  });

  it('keeps the step settings panel visible when widened and remembers widths', () => {
    window.localStorage.setItem('nano.pipe.editor.settingsWidth', '900');
    const draft = { name: 'Firewall', description: '', revision: 1, steps: [vrl('a', 'First')] };
    render(<PipelineEditor pipeline={{ id: 's1', name: 'Firewall', description: '', sourceId: 's1', sourceName: 'Firewall', sourceType: 'firewall', activeRevision: 1, draftRevision: 1, hasDraft: false, health: 'healthy', latestRelease: null }}
      draft={draft} capabilities={capabilities} permissions={{ view: true, edit: true, capture: true, release: true }} dirty={false} samples={[]}
      onDraftChange={vi.fn()} onSave={vi.fn()} onValidate={vi.fn()} onReview={vi.fn()} onHistory={vi.fn()} onCaptureStart={vi.fn()} onCaptureStop={vi.fn()} onFreeze={vi.fn()} onSampleSelect={vi.fn()} onPreview={vi.fn()} />);
    const settings = screen.getByRole('separator', { name: 'Resize step settings' });
    // 1100px default width - 220 steps - 360 preview minimum = 520 max.
    expect(settings.getAttribute('aria-valuenow')).toBe('520');
    fireEvent.keyDown(settings, { key: 'ArrowLeft' });
    expect(window.localStorage.getItem('nano.pipe.editor.settingsWidth')).toBe('510');
    fireEvent.click(screen.getByRole('button', { name: 'Collapse step list' }));
    expect(screen.getByRole('button', { name: 'Expand step list' })).toBeTruthy();
    expect(window.localStorage.getItem('nano.pipe.editor.stepsCollapsed')).toBe('1');
    window.localStorage.clear();
  });
});

describe('NAN-3625 preview input', () => {
  const PUSH = '6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10';
  const PULL = '0b7e4d33-8c2a-4f6e-b1d9-5a3f2e7c9d01';
  it('chooses the input sample events preview as, including inputs only the draft names', () => {
    const onPreviewInputChange = vi.fn();
    render(
      <PipelinePreviewPanel
        samples={[]}
        revision={1}
        pending={false}
        canViewEvents
        available
        selectedStepId={null}
        onSampleSelect={vi.fn()}
        onPreview={vi.fn()}
        laneInputs={[{ id: `push:${PUSH}`, kind: 'push', label: 'Firewall HEC' }]}
        routedInputs={[`push:${PUSH}`, `pull:${PULL}`]}
        previewInput={null}
        onPreviewInputChange={onPreviewInputChange}
      />
    );
    const select = screen.getByLabelText('Preview as input') as HTMLSelectElement;
    expect(Array.from(select.options).map((option) => option.value)).toEqual(['', `push:${PUSH}`, `pull:${PULL}`]);
    fireEvent.change(select, { target: { value: `pull:${PULL}` } });
    expect(onPreviewInputChange).toHaveBeenLastCalledWith(`pull:${PULL}`);
    fireEvent.change(select, { target: { value: '' } });
    expect(onPreviewInputChange).toHaveBeenLastCalledWith(null);
  });
  it('stays hidden for lanes without listed or routed inputs', () => {
    render(
      <PipelinePreviewPanel samples={[]} revision={1} pending={false} canViewEvents available selectedStepId={null}
        onSampleSelect={vi.fn()} onPreview={vi.fn()} onPreviewInputChange={vi.fn()} />
    );
    expect(screen.queryByLabelText('Preview as input')).toBeNull();
  });
});
