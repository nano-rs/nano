// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4754: the Review step gate must come from real state. The AU report:
 * every row green ("Tests · not run" included), footer "Acknowledge warnings
 * to deploy", no acknowledge control, an empty parser called valid.
 */
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { DeployGatePanel } from './DeployGatePanel';
import { computeDeployGate, isEmptyVrl, type DeployGateInput, type GateAction } from './deploy-gate';

afterEach(cleanup);

const VRL = '. = parse_json!(.message)';

function input(over: Partial<DeployGateInput> = {}): DeployGateInput {
  return {
    shared: true,
    strictOcsf: true,
    feedId: 'vercel',
    name: 'vercel',
    sourceConfigId: '',
    vrl: VRL,
    syntaxValid: true,
    isValidating: false,
    errors: 0,
    warningMessages: [],
    sampleCount: 1,
    testsRun: true,
    isTesting: false,
    passingTests: 1,
    failingTests: 0,
    transportReady: null,
    namespaceValid: true,
    acknowledged: false,
    ...over,
  };
}

function Harness({ over, onAction = () => {} }: { over: Partial<DeployGateInput>; onAction?: (a: GateAction) => void }) {
  const [ack, setAck] = useState(false);
  const gate = computeDeployGate(input({ ...over, acknowledged: ack }));
  return (
    <>
      <DeployGatePanel gate={gate} acknowledged={ack} setAcknowledged={setAck} onAction={onAction} shared />
      <button type="button" disabled={!gate.canDeploy}>
        Activate source
      </button>
    </>
  );
}

const activate = () => screen.getByRole('button', { name: 'Activate source' });

describe('deploy gate (NAN-4754)', () => {
  it('tests not run with 0 warnings: blocked on the tests row, no acknowledge control, Run tests offered', () => {
    const onAction = vi.fn();
    render(<Harness over={{ testsRun: false, passingTests: 0 }} onAction={onAction} />);
    expect(screen.getByTestId('gate-tests').getAttribute('data-status')).toBe('block');
    expect(screen.getByTestId('gate-tests').textContent).toContain('Tests · not run against 1 sample');
    expect(screen.getByTestId('gate-diagnostics').textContent).toContain('no warnings');
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.getByTestId('gate-status').textContent).toContain('Blocked · Tests · not run against 1 sample');
    expect(screen.getByTestId('gate-status').textContent).not.toMatch(/acknowledge/i);
    expect((activate() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Run tests' }));
    expect(onAction).toHaveBeenCalledWith('run-tests');
  });

  it('an empty VRL is not valid: blocked, points back to step 2', () => {
    const onAction = vi.fn();
    render(<Harness over={{ vrl: '', syntaxValid: null, testsRun: false, passingTests: 0 }} onAction={onAction} />);
    expect(screen.getByTestId('gate-parser').getAttribute('data-status')).toBe('block');
    expect(screen.getByTestId('gate-parser').textContent).toContain('Parser · empty · draft or write one in step 2');
    expect(screen.queryByText(/VRL syntax · valid/)).toBeNull();
    expect(screen.queryByTestId('gate-diagnostics')).toBeNull();
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect((activate() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getAllByRole('button', { name: 'Go to step 2' })[0]);
    expect(onAction).toHaveBeenCalledWith('step2');
  });

  it('warnings present: listed with an acknowledge checkbox; acknowledging enables activation', () => {
    render(<Harness over={{ warningMessages: ['unused variable `x`', 'fallible call'] }} />);
    expect(screen.getByTestId('gate-diagnostics').getAttribute('data-status')).toBe('warn');
    expect(screen.getByText('unused variable `x`')).toBeTruthy();
    expect(screen.getByText('fallible call')).toBeTruthy();
    expect(screen.getByTestId('gate-status').textContent).toContain('Acknowledge the warnings above to activate');
    expect((activate() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByTestId('gate-status').textContent).toContain('Cleared to activate');
    expect((activate() as HTMLButtonElement).disabled).toBe(false);
  });

  it('no warnings and passing samples: cleared with no acknowledgement', () => {
    render(<Harness over={{}} />);
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.getByTestId('gate-tests').textContent).toContain('Tests · 1/1 samples pass');
    expect((activate() as HTMLButtonElement).disabled).toBe(false);
  });

  it('hosted, no samples yet: one stated path — acknowledge and activate, iterate from first logs', () => {
    render(<Harness over={{ sampleCount: 0, testsRun: false, passingTests: 0 }} />);
    expect(screen.getByTestId('gate-tests').getAttribute('data-status')).toBe('warn');
    expect(screen.getByText(/send the first logs, then iterate the parser/)).toBeTruthy();
    expect((activate() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    expect((activate() as HTMLButtonElement).disabled).toBe(false);
  });
});

describe('computeDeployGate', () => {
  it('dedicated OCSF without samples is blocked (the server requires a passing sample)', () => {
    const gate = computeDeployGate(input({ shared: false, sourceConfigId: 'sc', transportReady: true, sampleCount: 0 }));
    expect(gate.blocker?.id).toBe('tests');
    expect(gate.canDeploy).toBe(false);
  });

  it('failing samples block', () => {
    const gate = computeDeployGate(input({ passingTests: 1, failingTests: 1, sampleCount: 2 }));
    expect(gate.blocker?.label).toBe('Tests · 1 of 2 samples fail · fix in step 2');
  });

  it('comment-only VRL counts as empty', () => {
    expect(isEmptyVrl('  \n# todo\n')).toBe(true);
    expect(isEmptyVrl(VRL)).toBe(false);
  });
});
