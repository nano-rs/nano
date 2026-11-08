// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4754 (ported, NAN-4912): the Review step gate comes from real state.
 * The original report: every row green ("Tests · not run" included), footer
 * "Acknowledge warnings to deploy", no acknowledge control, an empty parser
 * called valid. On the ClickHouse product the gate also says whether a push
 * source is connected (token issued, events received).
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
    transport: 'push',
    strictOcsf: false,
    feedId: 'acme_vpn',
    name: 'Acme VPN',
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
    connection: { activeTokens: 1, eventsReceived: 3 },
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
      <DeployGatePanel gate={gate} acknowledged={ack} setAcknowledged={setAck} onAction={onAction} />
      <button type="button" disabled={!gate.canDeploy}>
        Publish source
      </button>
    </>
  );
}

const publish = () => screen.getByRole('button', { name: 'Publish source' }) as HTMLButtonElement;

describe('deploy gate (NAN-4754, dedicated)', () => {
  it('tests not run with 0 warnings: blocked on the tests row, no acknowledge control, Run tests offered', () => {
    const onAction = vi.fn();
    render(<Harness over={{ testsRun: false, passingTests: 0 }} onAction={onAction} />);
    expect(screen.getByTestId('gate-tests').getAttribute('data-status')).toBe('block');
    expect(screen.getByTestId('gate-tests').textContent).toContain('Tests · not run against 1 sample');
    expect(screen.getByTestId('gate-diagnostics').textContent).toContain('no warnings');
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.getByTestId('gate-status').textContent).toContain('Blocked · Tests · not run against 1 sample');
    expect(publish().disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Run tests' }));
    expect(onAction).toHaveBeenCalledWith('run-tests');
  });

  it('an empty VRL is not valid: blocked, points back to the Parse step', () => {
    const onAction = vi.fn();
    render(<Harness over={{ vrl: '', syntaxValid: null, testsRun: false, passingTests: 0 }} onAction={onAction} />);
    expect(screen.getByTestId('gate-parser').getAttribute('data-status')).toBe('block');
    expect(screen.getByTestId('gate-parser').textContent).toContain('Parser · empty · draft or write one in step 3');
    expect(screen.queryByTestId('gate-diagnostics')).toBeNull();
    expect(publish().disabled).toBe(true);
    fireEvent.click(screen.getAllByRole('button', { name: 'Go to step 3' })[0]);
    expect(onAction).toHaveBeenCalledWith('step2');
  });

  it('warnings present: listed with an acknowledge checkbox; acknowledging enables publishing', () => {
    render(<Harness over={{ warningMessages: ['unused variable `x`', 'fallible call'] }} />);
    expect(screen.getByTestId('gate-diagnostics').getAttribute('data-status')).toBe('warn');
    expect(screen.getByText('unused variable `x`')).toBeTruthy();
    expect(screen.getByTestId('gate-status').textContent).toContain('Acknowledge the warnings above to publish');
    expect(publish().disabled).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByTestId('gate-status').textContent).toContain('Cleared to publish');
    expect(publish().disabled).toBe(false);
  });

  it('receiving events and passing samples: cleared with no acknowledgement', () => {
    render(<Harness over={{}} />);
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.getByTestId('gate-transport').textContent).toContain('Connection · 3 events received (24h)');
    expect(screen.getByTestId('gate-tests').textContent).toContain('Tests · 1/1 samples pass');
    expect(publish().disabled).toBe(false);
  });

  it('no token issued: a warning that points back to Connect', () => {
    const onAction = vi.fn();
    render(<Harness over={{ connection: { activeTokens: 0, eventsReceived: 0 } }} onAction={onAction} />);
    expect(screen.getByTestId('gate-transport').getAttribute('data-status')).toBe('warn');
    expect(screen.getByTestId('gate-transport').textContent).toContain('Connection · no token issued');
    fireEvent.click(screen.getByRole('button', { name: 'Go to step 2' }));
    expect(onAction).toHaveBeenCalledWith('connect');
    expect(publish().disabled).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    expect(publish().disabled).toBe(false);
  });

  it('no samples yet: acknowledge and publish, iterate from first logs', () => {
    render(<Harness over={{ sampleCount: 0, testsRun: false, passingTests: 0 }} />);
    expect(screen.getByTestId('gate-tests').getAttribute('data-status')).toBe('warn');
    expect(screen.getByText(/send the first logs, then iterate the parser/)).toBeTruthy();
    expect(publish().disabled).toBe(true);
    fireEvent.click(screen.getByRole('checkbox'));
    expect(publish().disabled).toBe(false);
  });
});

describe('computeDeployGate', () => {
  it('OCSF without samples is blocked (the server requires a passing sample)', () => {
    const gate = computeDeployGate(input({ strictOcsf: true, sampleCount: 0 }));
    expect(gate.blocker?.id).toBe('tests');
    expect(gate.canDeploy).toBe(false);
  });

  it('a pull source needs its source configuration and a ready transport', () => {
    expect(computeDeployGate(input({ transport: 'pull', sourceConfigId: '' })).blocker?.id).toBe('source');
    const notReady = computeDeployGate(input({ transport: 'pull', sourceConfigId: 'sc', transportReady: false }));
    expect(notReady.warnings.map((w) => w.id)).toEqual(['transport']);
    expect(computeDeployGate(input({ transport: 'pull', sourceConfigId: 'sc', transportReady: true })).canDeploy).toBe(true);
  });

  it('failing samples block', () => {
    const gate = computeDeployGate(input({ passingTests: 1, failingTests: 1, sampleCount: 2 }));
    expect(gate.blocker?.label).toBe('Tests · 1 of 2 samples fail · fix in step 3');
  });

  it('comment-only VRL counts as empty', () => {
    expect(isEmptyVrl('  \n# todo\n')).toBe(true);
    expect(isEmptyVrl(VRL)).toBe(false);
  });
});
