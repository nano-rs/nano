// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4754 (ported to the ClickHouse product, NAN-4912): the Add data wizard's
 * Review step gate, computed from real state.
 *
 * The rule the UI states:
 *  - A parser is required: non-empty VRL (comments alone do not count) that
 *    passes the syntax check. An empty parser points back to the Parse step.
 *  - Samples are the tests. With samples (pasted, or pulled from the events the
 *    source already received), every sample must run through the parser and
 *    pass before publishing.
 *  - No samples is allowed (except under OCSF, whose server refuses a publish
 *    without a passing sample): it is a listed warning to acknowledge. Publish,
 *    let the first logs arrive, then iterate the parser from that data.
 *  - Connection: a push source with no token and no received events is a
 *    warning (publishing is fine; events arrive once a sender uses a token). A
 *    pull source whose source configuration is not enabled and deployed is a
 *    warning too.
 *  - Every warning needs the one explicit acknowledgement. No warnings, no
 *    acknowledgement.
 */

export type GateStatus = 'ok' | 'warn' | 'block' | 'pending';
/** Where a check's fix lives: the Source step, the Connect step, the Parse step, or re-running tests. */
export type GateAction = 'step1' | 'connect' | 'step2' | 'run-tests';

export interface GateCheck {
  id: 'source' | 'parser' | 'tests' | 'diagnostics' | 'transport' | 'namespace';
  status: GateStatus;
  label: string;
  /** Extra lines under the row (diagnostic messages). */
  details?: string[];
  action?: GateAction;
}

export interface DeployGateInput {
  /** `push`: a token decides the source (HTTP / HEC / OTLP). `pull`: a source configuration routes it. */
  transport: 'push' | 'pull';
  strictOcsf: boolean;
  feedId: string;
  name: string;
  sourceConfigId: string;
  vrl: string;
  /** null = not validated yet. */
  syntaxValid: boolean | null;
  isValidating: boolean;
  errors: number;
  warningMessages: string[];
  sampleCount: number;
  testsRun: boolean;
  isTesting: boolean;
  passingTests: number;
  failingTests: number;
  /** Pull only: the source configuration is enabled and deployed. null = checking. */
  transportReady: boolean | null;
  transportLabel?: string;
  /** Push only: active tokens bound to the source and events received (24 h). null = unknown. */
  connection?: { activeTokens: number; eventsReceived: number } | null;
  namespaceValid: boolean | null;
  namespaceError?: string;
  acknowledged: boolean;
}

export interface DeployGate {
  checks: GateCheck[];
  /** The checks the acknowledgement covers; empty = no acknowledgement shown or needed. */
  warnings: GateCheck[];
  /** First blocking (or still pending) check, if any. */
  blocker: GateCheck | null;
  canDeploy: boolean;
  /** One line for the gate footer. */
  status: string;
}

/** True when the VRL has no statement: blank, or only comments. */
export function isEmptyVrl(vrl: string): boolean {
  return vrl.split(/\r?\n/).every((line) => {
    const t = line.trim();
    return t === '' || t.startsWith('#');
  });
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

function connectionCheck(input: DeployGateInput): GateCheck {
  if (input.transport === 'pull') {
    if (input.transportReady === null) return { id: 'transport', status: 'pending', label: 'Transport · checking…' };
    if (input.transportReady) return { id: 'transport', status: 'ok', label: 'Transport ready' };
    return {
      id: 'transport',
      status: 'warn',
      label: input.transportLabel ?? 'Transport · not ready',
      details: ["Events won't arrive until the source configuration is enabled and deployed."],
    };
  }
  const c = input.connection;
  if (!c) return { id: 'transport', status: 'pending', label: 'Connection · checking…' };
  if (c.eventsReceived > 0) {
    return { id: 'transport', status: 'ok', label: `Connection · ${plural(c.eventsReceived, 'event')} received (24h)` };
  }
  if (c.activeTokens > 0) {
    return {
      id: 'transport',
      status: 'warn',
      label: `Connection · ${plural(c.activeTokens, 'token')} issued · no events yet`,
      details: ['Publishing is fine: events are parsed as soon as a sender uses the token.'],
    };
  }
  return {
    id: 'transport',
    status: 'warn',
    label: 'Connection · no token issued',
    details: ['Nothing can send to this source until a token is issued (Connect step, or Ingestion → Ingest tokens).'],
    action: 'connect',
  };
}

export function computeDeployGate(input: DeployGateInput): DeployGate {
  const checks: GateCheck[] = [];

  if (!input.feedId || !input.name || (input.transport === 'pull' && !input.sourceConfigId)) {
    checks.push({
      id: 'source',
      status: 'block',
      label: input.transport === 'pull' ? 'Source · pick a source configuration and name in step 1' : 'Source · set its key and name in step 1',
      action: 'step1',
    });
  }

  const emptyParser = isEmptyVrl(input.vrl);
  if (emptyParser) {
    checks.push({ id: 'parser', status: 'block', label: 'Parser · empty · draft or write one in step 3', action: 'step2' });
  } else if (input.isValidating || input.syntaxValid === null) {
    checks.push({ id: 'parser', status: 'pending', label: 'VRL syntax · checking…' });
  } else if (input.errors > 0 || input.syntaxValid === false) {
    const n = Math.max(input.errors, 1);
    checks.push({ id: 'parser', status: 'block', label: `VRL syntax · ${plural(n, 'error')} · fix in step 3`, action: 'step2' });
  } else {
    checks.push({ id: 'parser', status: 'ok', label: 'VRL syntax · valid' });
  }

  const samples = plural(input.sampleCount, 'sample');
  if (emptyParser) {
    checks.push({
      id: 'tests',
      status: 'block',
      label: input.sampleCount > 0 ? `Tests · ${samples} waiting for a parser` : 'Tests · waiting for a parser',
    });
  } else if (input.sampleCount > 0) {
    if (input.isTesting) {
      checks.push({ id: 'tests', status: 'pending', label: `Tests · running ${samples}…` });
    } else if (!input.testsRun) {
      checks.push({ id: 'tests', status: 'block', label: `Tests · not run against ${samples}`, action: 'run-tests' });
    } else if (input.failingTests > 0) {
      const total = input.passingTests + input.failingTests;
      checks.push({ id: 'tests', status: 'block', label: `Tests · ${input.failingTests} of ${total} samples fail · fix in step 3`, action: 'step2' });
    } else {
      checks.push({ id: 'tests', status: 'ok', label: `Tests · ${input.passingTests}/${input.passingTests} samples pass` });
    }
  } else if (input.strictOcsf) {
    checks.push({ id: 'tests', status: 'block', label: 'Tests · OCSF publish needs one passing sample · add it in step 3', action: 'step2' });
  } else {
    checks.push({
      id: 'tests',
      status: 'warn',
      label: 'Tests · no samples · parser is syntax-checked only',
      details: ['Publish, send the first logs, then iterate the parser from that data.'],
    });
  }

  if (!emptyParser && input.syntaxValid === true) {
    const n = input.warningMessages.length;
    checks.push(
      n > 0
        ? { id: 'diagnostics', status: 'warn', label: `Diagnostics · ${plural(n, 'warning')}`, details: input.warningMessages }
        : { id: 'diagnostics', status: 'ok', label: 'Diagnostics · no warnings' },
    );
  }

  checks.push(connectionCheck(input));

  if (input.namespaceValid === false) {
    checks.push({ id: 'namespace', status: 'block', label: `Namespace · ${input.namespaceError ?? 'invalid'}`, action: 'step1' });
  } else if (input.namespaceValid === null) {
    checks.push({ id: 'namespace', status: 'pending', label: 'Namespace · checking…' });
  } else {
    checks.push({ id: 'namespace', status: 'ok', label: 'Namespace valid' });
  }

  const warnings = checks.filter((c) => c.status === 'warn');
  const blocker = checks.find((c) => c.status === 'block' || c.status === 'pending') ?? null;
  const canDeploy = !blocker && (warnings.length === 0 || input.acknowledged);
  const status = canDeploy
    ? 'Cleared to publish'
    : blocker
      ? blocker.status === 'pending'
        ? `Waiting · ${blocker.label}`
        : `Blocked · ${blocker.label}`
      : 'Acknowledge the warnings above to publish';
  return { checks, warnings, blocker, canDeploy, status };
}
