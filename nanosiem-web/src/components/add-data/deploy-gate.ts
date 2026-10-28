// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4754: the Add data wizard's Review step gate, computed from real state.
 *
 * The rule the UI states:
 *  - A parser is required: non-empty VRL (comments alone do not count) that
 *    passes the syntax check. An empty parser points back to step 2.
 *  - Pasted samples are the tests. With samples, every sample must run
 *    through the parser and pass before activation.
 *  - No samples is allowed (except a dedicated OCSF deployment, whose server
 *    refuses a deploy without a passing sample): it is a listed warning to
 *    acknowledge. Activate, let the first logs arrive, then iterate the parser
 *    from that data.
 *  - Every other warning (VRL diagnostics, a dedicated transport not ready) is
 *    listed and needs the one explicit acknowledgement. No warnings, no
 *    acknowledgement.
 */

export type GateStatus = 'ok' | 'warn' | 'block' | 'pending';
/** Where a check's fix lives: step 1, step 2, or re-running the sample tests. */
export type GateAction = 'step1' | 'step2' | 'run-tests';

export interface GateCheck {
  id: 'source' | 'parser' | 'tests' | 'diagnostics' | 'transport' | 'namespace';
  status: GateStatus;
  label: string;
  /** Extra lines under the row (diagnostic messages). */
  details?: string[];
  action?: GateAction;
}

export interface DeployGateInput {
  shared: boolean;
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
  transportReady: boolean | null;
  transportLabel?: string;
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

export function computeDeployGate(input: DeployGateInput): DeployGate {
  const checks: GateCheck[] = [];
  const verb = input.shared ? 'activate' : 'deploy';

  if (!input.feedId || !input.name || (!input.shared && !input.sourceConfigId)) {
    checks.push({
      id: 'source',
      status: 'block',
      label: input.shared ? 'Source · set its name in step 1' : 'Source · pick a transport and name in step 1',
      action: 'step1',
    });
  }

  const emptyParser = isEmptyVrl(input.vrl);
  if (emptyParser) {
    checks.push({ id: 'parser', status: 'block', label: 'Parser · empty · draft or write one in step 2', action: 'step2' });
  } else if (input.isValidating || input.syntaxValid === null) {
    checks.push({ id: 'parser', status: 'pending', label: 'VRL syntax · checking…' });
  } else if (input.errors > 0 || input.syntaxValid === false) {
    const n = Math.max(input.errors, 1);
    checks.push({ id: 'parser', status: 'block', label: `VRL syntax · ${plural(n, 'error')} · fix in step 2`, action: 'step2' });
  } else {
    checks.push({ id: 'parser', status: 'ok', label: 'VRL syntax · valid' });
  }

  const samples = plural(input.sampleCount, 'sample');
  if (emptyParser) {
    // Nothing to test yet; the parser row carries the fix.
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
      checks.push({ id: 'tests', status: 'block', label: `Tests · ${input.failingTests} of ${total} samples fail · fix in step 2`, action: 'step2' });
    } else {
      checks.push({ id: 'tests', status: 'ok', label: `Tests · ${input.passingTests}/${input.passingTests} samples pass` });
    }
  } else if (!input.shared && input.strictOcsf) {
    checks.push({ id: 'tests', status: 'block', label: 'Tests · OCSF deploy needs one passing sample · paste it in step 2', action: 'step2' });
  } else {
    checks.push({
      id: 'tests',
      status: 'warn',
      label: `Tests · no samples · parser is syntax-checked only`,
      details: [`${verb === 'activate' ? 'Activate' : 'Deploy'}, send the first logs, then iterate the parser from that data.`],
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

  if (!input.shared) {
    if (input.transportReady === null) {
      checks.push({ id: 'transport', status: 'pending', label: 'Transport · checking…' });
    } else if (input.transportReady) {
      checks.push({ id: 'transport', status: 'ok', label: 'Transport ready' });
    } else {
      checks.push({
        id: 'transport',
        status: 'warn',
        label: input.transportLabel ?? 'Transport · not ready',
        details: ["Events won't arrive until the source config is enabled and deployed."],
      });
    }
  }

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
    ? `Cleared to ${verb}`
    : blocker
      ? blocker.status === 'pending'
        ? `Waiting · ${blocker.label}`
        : `Blocked · ${blocker.label}`
      : `Acknowledge the warnings above to ${verb}`;
  return { checks, warnings, blocker, canDeploy, status };
}
