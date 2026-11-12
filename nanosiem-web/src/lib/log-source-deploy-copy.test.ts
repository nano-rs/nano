// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { deployDialogDescription } from './log-source-deploy-copy';

// NAN-5321: Deploy claimed to use "the current VRL" while it redeployed the active version.
describe('deployDialogDescription', () => {
  it('never-published source deploys its working copy', () => {
    expect(deployDialogDescription('apache', null, true)).toContain('current VRL');
  });
  it('published source redeploys the active version', () => {
    const d = deployDialogDescription('apache', 3, false);
    expect(d).toContain('published version (v3)');
    expect(d).not.toContain('current VRL');
  });
  it('says an unpublished draft is not included', () => {
    expect(deployDialogDescription('apache', 3, true)).toMatch(/draft changes are not included.*Publish/);
  });
});
