// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5088: Create / Connect distinguishes three states from /api/capabilities.
 *   open build                         → provider tab absent (unchanged)
 *   enterprise, license not active     → provider tab disabled + license note
 *   enterprise, license active         → both tabs, no note
 * And the entitlement panel names the license, not the edition, on enterprise.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { BuildEdition, Capabilities } from '@/hooks/use-capabilities';

const state = vi.hoisted(() => ({
  edition: 'open' as BuildEdition,
  licensed: false,
  fallback: false,
  perms: new Set<string>(),
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p: string) => state.perms.has(p) }) }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    edition: state.edition,
    version: 'test',
    ...(state.fallback ? { fallback: true } : {}),
    capabilities: { customEnrichment: state.licensed, agentEnrichment: state.licensed } as Capabilities,
  }),
}));
vi.mock('@/enterprise/pages/CustomEnrichmentWizard', () => ({ CustomEnrichmentWizard: () => <div>provider wizard</div> }));
vi.mock('@/pages/LookupTableCreate', () => ({ LookupTableCreate: () => <div>lookup editor</div> }));

import { InventoryEditor } from './InventoryEditor';
import { InventoryEntitlement } from './InventoryEntitlement';

const AUTHOR = ['enrichments:custom:create', 'enrichments:code', 'lookup:create', 'lookup:view'];

beforeAll(() => {
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
        addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
      }),
    });
  }
});
afterEach(() => cleanup());

function setup(edition: BuildEdition, licensed: boolean, perms: string[] = AUTHOR, fallback = false) {
  state.edition = edition;
  state.licensed = licensed;
  state.fallback = fallback;
  state.perms = new Set(perms);
  render(<MemoryRouter><InventoryEditor definitionId="new" onClose={() => {}} onSaved={() => {}} /></MemoryRouter>);
}

describe('InventoryEditor Create / Connect', () => {
  it('open build: no provider tab and no license note (unchanged)', async () => {
    setup('open', false);
    expect(screen.queryByRole('button', { name: 'TI / Asset provider' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Lookup table' })).toBeTruthy();
    expect(screen.queryByText(/active license/)).toBeNull();
    expect(await screen.findByText('lookup editor')).toBeTruthy();
  });

  it('enterprise without an active license: provider tab disabled with a link to the license page', async () => {
    setup('enterprise', false, [...AUTHOR, 'settings:system']);
    const provider = screen.getByRole('button', { name: 'TI / Asset provider' }) as HTMLButtonElement;
    expect(provider.disabled).toBe(true);
    expect(provider.getAttribute('aria-describedby')).toBe('provider-licence-note');
    expect(screen.getByRole('note').textContent).toMatch(/Custom providers need an active license/);
    expect(screen.getByRole('link', { name: /Settings › License/ }).getAttribute('href')).toBe('/settings/license');
    expect(screen.getByText(/^Add a lookup table\./)).toBeTruthy();
    expect(await screen.findByText('lookup editor')).toBeTruthy();
    expect(screen.queryByText('provider wizard')).toBeNull();
  });

  it('enterprise without an active license and no settings:system: no dead link', () => {
    setup('enterprise', false);
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.getByRole('note').textContent).toMatch(/Ask an administrator/);
  });

  it('enterprise without a license and provider-only permissions: explains the license, not permissions', () => {
    setup('enterprise', false, ['enrichments:custom:create', 'enrichments:code']);
    expect(screen.getByRole('note').textContent).toMatch(/active license/);
    expect(screen.queryByText('Authoring permission required.')).toBeNull();
  });

  it('enterprise before /api/capabilities answers: no license verdict on the fail-closed fallback', () => {
    setup('enterprise', false, AUTHOR, true);
    expect(screen.queryByRole('button', { name: 'TI / Asset provider' })).toBeNull();
    expect(screen.queryByRole('note')).toBeNull();
  });

  it('enterprise with an active license: both tabs enabled, no note', async () => {
    setup('enterprise', true);
    expect((screen.getByRole('button', { name: 'TI / Asset provider' }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByRole('button', { name: 'Lookup table' })).toBeTruthy();
    expect(screen.queryByRole('note')).toBeNull();
    expect(screen.getByText(/^Author a provider or add a lookup table\./)).toBeTruthy();
    expect(await screen.findByText('provider wizard')).toBeTruthy();
  });
});

describe('InventoryEntitlement', () => {
  it('open build names the Enterprise edition', () => {
    render(<MemoryRouter><InventoryEntitlement requirement={{ capability: 'customEnrichment', cause: 'edition', label: 'Enterprise edition' }} edition="open" /></MemoryRouter>);
    expect(screen.getByRole('status').textContent).toBe('Requires the Enterprise edition');
    expect(screen.getByText(/installs and runs unchanged on an enterprise deployment/)).toBeTruthy();
  });

  it('enterprise without a license names the license and links Settings › License', () => {
    render(<MemoryRouter><InventoryEntitlement requirement={{ capability: 'customEnrichment', cause: 'licence', label: 'Active license' }} edition="enterprise" canManageLicence /></MemoryRouter>);
    expect(screen.getByRole('status').textContent).toBe('Requires an active license');
    expect(screen.queryByText(/Enterprise edition|unchanged on an enterprise deployment/)).toBeNull();
    expect(screen.getByRole('link', { name: /Settings › License/ }).getAttribute('href')).toBe('/settings/license');
  });

  it('enterprise without a license and no settings:system: no link', () => {
    render(<MemoryRouter><InventoryEntitlement requirement={{ capability: 'customEnrichment', cause: 'licence', label: 'Active license' }} edition="enterprise" /></MemoryRouter>);
    expect(screen.queryByRole('link')).toBeNull();
    expect(screen.getByText(/Ask an administrator/)).toBeTruthy();
  });
});
