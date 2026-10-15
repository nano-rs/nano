// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type {
  AssetDossierAuth, AssetDossierDns, AssetDossierFiles, AssetDossierNetwork, AssetDossierProcesses,
} from '@/lib/api/types';
import { ProcessesCard } from './ProcessesCard';
import { NetworkCard } from './NetworkCard';
import { AuthCard } from './AuthCard';
import { FilesCard } from './FilesCard';
import { DnsCard } from './DnsCard';

afterEach(cleanup);

const processes = { unique: 0, rare: 0, from_office: 0, top: [], rare_list: [] } as unknown as AssetDossierProcesses;
const network = { total_conns: 0, bytes_in: 0, bytes_out: 0, unique_dsts: 0, new_domains: 0, top_dsts: [], rare_countries: [] } as unknown as AssetDossierNetwork;
const auth = { success: 0, failure: 0, interactive: 0, network: 0, lateral: 0, recent: [] } as unknown as AssetDossierAuth;
const files = { writes: 0, sensitive: 0, exec: 0, recent: [] } as unknown as AssetDossierFiles;
const dns = { queries: 0, unique: 0, nx: 0, rare_tlds: 0, top: [] } as unknown as AssetDossierDns;

function cards(pending: boolean) {
  return render(<div>
    <ProcessesCard processes={processes} pending={pending} />
    <NetworkCard network={network} pending={pending} />
    <AuthCard auth={auth} pending={pending} />
    <FilesCard files={files} pending={pending} />
    <DnsCard dns={dns} pending={pending} />
  </div>);
}

// NAN-3291: while the dossier reads (live: ~20 s before 87 processes and
// 101K auth events landed) an empty card is loading, not "no events".
it('shows a loading state, never the empty-range text, while the dossier reads', () => {
  cards(true);
  expect(screen.getAllByTestId('asset-card-pending')).toHaveLength(5);
  expect(screen.queryByText(/for this entity in range/)).toBeNull();
});

it('shows the empty-range text once the dossier is complete', () => {
  cards(false);
  expect(screen.queryByTestId('asset-card-pending')).toBeNull();
  for (const text of ['No process events', 'No network events', 'No auth events', 'No file events', 'No DNS events']) {
    expect(screen.getByText(new RegExp(`${text} for this entity in range`))).toBeTruthy();
  }
});
