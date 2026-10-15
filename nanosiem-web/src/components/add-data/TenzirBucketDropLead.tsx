// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3844: the Sources page lead on an `install.sh --tenzir` install. Data
 * arrives only through the Tenzir bucket drop (NAN-3807), so the page opens
 * with the source-key flow and the bucket drop status, ahead of the parser
 * list. Keys are minted on the install host by `lean-landing-admin` (it holds
 * the object-store admin rights the API does not), so the UI shows the command
 * rather than a button.
 */

import { CopyButton } from '@/components/add-data/CopyButton';
import { LandingSourcesPanel } from '@/components/add-data/LandingSourcesPanel';

export const TENZIR_ADD_SOURCE_COMMAND =
  'docker compose -f docker-compose.opensource.yml run --rm lean-landing-admin add --name <name>';
export const TENZIR_BUNDLED_NODE_COMMAND =
  'docker compose -f docker-compose.opensource.yml --profile tenzir up -d tenzir';

function Command({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2 mt-1">
      <code className="flex-1 min-w-0 truncate rounded-sm border border-border bg-muted/40 px-2 h-6 leading-6 font-mono text-[11px] text-foreground select-all">
        {text}
      </code>
      <CopyButton text={text} aria-label={`Copy ${text}`} />
    </div>
  );
}

export function TenzirBucketDropLead() {
  return (
    <section className="shrink-0 border-b border-border px-5 py-4 space-y-4" data-testid="tenzir-bucket-drop-lead">
      <div>
        <h2 className="text-[12.5px] font-medium text-foreground">Tenzir bucket drop</h2>
        <p className="mt-0.5 text-[11.5px] text-muted-foreground">
          This install has no Vector. Tenzir maps your logs to OCSF and writes Parquet files straight into this
          install's object store; each file is converted and becomes searchable.
        </p>
      </div>

      <ol className="space-y-2.5 text-[11.5px] text-foreground">
        <li>
          <span className="font-mono text-[10.5px] text-muted-foreground mr-1.5">1</span>
          Create a source key on the install host. It prints the write-only key and a ready-to-paste Tenzir{' '}
          <span className="font-mono text-[10.5px]">to_s3</span> sink, once.
          <Command text={TENZIR_ADD_SOURCE_COMMAND} />
        </li>
        <li>
          <span className="font-mono text-[10.5px] text-muted-foreground mr-1.5">2</span>
          Paste the sink into your Tenzir pipeline and run it on this install's compose network (endpoint{' '}
          <span className="font-mono text-[10.5px]">lake-object-store:9000</span>), or start the bundled node:
          <Command text={TENZIR_BUNDLED_NODE_COMMAND} />
        </li>
        <li>
          <span className="font-mono text-[10.5px] text-muted-foreground mr-1.5">3</span>
          Files show up below as they land, with accepted and refused rows per file.
        </li>
      </ol>

      <LandingSourcesPanel />
    </section>
  );
}
