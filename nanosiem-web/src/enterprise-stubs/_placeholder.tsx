// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared placeholder rendered by every page-level enterprise stub. The
// `@/enterprise/pages/*` alias resolves to this directory in open-edition
// Vite builds (`VITE_EDITION=open`); each stub re-exports its named
// component as `EnterprisePagePlaceholder` so route mounting still works
// but the rendered content explains why the surface is unavailable.
//
// Imports stay inside src/enterprise-stubs/ — never reach back into open
// code beyond ui primitives — so the stubs tree-shake cleanly.

import { Link, useLocation } from 'react-router-dom';
import { Lock } from 'lucide-react';

// Accepts arbitrary props and discards them — page stubs reuse this for
// surfaces whose real implementations take props (e.g., CaseInvestigate's
// optional `id`). Consumers see the real signature via TS path resolution;
// at runtime the stub silently ignores anything passed.
export function EnterprisePagePlaceholder(_props?: Record<string, unknown>) {
  const location = useLocation();
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-8 select-none">
      <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center mb-4">
        <Lock className="w-6 h-6 text-muted-foreground" />
      </div>
      <h1 className="text-[15px] font-semibold text-foreground mb-2">
        Available in nano paid plans
      </h1>
      <p className="text-[12.5px] text-muted-foreground mb-1 max-w-md">
        This surface ships with paid nano editions. The open-core build
        you're running doesn't include it.
      </p>
      <code className="text-[10.5px] text-muted-foreground/60 font-mono mb-6">
        {location.pathname}
      </code>
      <div className="flex items-center gap-2">
        <Link
          to="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-border text-foreground font-medium text-[12.5px] hover:bg-muted transition-colors"
        >
          Back to Home
        </Link>
        <a
          href="https://nano.rs/pricing"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium text-[12.5px] hover:bg-primary/90 transition-colors"
        >
          See pricing
        </a>
      </div>
    </div>
  );
}
