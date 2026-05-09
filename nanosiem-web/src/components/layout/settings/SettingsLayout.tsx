// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * SettingsLayout — dedicated shell for the /settings area.
 *
 * Replaces the main `AppLayout` chrome whenever the user is on a /settings
 * route. Owns its own rail / topbar / status bar / Recent Changes drawer.
 *
 * Mirrors `design-ref/settings.html` + `design-ref/shadcn/settings-app.jsx`.
 */

import { ReactNode, useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { ScrollContainerProvider } from '@/contexts/ScrollContainerContext';
import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { TooltipProvider } from '@/components/ui/tooltip';
import { usePivtState } from '@/enterprise/hooks/use-pivt-state';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { LicenseBanner } from '@/components/LicenseBanner';
import { DemoBanner } from '@/components/DemoBanner';
import { SettingsRail } from './SettingsRail';
import { SettingsTopbar } from './SettingsTopbar';
import { SettingsStatusBar } from './SettingsStatusBar';
import { RecentChangesDrawer } from './RecentChangesDrawer';

interface SettingsLayoutProps {
  children: ReactNode;
}

export function SettingsLayout({ children }: SettingsLayoutProps) {
  const navigate = useNavigate();
  const [auditOpen, setAuditOpen] = useState(false);
  const pivt = usePivtState();
  const scrollRef = useRef<HTMLDivElement>(null);

  const onBackToApp = useCallback(() => navigate('/'), [navigate]);

  return (
    <TooltipProvider>
    <BreadcrumbProvider>
      <ScrollContainerProvider value={scrollRef}>
          <div
            className="h-screen text-foreground flex flex-col overflow-hidden"
            style={{ background: 'var(--background)' }}
          >
            <DemoBanner />
            <LicenseBanner />

            <div
              className="flex-1 grid relative overflow-hidden"
              style={{
                gridTemplateColumns: '232px 1fr',
                gridTemplateRows: '42px 1fr 22px',
              }}
            >
              {/* Left rail spans all 3 rows of column 1 */}
              <SettingsRail onBackToApp={onBackToApp} />

              {/* Topbar */}
              <SettingsTopbar
                onOpenAudit={() => setAuditOpen(v => !v)}
                auditOpen={auditOpen}
                pivt={pivt}
              />

              {/* Body — column 2, row 2 */}
              <main
                className="col-start-2 row-start-2 min-h-0 min-w-0 overflow-hidden flex"
                style={{ background: 'var(--background)' }}
              >
                <PivtShellOverlay state={pivt}>
                  <div ref={scrollRef} className="flex-1 min-w-0 overflow-y-auto scrollbar-thin">
                    {children}
                  </div>
                </PivtShellOverlay>
              </main>

              {/* Status bar */}
              <SettingsStatusBar />

              {/* Right-edge drawer */}
              <RecentChangesDrawer open={auditOpen} onClose={() => setAuditOpen(false)} />
            </div>
          </div>
      </ScrollContainerProvider>
    </BreadcrumbProvider>
    </TooltipProvider>
  );
}
