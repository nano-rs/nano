// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Stub page for settings sections that have a rail entry but no implementation
 * yet (notifications, billing, feature flags). Renders inside the new
 * SettingsLayout, so the user keeps the rail/topbar/Recent Changes drawer.
 */

import { useLocation } from 'react-router-dom';
import { Sparkles } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { resolveActiveSection, SECTION_BY_ID } from '@/components/layout/settings/sections';

export function SettingsComingSoon() {
  const location = useLocation();
  const { sectionId } = resolveActiveSection(location.pathname, location.search);
  const section = sectionId ? SECTION_BY_ID[sectionId] : null;
  const title = section?.label || 'Settings';

  useDocumentTitle(`${title} · Settings`);
  useBreadcrumbTitle(title);

  return (
    <div className="h-full">
      <div className="max-w-[640px] mx-auto px-8 py-16 flex flex-col items-center text-center gap-4">
        <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center">
          <Sparkles className="w-6 h-6" />
        </div>
        <div className="text-[18px] font-semibold tracking-tight text-foreground leading-none">{title}</div>
        <div className="text-[12.5px] text-muted-foreground max-w-[420px] leading-relaxed">
          {section?.desc || 'Coming soon.'}
        </div>
      </div>
    </div>
  );
}

export default SettingsComingSoon;
