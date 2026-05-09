// SPDX-License-Identifier: AGPL-3.0-or-later

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { ReactNode } from 'react';

export interface RightPanelTab {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  content: ReactNode;
  iconColor?: string;
}

interface RightPanelProps {
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  activeTab: string;
  onTabChange: (tab: string) => void;
  tabs: RightPanelTab[];
}

export function RightPanel({
  collapsed,
  onCollapsedChange,
  activeTab,
  onTabChange,
  tabs,
}: RightPanelProps) {
  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-muted/10">
      {collapsed ? (
        <div className="flex-1 flex flex-col items-center py-4 gap-4">
          <button
            onClick={() => onCollapsedChange(false)}
            className="p-2 hover:bg-transparent rounded-lg transition-colors text-muted-foreground hover:text-primary"
            title="Expand panel"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                onCollapsedChange(false);
                onTabChange(tab.id);
              }}
              className={`p-2 hover:bg-transparent rounded-lg transition-colors ${tab.iconColor || 'text-muted-foreground hover:text-primary'}`}
              title={tab.label}
            >
              <tab.icon className="w-5 h-5" />
            </button>
          ))}
        </div>
      ) : (
        <Tabs value={activeTab} onValueChange={onTabChange} className="flex-1 flex flex-col min-h-0">
          <div className="flex items-center justify-between border-b border-border px-2 py-2">
            <TabsList className="rounded-lg border border-border/60 bg-card p-0.5">
              {tabs.map((tab) => (
                <TabsTrigger
                  key={tab.id}
                  value={tab.id}
                  className="rounded-md px-2.5 py-1 text-[11px] font-mono uppercase tracking-[0.12em] data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                >
                  <tab.icon className="w-4 h-4 mr-2" />
                  {tab.label}
                </TabsTrigger>
              ))}
            </TabsList>
            <button
              onClick={() => onCollapsedChange(true)}
              className="p-2 hover:bg-transparent rounded-lg transition-colors text-muted-foreground hover:text-primary"
              title="Collapse panel"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          {tabs.map((tab) => (
            <TabsContent key={tab.id} value={tab.id} className="mt-0 min-h-0 flex-1 overflow-y-auto p-4">
              {tab.content}
            </TabsContent>
          ))}
        </Tabs>
      )}
    </div>
  );
}
