// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Quick Actions Component
 *
 * Action buttons for common tasks.
 */

import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { ShieldPlus, AlertTriangle, Upload, Search } from 'lucide-react';

export function QuickActions() {
  const actions = [
    { label: 'New Rule', icon: ShieldPlus, to: '/rules/editor/new', color: 'bg-primary hover:bg-primary/90' },
    { label: 'Alerts', icon: AlertTriangle, to: '/alerts', color: 'bg-amber-600 hover:bg-amber-700' },
    { label: 'Upload', icon: Upload, to: '/upload', color: 'bg-ai hover:bg-ai-muted' },
    { label: 'Search', icon: Search, to: '/search', color: 'bg-cyan-600 hover:bg-cyan-700' },
  ];

  return (
    <div className="flex gap-2">
      {actions.map((action) => (
        <Link key={action.label} to={action.to}>
          <Button
            size="sm"
            className={`${action.color} rounded-xl h-9 px-3 text-xs font-medium`}
          >
            <action.icon className="w-3.5 h-3.5" />
            {action.label}
          </Button>
        </Link>
      ))}
    </div>
  );
}
