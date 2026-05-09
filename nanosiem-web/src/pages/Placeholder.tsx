// SPDX-License-Identifier: AGPL-3.0-or-later

import { Card, CardContent } from '@/components/ui/card';
import { Construction } from 'lucide-react';

interface PlaceholderProps {
  title: string;
  description: string;
}

export function Placeholder({ title, description }: PlaceholderProps) {
  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">{title}</h1>
        <p className="text-muted-foreground mt-1">{description}</p>
      </div>

      <Card className="bg-card border-gray-800">
        <CardContent className="p-12">
          <div className="flex flex-col items-center justify-center text-center">
            <Construction className="w-16 h-16 text-muted-foreground mb-4" />
            <h2 className="text-xl font-semibold text-foreground mb-2">Coming Soon</h2>
            <p className="text-muted-foreground">This feature is currently under development.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
