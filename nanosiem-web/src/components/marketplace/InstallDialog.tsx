// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import {
  Sheet, SheetContent, SheetDescription, SheetFooter,
  SheetHeader, SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Loader2, Eye, EyeOff, Lock, Download } from 'lucide-react';
import type { MarketplaceCatalogEntry, CredentialFieldDef } from '@/lib/api/marketplace';

interface InstallDialogProps {
  entry: MarketplaceCatalogEntry | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onInstall: (slug: string, credentials?: Record<string, string>) => Promise<void>;
}

export function InstallDialog({ entry, open, onOpenChange, onInstall }: InstallDialogProps) {
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [installing, setInstalling] = useState(false);
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});

  if (!entry) return null;

  const credentialFields: CredentialFieldDef[] = entry.credential_fields || [];
  const needsCredentials = entry.requires_credential !== 'none' && credentialFields.length > 0;

  const handleInstall = async () => {
    setInstalling(true);
    try {
      await onInstall(entry.slug, needsCredentials ? credentials : undefined);
      onOpenChange(false);
      setCredentials({});
    } finally {
      setInstalling(false);
    }
  };

  const canInstall = () => {
    if (entry.requires_credential === 'required') {
      return credentialFields
        .filter(f => f.required)
        .every(f => credentials[f.name]?.trim());
    }
    return true;
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[420px] overflow-y-auto sm:w-[480px]">
        <SheetHeader className="border-b border-border/50 pb-4">
          <SheetTitle className="search-console-section-header"><Download />Install Enrichment</SheetTitle>
          <SheetDescription>
            {entry.name} · {entry.description}
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-4 py-4">
          <div className="flex gap-2 flex-wrap">
            <Badge variant="outline" className="rounded-lg font-mono text-[10px] uppercase tracking-[0.12em]">{entry.category}</Badge>
            <Badge variant="outline" className="rounded-lg font-mono text-[10px] uppercase tracking-[0.12em]">{entry.execution_backend}</Badge>
            {entry.author && <Badge variant="secondary" className="rounded-lg font-mono text-[10px]">{entry.author}</Badge>}
          </div>

          {needsCredentials && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
                <Lock className="w-4 h-4" />
                <span>
                  {entry.requires_credential === 'required' ? 'Credentials required' : 'Credentials optional'}
                </span>
              </div>
              {credentialFields.map((field) => (
                <div key={field.name} className="space-y-1">
                  <Label htmlFor={field.name} className="search-console-section-meta">
                    {field.label}
                    {field.required && <span className="text-red-500 ml-1">*</span>}
                  </Label>
                  <div className="relative">
                    <Input
                      id={field.name}
                      type={field.field_type === 'secret' && !showSecrets[field.name] ? 'password' : 'text'}
                      placeholder={field.help || `Enter ${field.label}`}
                      value={credentials[field.name] || ''}
                      onChange={(e) => setCredentials(prev => ({ ...prev, [field.name]: e.target.value }))}
                      className="rounded-lg border-border/70 bg-background/60"
                    />
                    {field.field_type === 'secret' && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                        onClick={() => setShowSecrets(prev => ({ ...prev, [field.name]: !prev[field.name] }))}
                      >
                        {showSecrets[field.name] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </Button>
                    )}
                  </div>
                  {field.help && <p className="text-xs text-muted-foreground">{field.help}</p>}
                </div>
              ))}
            </div>
          )}

          {entry.allowed_domains.length > 0 && (
            <div className="text-xs text-muted-foreground">
              <span className="search-console-section-meta">Network access:</span>{' '}
              {entry.allowed_domains.join(', ')}
            </div>
          )}
        </div>

        <SheetFooter className="mt-6 border-t border-border/50 pt-4">
          <Button variant="outline" className="rounded-lg" onClick={() => onOpenChange(false)} disabled={installing}>
            Cancel
          </Button>
          <Button className="rounded-lg" onClick={handleInstall} disabled={installing || !canInstall()}>
            {installing && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Install
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
