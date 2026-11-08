// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sigma Rule Converter Component
 *
 * Converts Sigma detection rules to nano format (YAML frontmatter + nPL query)
 * https://github.com/SigmaHQ/sigma
 */

import { useState, useMemo } from 'react';
import { DetailSheet, useDetailSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CircleAlert, CircleCheck, Copy, ArrowRight, FileCode, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import { convertSigmaRule } from './sigma-convert';

interface SigmaConverterProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onApply?: (content: string) => void;
}

export function SigmaConverter({ open, onOpenChange, onApply }: SigmaConverterProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const { profile, ready, unresolvedReason } = useSchemaFieldMap();
  const [sigmaInput, setSigmaInput] = useState('');
  const [activeTab, setActiveTab] = useState<'input' | 'output'>('input');

  const conversionResult = useMemo(() => {
    if (!sigmaInput.trim()) {
      return null;
    }
    // NAN-4903: field targets depend on the tenant's schema profile; never
    // convert against a guessed one.
    if (!ready) {
      return { success: false, output: '', warnings: [], errors: [unresolvedReason ?? 'Schema profile unavailable.'] };
    }
    return convertSigmaRule(sigmaInput, profile, user?.name);
  }, [sigmaInput, profile, ready, unresolvedReason, user?.name]);

  const handleConvert = () => {
    if (conversionResult?.success) {
      setActiveTab('output');
    }
  };

  const handleCopy = () => {
    if (conversionResult?.success && conversionResult.output) {
      navigator.clipboard.writeText(conversionResult.output);
      toast({ title: 'Copied to clipboard' });
    }
  };

  const handleApply = () => {
    if (conversionResult?.success && conversionResult.output && onApply) {
      onApply(conversionResult.output);
      onOpenChange(false);
      setSigmaInput('');
      setActiveTab('input');
    }
  };

  const handleClose = () => {
    onOpenChange(false);
    setSigmaInput('');
    setActiveTab('input');
  };

  return (
    <DetailSheet
      open={open}
      onOpenChange={handleClose}
      size="lg"
      breadcrumb={['Detection', 'Sigma']}
      icon={<FileCode className="w-4 h-4" strokeWidth={1.5} />}
      title="Sigma Rule Converter"
      description="Paste a Sigma rule to convert it to nano detection format."
      guardDirty={sigmaInput.trim().length > 0}
      discardTitle="Discard Sigma input?"
      discardDescription="Closing the converter will lose the pasted Sigma rule."
      bodyClassName="flex flex-col px-0 py-0"
      footer={
        <>
          <SheetCancelButton />
          <div className="ml-auto flex items-center gap-2">
            {activeTab === 'input' ? (
              <Button
                size="sm"
                onClick={handleConvert}
                disabled={!conversionResult?.success}
                className="h-7 text-[11.5px]"
              >
                <ArrowRight className="w-3.5 h-3.5" />
                View Converted Rule
              </Button>
            ) : (
              <>
                <Button variant="outline" size="sm" onClick={handleCopy} className="h-7 text-[11.5px]">
                  <Copy className="w-3.5 h-3.5" />
                  Copy
                </Button>
                {onApply && (
                  <Button size="sm" onClick={handleApply} disabled={!conversionResult?.success} className="h-7 text-[11.5px]">
                    <ArrowRight className="w-3.5 h-3.5" />
                    Apply to Editor
                  </Button>
                )}
              </>
            )}
          </div>
        </>
      }
    >
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'input' | 'output')} className="flex-1 flex flex-col min-h-0">
        <TabsList className="mx-4 mt-3 mb-2 w-fit">
          <TabsTrigger value="input" className="gap-2">
            <FileCode className="w-4 h-4" />
            Sigma Input
          </TabsTrigger>
          <TabsTrigger value="output" className="gap-2" disabled={!conversionResult?.success}>
            <ArrowRight className="w-4 h-4" />
            Converted Output
            {conversionResult?.success && (
              <Badge variant="outline" className="ml-1 text-xs border-green-500/30 text-green-400">Ready</Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="input" className="flex-1 min-h-0 px-4 pb-3 mt-0">
          <div className="h-full flex flex-col gap-4">
            <Textarea
              value={sigmaInput}
              onChange={(e) => setSigmaInput(e.target.value)}
              placeholder={`Paste your Sigma rule here...

Example:
title: Suspicious PowerShell Encoded Command
logsource:
category: process_creation
product: windows
detection:
selection:
  CommandLine|contains:
    - ' -enc '
    - ' -encodedcommand '
condition: selection
level: medium`}
              className="flex-1 min-h-[240px] font-mono text-[12px] border-border rounded-md resize-none"
            />

            {/* Conversion status */}
            {sigmaInput.trim() && (
              <div className="space-y-2">
                {conversionResult?.success ? (
                  <div className="flex items-center gap-2 text-green-400">
                    <CircleCheck className="w-4 h-4" />
                    <span className="text-sm">Rule parsed successfully</span>
                  </div>
                ) : conversionResult?.errors.length ? (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-red-400 mb-2">
                      <CircleAlert className="w-4 h-4" />
                      <span className="text-sm font-medium">Conversion Errors</span>
                    </div>
                    <ul className="text-sm text-red-300 list-disc list-inside space-y-1">
                      {conversionResult.errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}

                {conversionResult?.warnings.length ? (
                  <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-yellow-400 mb-2">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="text-sm font-medium">Warnings ({conversionResult.warnings.length})</span>
                    </div>
                    <ul className="text-sm text-yellow-700 dark:text-yellow-300 list-disc list-inside space-y-1">
                      {conversionResult.warnings.map((warn, i) => (
                        <li key={i}>{warn}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="output" className="flex-1 min-h-0 px-4 pb-3 mt-0">
          <div className="h-full flex flex-col gap-4">
            <div className="flex-1 min-h-[240px] relative">
              <Textarea
                value={conversionResult?.output || ''}
                readOnly
                className="h-full font-mono text-[12px] border-border rounded-md resize-none text-green-400 bg-muted/30"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                className="absolute top-2 right-2"
              >
                <Copy className="w-4 h-4" />
              </Button>
            </div>

            {conversionResult?.warnings.length ? (
              <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <div className="flex items-center gap-2 text-yellow-400 mb-2">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm font-medium">Review These Items</span>
                </div>
                <ul className="text-sm text-yellow-700 dark:text-yellow-300 list-disc list-inside space-y-1">
                  {conversionResult.warnings.map((warn, i) => (
                    <li key={i}>{warn}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </TabsContent>
      </Tabs>
    </DetailSheet>
  );
}

// Export the conversion function for use elsewhere
export { convertSigmaRule };

/** Footer Cancel that routes through the sheet's dirty guard. */
function SheetCancelButton() {
  const { requestClose } = useDetailSheet();
  return (
    <Button variant="outline" size="sm" onClick={requestClose} className="h-7 text-[11.5px]">
      Cancel
    </Button>
  );
}
