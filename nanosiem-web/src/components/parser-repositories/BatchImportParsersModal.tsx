// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Loader2,
  Download,
  CircleCheck,
  XCircle,
  CircleAlert,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { RepositoryParser, BatchImportParserItem } from '@/lib/api/parser-repositories';
import { useToast } from '@/hooks/use-toast';
import { PermissionAction } from '@/components/repositories/PermissionAction';
import type { ActionAccess } from '@/components/repositories/repository-action-policy';

interface BatchImportParsersModalProps {
  repositoryId: string;
  parsers: RepositoryParser[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
  getImportAccess: (items: BatchImportParserItem[]) => ActionAccess;
}

interface ParserImportConfig {
  selected: boolean;
  importType: 'linked' | 'forked';
  ingestionMethod: string;
}

export function BatchImportParsersModal({
  repositoryId,
  parsers,
  open,
  onOpenChange,
  onSuccess,
  getImportAccess,
}: BatchImportParsersModalProps) {
  const { toast } = useToast();

  const [configs, setConfigs] = useState<Record<string, ParserImportConfig>>({});
  const [importing, setImporting] = useState(false);
  const [importProgress, setImportProgress] = useState({ imported: 0, skipped: 0, failed: 0, total: 0 });

  // Initialize configs when modal opens
  useEffect(() => {
    if (!open) return;
    const initial: Record<string, ParserImportConfig> = {};
    for (const parser of parsers) {
      initial[parser.id] = {
        selected: true,
        importType: 'linked',
        ingestionMethod: 'routed',
      };
    }
    setConfigs(initial);
    setImporting(false);
    setImportProgress({ imported: 0, skipped: 0, failed: 0, total: 0 });
  }, [open, parsers]);

  const selectedCount = useMemo(
    () => Object.values(configs).filter((c) => c.selected).length,
    [configs]
  );

  const updateConfig = useCallback((parserId: string, updates: Partial<ParserImportConfig>) => {
    setConfigs((prev) => ({
      ...prev,
      [parserId]: { ...prev[parserId], ...updates },
    }));
  }, []);

  const toggleAll = useCallback(
    (selected: boolean) => {
      setConfigs((prev) => {
        const next = { ...prev };
        for (const id of Object.keys(next)) {
          next[id] = { ...next[id], selected };
        }
        return next;
      });
    },
    []
  );

  const setBulkImportType = useCallback((importType: 'linked' | 'forked') => {
    setConfigs((prev) => {
      const next = { ...prev };
      for (const id of Object.keys(next)) {
        if (next[id].selected) {
          next[id] = { ...next[id], importType };
        }
      }
      return next;
    });
  }, []);

  const setBulkIngestionMethod = useCallback((ingestionMethod: string) => {
    setConfigs((prev) => {
      const next = { ...prev };
      for (const id of Object.keys(next)) {
        if (next[id].selected) {
          next[id] = { ...next[id], ingestionMethod };
        }
      }
      return next;
    });
  }, []);

  const getFolder = (filePath: string) => {
    const parts = filePath.split('/');
    return parts.length > 1 ? parts.slice(0, -1).join('/') : '';
  };

  const buildItems = (): BatchImportParserItem[] => {
    const selectedParsers = parsers.filter((p) => configs[p.id]?.selected);
    return selectedParsers.map((parser) => {
      const config = configs[parser.id];
      return {
        path: parser.file_path,
        import_type: config.importType,
        ingestion_method: config.ingestionMethod,
      };
    });
  };

  const plannedItems = buildItems();
  const importAccess = getImportAccess(plannedItems);

  const handleImport = async () => {
    if (plannedItems.length === 0 || !importAccess.allowed) return;

    setImporting(true);

    setImportProgress({ imported: 0, skipped: 0, failed: 0, total: plannedItems.length });

    try {
      const result = await api.parserRepositories.batchImport(repositoryId, plannedItems);

      setImportProgress({
        imported: result.imported,
        skipped: result.skipped,
        failed: result.failed.length,
        total: plannedItems.length,
      });

      toast({
        title: 'Batch import complete',
        description: `Imported ${result.imported}, skipped ${result.skipped}${result.failed.length > 0 ? `, ${result.failed.length} failed` : ''}`,
        variant: result.failed.length > 0 ? 'destructive' : 'default',
      });

      if (result.failed.length === 0) {
        onSuccess();
      }
    } catch (err: unknown) {
      toast({
        title: 'Batch import failed',
        description: err instanceof Error ? err.message : 'Failed to import parsers',
        variant: 'destructive',
      });
      setImporting(false);
    }
  };

  const importDone = importing && importProgress.imported + importProgress.skipped + importProgress.failed === importProgress.total && importProgress.total > 0;
  const progressPercent = importProgress.total > 0
    ? ((importProgress.imported + importProgress.skipped + importProgress.failed) / importProgress.total) * 100
    : 0;

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!importing) onOpenChange(o); }}>
      <DialogContent className="flex max-h-[85vh] max-w-4xl flex-col">
        <DialogHeader className="border-b border-border/50 pb-4">
          <DialogTitle className="search-console-section-header"><Download />Batch Import Parsers</DialogTitle>
          <DialogDescription>
            Import multiple parsers at once. {parsers.length} parser{parsers.length !== 1 ? 's' : ''} available for import.
          </DialogDescription>
        </DialogHeader>

        {/* Bulk controls */}
        {!importing && (
          <div className="flex items-center gap-3 border-b border-border/50 px-1 py-2">
            <Button variant="ghost" className="h-7 text-[11.5px]" onClick={() => toggleAll(true)}>
              Select All
            </Button>
            <Button variant="ghost" className="h-7 text-[11.5px]" onClick={() => toggleAll(false)}>
              Deselect All
            </Button>
            <div className="h-4 w-px bg-border" />
            <span className="search-console-section-meta">Set selected to:</span>
            <Select onValueChange={(v) => setBulkImportType(v as 'linked' | 'forked')}>
              <SelectTrigger className="w-28">
                <SelectValue placeholder="Import type..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="linked">Linked</SelectItem>
                <SelectItem value="forked">Forked</SelectItem>
              </SelectContent>
            </Select>
            <Select onValueChange={setBulkIngestionMethod}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Ingestion..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="routed">HTTP (Routed)</SelectItem>
                <SelectItem value="vector">Vector</SelectItem>
                <SelectItem value="splunk_hec">Splunk HEC</SelectItem>
                <SelectItem value="kafka">Kafka</SelectItem>
                <SelectItem value="aws_s3">AWS S3</SelectItem>
                <SelectItem value="gcp_pubsub">GCP Pub/Sub</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}

        {/* Progress bar during import */}
        {importing && (
          <div className="space-y-3 py-4">
            <Progress value={progressPercent} className="h-2" />
            <div className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1 text-green-600">
                <CircleCheck className="w-3.5 h-3.5" /> {importProgress.imported} imported
              </span>
              <span className="flex items-center gap-1 text-muted-foreground">
                <CircleAlert className="w-3.5 h-3.5" /> {importProgress.skipped} skipped
              </span>
              {importProgress.failed > 0 && (
                <span className="flex items-center gap-1 text-red-500">
                  <XCircle className="w-3.5 h-3.5" /> {importProgress.failed} failed
                </span>
              )}
              <span className="text-muted-foreground ml-auto">
                {importProgress.imported + importProgress.skipped + importProgress.failed} / {importProgress.total}
              </span>
            </div>
          </div>
        )}

        {/* Parsers table */}
        {!importing && (
          <div className="min-h-0 flex-1 overflow-auto rounded-md border border-border">
            <table className="w-full text-[12px]">
              <thead className="sticky top-0 z-10 bg-muted/60 backdrop-blur-sm">
                <tr className="border-b border-border/50">
                  <th className="w-10 p-2 text-left">
                    <Checkbox
                      checked={selectedCount === parsers.length && parsers.length > 0}
                      onCheckedChange={(checked) => toggleAll(!!checked)}
                    />
                  </th>
                  <th className="search-console-section-meta p-2 text-left">Parser</th>
                  <th className="search-console-section-meta w-36 p-2 text-left">Folder</th>
                  <th className="search-console-section-meta w-28 p-2 text-left">Import Type</th>
                  <th className="search-console-section-meta w-36 p-2 text-left">Ingestion</th>
                </tr>
              </thead>
              <tbody>
                {parsers.map((parser) => {
                  const config = configs[parser.id];
                  if (!config) return null;
                  const folder = getFolder(parser.file_path);

                  return (
                    <tr
                      key={parser.id}
                      className={`border-b hover:bg-accent/30 transition-colors ${
                        config.selected ? '' : 'opacity-50'
                      }`}
                    >
                      <td className="p-2">
                        <Checkbox
                          checked={config.selected}
                          onCheckedChange={(checked) =>
                            updateConfig(parser.id, { selected: !!checked })
                          }
                        />
                      </td>
                      <td className="p-2">
                        <div className="font-medium text-[12.5px] leading-snug truncate max-w-[300px]" title={parser.display_name || parser.file_path}>
                          {parser.display_name || parser.name || parser.file_path.split('/').pop()}
                        </div>
                        {parser.description && (
                          <div className="text-[11px] text-muted-foreground truncate max-w-[300px]">
                            {parser.description}
                          </div>
                        )}
                      </td>
                      <td className="p-2">
                        <span className="font-mono text-[11px] text-muted-foreground truncate block max-w-[140px]" title={folder}>
                          {folder}
                        </span>
                      </td>
                      <td className="p-2">
                        <Select
                          value={config.importType}
                          onValueChange={(v) => updateConfig(parser.id, { importType: v as 'linked' | 'forked' })}
                          disabled={!config.selected}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="linked">Linked</SelectItem>
                            <SelectItem value="forked">Forked</SelectItem>
                          </SelectContent>
                        </Select>
                      </td>
                      <td className="p-2">
                        <Select
                          value={config.ingestionMethod}
                          onValueChange={(v) => updateConfig(parser.id, { ingestionMethod: v })}
                          disabled={!config.selected}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="routed">HTTP (Routed)</SelectItem>
                            <SelectItem value="vector">Vector</SelectItem>
                            <SelectItem value="splunk_hec">Splunk HEC</SelectItem>
                            <SelectItem value="kafka">Kafka</SelectItem>
                            <SelectItem value="aws_s3">AWS S3</SelectItem>
                            <SelectItem value="gcp_pubsub">GCP Pub/Sub</SelectItem>
                          </SelectContent>
                        </Select>
                      </td>
                    </tr>
                  );
                })}
                {parsers.length === 0 && (
                  <tr>
                    <td colSpan={5} className="text-center py-8 text-muted-foreground">
                      All parsers have already been imported.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        <DialogFooter>
          {importDone ? (
            <Button className="h-8 text-[11.5px]" onClick={() => { onOpenChange(false); onSuccess(); }}>
              Done
            </Button>
          ) : (
            <>
              <Button variant="outline" className="h-8 text-[11.5px]" onClick={() => onOpenChange(false)} disabled={importing}>
                Cancel
              </Button>
              <PermissionAction access={importAccess}>
                <Button
                  className="h-8 text-[11.5px] gap-1.5"
                  onClick={handleImport}
                  disabled={importing || selectedCount === 0 || !importAccess.allowed}
                >
                  {importing ? (
                    <Loader2 className="h-[11px] w-[11px] animate-spin" />
                  ) : (
                    <Download className="h-[11px] w-[11px]" />
                  )}
                  Import {selectedCount} Parser{selectedCount !== 1 ? 's' : ''}
                </Button>
              </PermissionAction>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
