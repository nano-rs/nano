// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { ChevronDown, ChevronUp, Info } from 'lucide-react';
import type { PreviewResult, ColumnInfo } from '@/lib/api';

const COLUMN_TYPES = [
  { value: 'text', label: 'Text' },
  { value: 'integer', label: 'Integer' },
  { value: 'float', label: 'Float' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'timestamp', label: 'Timestamp' },
  { value: 'json', label: 'JSON' },
];

interface FilePreviewProps {
  preview: PreviewResult;
  onColumnTypeChange?: (column: string, newType: string) => void;
  columnTypeOverrides?: Record<string, string>;
  showTypeOverrides?: boolean;
  maxRows?: number;
}

export function FilePreview({
  preview,
  onColumnTypeChange,
  columnTypeOverrides = {},
  showTypeOverrides = false,
  maxRows = 10,
}: FilePreviewProps) {
  const [expanded, setExpanded] = useState(true);
  const displayRows = preview.rows.slice(0, maxRows);

  const getColumnType = (col: ColumnInfo) => {
    return columnTypeOverrides[col.name] || col.detected_type;
  };

  return (
    <Card className="bg-card border-0 rounded-2xl">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle className="text-lg text-foreground">Data Preview</CardTitle>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="rounded-lg border-border text-xs">
                {preview.format.toUpperCase()}
              </Badge>
              <Badge variant="outline" className="rounded-lg border-border text-xs">
                {preview.columns.length} columns
              </Badge>
              <Badge variant="outline" className="rounded-lg border-border text-xs">
                ~{preview.total_rows_estimate.toLocaleString()} rows
              </Badge>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setExpanded(!expanded)}
            className="text-muted-foreground hover:text-primary"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </Button>
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="space-y-4">
          {/* Column Info */}
          {showTypeOverrides && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Info className="w-4 h-4" />
                <span>Column types are auto-detected. Override if needed.</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {preview.columns.map((col) => (
                  <ColumnTypeSelector
                    key={col.name}
                    column={col}
                    currentType={getColumnType(col)}
                    onTypeChange={(newType) => onColumnTypeChange?.(col.name, newType)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Data Table */}
          <div className="overflow-x-auto rounded-xl border border-border">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  {preview.columns.map((col) => (
                    <TableHead key={col.name} className="text-muted-foreground font-medium">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="flex items-center gap-2 cursor-help">
                              <span className="truncate max-w-[150px]">{col.name}</span>
                              <Badge variant="outline" className="text-[10px] rounded border-border shrink-0">
                                {getColumnType(col)}
                              </Badge>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent className="bg-card border-border text-foreground">
                            <div className="space-y-1 text-xs">
                              <p><strong>Column:</strong> {col.name}</p>
                              <p><strong>Detected Type:</strong> {col.detected_type}</p>
                              <p><strong>Null Count:</strong> {col.null_count}</p>
                              {col.sample_values.length > 0 && (
                                <p><strong>Samples:</strong> {col.sample_values.slice(0, 3).join(', ')}</p>
                              )}
                            </div>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayRows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={preview.columns.length} className="text-center text-muted-foreground py-8">
                      No data to preview
                    </TableCell>
                  </TableRow>
                ) : (
                  displayRows.map((row, i) => (
                    <TableRow key={i} className="border-border hover:bg-accent/50">
                      {preview.columns.map((col) => (
                        <TableCell key={col.name} className="text-foreground max-w-[200px]">
                          <CellValue value={row[col.name]} type={getColumnType(col)} />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {preview.rows.length > maxRows && (
            <p className="text-xs text-muted-foreground text-center">
              Showing first {maxRows} of {preview.rows.length} preview rows
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function ColumnTypeSelector({
  column,
  currentType,
  onTypeChange,
}: {
  column: ColumnInfo;
  currentType: string;
  onTypeChange: (newType: string) => void;
}) {
  const isOverridden = currentType !== column.detected_type;

  return (
    <div className={`flex items-center gap-2 p-2 rounded-lg ${isOverridden ? 'bg-primary/10' : 'bg-muted/30'}`}>
      <span className="text-sm text-foreground truncate max-w-[100px]">{column.name}</span>
      <Select value={currentType} onValueChange={onTypeChange}>
        <SelectTrigger className="h-7 w-[100px] bg-transparent border-border rounded-lg text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent className=" rounded-xl">
          {COLUMN_TYPES.map((type) => (
            <SelectItem
              key={type.value}
              value={type.value}
              className="text-foreground  text-xs"
            >
              {type.label}
              {type.value === column.detected_type && (
                <span className="ml-1 text-muted-foreground">(detected)</span>
              )}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function CellValue({ value, type }: { value: unknown; type: string }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground italic">null</span>;
  }

  if (typeof value === 'object') {
    return (
      <code className="text-xs bg-muted/30 px-1 py-0.5 rounded text-purple-400 truncate block">
        {JSON.stringify(value)}
      </code>
    );
  }

  if (type === 'boolean') {
    const boolValue = value === true || value === 'true' || value === '1';
    return (
      <Badge variant="outline" className={`text-xs rounded ${boolValue ? 'text-green-400 border-green-500/30' : 'text-red-400 border-red-500/30'}`}>
        {boolValue ? 'true' : 'false'}
      </Badge>
    );
  }

  if (type === 'timestamp') {
    try {
      const date = new Date(String(value));
      if (!isNaN(date.getTime())) {
        return <span className="text-primary">{date.toISOString()}</span>;
      }
    } catch {
      // Fall through to default
    }
  }

  if (type === 'integer' || type === 'float') {
    return <span className="text-yellow-400 font-mono">{String(value)}</span>;
  }

  const strValue = String(value);
  if (strValue.length > 50) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="truncate block cursor-help">{strValue.slice(0, 50)}...</span>
          </TooltipTrigger>
          <TooltipContent className="bg-card border-border text-foreground max-w-md">
            <p className="text-xs break-all">{strValue}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return <span>{strValue}</span>;
}

export default FilePreview;
