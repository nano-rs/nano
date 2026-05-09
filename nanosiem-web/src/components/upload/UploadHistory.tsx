// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
  Search,
  RefreshCw,
  Loader2,
  CircleCheck,
  XCircle,
  Clock,
  FileText,
  FileJson,
  FileSpreadsheet,
  CircleAlert,
} from 'lucide-react';
import { useUploadHistory } from '@/hooks/use-api';
import type { UploadRecord, UploadHistoryFilter } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'completed':
      return <CircleCheck className="w-4 h-4 text-green-400" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'processing':
      return <Clock className="w-4 h-4 text-yellow-400 animate-pulse" />;
    default:
      return <CircleAlert className="w-4 h-4 text-muted-foreground" />;
  }
}

function getStatusBadge(status: string) {
  switch (status) {
    case 'completed':
      return <Badge className="bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 rounded-lg">Completed</Badge>;
    case 'failed':
      return <Badge className="bg-red-500/10 text-red-400 rounded-lg">Failed</Badge>;
    case 'processing':
      return <Badge className="bg-yellow-500/10 text-yellow-400 rounded-lg">Processing</Badge>;
    default:
      return <Badge className="bg-gray-500/10 text-muted-foreground rounded-lg">{status}</Badge>;
  }
}

function getFormatIcon(format: string) {
  switch (format.toLowerCase()) {
    case 'csv':
      return <FileSpreadsheet className="w-4 h-4 text-green-400" />;
    case 'json':
    case 'ndjson':
      return <FileJson className="w-4 h-4 text-primary" />;
    default:
      return <FileText className="w-4 h-4 text-muted-foreground" />;
  }
}

interface UploadHistoryProps {
  filter?: UploadHistoryFilter;
  showFilters?: boolean;
  limit?: number;
}

export function UploadHistory({ filter: initialFilter, showFilters = true, limit = 50 }: UploadHistoryProps) {
  const [filter, setFilter] = useState<UploadHistoryFilter>({
    ...initialFilter,
    limit,
  });
  const [searchQuery, setSearchQuery] = useState('');

  const { data: uploads, loading, refetch } = useUploadHistory(filter);

  const filteredUploads = uploads?.filter((upload) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      upload.filename.toLowerCase().includes(query) ||
      upload.destination_name.toLowerCase().includes(query)
    );
  });

  const handleStatusFilter = (status: string) => {
    setFilter((prev) => ({
      ...prev,
      status: status === 'all' ? undefined : status,
    }));
  };

  const handleDestinationTypeFilter = (type: string) => {
    setFilter((prev) => ({
      ...prev,
      destination_type: type === 'all' ? undefined : type,
    }));
  };

  return (
    <Card className="bg-card border-0 rounded-2xl">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg text-foreground">Upload History</CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="rounded-xl border-border">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {showFilters && (
          <div className="flex items-center gap-4 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by filename or destination..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 border-border rounded-xl"
              />
            </div>
            <Select value={filter.status || 'all'} onValueChange={handleStatusFilter}>
              <SelectTrigger className="w-[140px] border-border rounded-xl">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent className=" rounded-xl">
                <SelectItem value="all" className="text-foreground ">All Status</SelectItem>
                <SelectItem value="completed" className="text-foreground ">Completed</SelectItem>
                <SelectItem value="failed" className="text-foreground ">Failed</SelectItem>
                <SelectItem value="processing" className="text-foreground ">Processing</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filter.destination_type || 'all'} onValueChange={handleDestinationTypeFilter}>
              <SelectTrigger className="w-[140px] border-border rounded-xl">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent className=" rounded-xl">
                <SelectItem value="all" className="text-foreground ">All Types</SelectItem>
                <SelectItem value="logs" className="text-foreground ">Logs</SelectItem>
                <SelectItem value="lookup" className="text-foreground ">Lookup</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : !filteredUploads || filteredUploads.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No uploads found</p>
            <p className="text-muted-foreground text-sm mt-1">Upload files to see them here</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-border">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="text-muted-foreground">Status</TableHead>
                  <TableHead className="text-muted-foreground">Filename</TableHead>
                  <TableHead className="text-muted-foreground">Format</TableHead>
                  <TableHead className="text-muted-foreground">Destination</TableHead>
                  <TableHead className="text-muted-foreground">Records</TableHead>
                  <TableHead className="text-muted-foreground">Size</TableHead>
                  <TableHead className="text-muted-foreground">Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUploads.map((upload) => (
                  <UploadRow key={upload.id} upload={upload} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function UploadRow({ upload }: { upload: UploadRecord }) {
  const successRate = upload.records_total > 0
    ? Math.round((upload.records_success / upload.records_total) * 100)
    : 100;

  return (
    <TableRow className="border-border hover:bg-accent/50">
      <TableCell>
        <div className="flex items-center gap-2">
          {getStatusIcon(upload.status)}
          {getStatusBadge(upload.status)}
        </div>
      </TableCell>
      <TableCell>
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-foreground truncate max-w-[200px] block cursor-help">
                {upload.filename}
              </span>
            </TooltipTrigger>
            <TooltipContent className="bg-card border-border text-foreground">
              <p>{upload.filename}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          {getFormatIcon(upload.file_format)}
          <span className="text-foreground uppercase text-xs">{upload.file_format}</span>
        </div>
      </TableCell>
      <TableCell>
        <div className="space-y-1">
          <Badge variant="outline" className="rounded-lg border-border text-xs">
            {upload.destination_type}
          </Badge>
          <p className="text-muted-foreground text-xs truncate max-w-[150px]">{upload.destination_name}</p>
        </div>
      </TableCell>
      <TableCell>
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="cursor-help">
                <span className="text-green-400">{upload.records_success.toLocaleString()}</span>
                <span className="text-muted-foreground"> / </span>
                <span className="text-foreground">{upload.records_total.toLocaleString()}</span>
                {upload.records_failed > 0 && (
                  <span className="text-red-400 ml-1">({upload.records_failed} failed)</span>
                )}
              </div>
            </TooltipTrigger>
            <TooltipContent className="bg-card border-border text-foreground">
              <div className="text-xs space-y-1">
                <p>Total: {upload.records_total.toLocaleString()}</p>
                <p>Success: {upload.records_success.toLocaleString()}</p>
                <p>Failed: {upload.records_failed.toLocaleString()}</p>
                <p>Success Rate: {successRate}%</p>
              </div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </TableCell>
      <TableCell className="text-foreground">{formatFileSize(upload.file_size)}</TableCell>
      <TableCell>
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-muted-foreground text-sm cursor-help">
                {new Date(upload.created_at).toLocaleDateString()}
              </span>
            </TooltipTrigger>
            <TooltipContent className="bg-card border-border text-foreground">
              <div className="text-xs space-y-1">
                <p>Started: {formatUTC(upload.created_at)}</p>
                {upload.completed_at && <p>Completed: {formatUTC(upload.completed_at)}</p>}
                {upload.error_message && (
                  <p className="text-red-400">Error: {upload.error_message}</p>
                )}
              </div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </TableCell>
    </TableRow>
  );
}

export default UploadHistory;
