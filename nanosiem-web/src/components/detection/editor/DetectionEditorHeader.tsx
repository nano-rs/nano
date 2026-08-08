// SPDX-License-Identifier: AGPL-3.0-or-later

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ArrowLeft, Save, Loader2, Play, FileCode, WandSparkles, Eye, Archive, ArchiveRestore, Trash2, MoreHorizontal, Undo2, Import, Power } from 'lucide-react';
import { PivtIcon } from '@/components/icons/PivtIcon';
import { Link } from 'react-router-dom';

interface DetectionEditorHeaderProps {
  title?: string;
  titleValid: boolean;
  titleError?: string | null;
  mode?: 'staging' | 'live' | 'alerting' | 'paused';
  archived?: boolean;
  isDraft?: boolean;
  aiGenerated?: boolean;
  sigmaImported?: boolean;
  ruleId?: string;

  // Actions
  onBack: () => void;
  onSave: () => void;
  onValidate: () => void;
  onFormat?: () => void;
  onArchive?: () => void;
  onUnarchive?: () => void;
  onDelete?: () => void;
  onDiscard?: () => void;
  onTogglePause?: () => void;

  // Loading states
  saving?: boolean;
  validating?: boolean;
  formatting?: boolean;

  // Disable states
  disableSave?: boolean;
  disableValidate?: boolean;
  hasChanges?: boolean;

  // Button labels
  saveLabel?: string;
}

export function DetectionEditorHeader({
  title,
  titleValid,
  titleError,
  mode,
  archived,
  isDraft,
  aiGenerated,
  sigmaImported,
  ruleId,
  onBack,
  onSave,
  onValidate,
  onFormat,
  onArchive,
  onUnarchive,
  onDelete,
  onDiscard,
  onTogglePause,
  saving,
  validating,
  formatting,
  disableSave,
  disableValidate,
  hasChanges,
  saveLabel = 'Save Rule',
}: DetectionEditorHeaderProps) {
  return (
    <div className="flex items-center justify-between px-2 md:px-4 py-2 md:py-3 gap-2 border-b border-border bg-muted/50">
      <div className="flex items-center gap-2 md:gap-3 min-w-0">
        <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-primary h-8 shrink-0" onClick={onBack}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <FileCode className="w-4 h-4 text-primary shrink-0 hidden md:block" />
        <div className="flex flex-col min-w-0">
          <span className={`font-medium truncate ${title ? (titleValid ? 'text-foreground' : 'text-red-400') : 'text-muted-foreground italic'}`}>
            {title || 'Enter rule name'}
          </span>
          {titleError && (
            <span className="text-xs text-red-400 mt-0.5">{titleError}</span>
          )}
        </div>
        {mode && <Badge variant="outline" className={`text-xs border-gray-700 hidden md:inline-flex ${mode === 'paused' ? 'text-amber-400 border-amber-700/50' : 'text-muted-foreground'}`}>{mode}</Badge>}
        {isDraft && <Badge variant="outline" className="text-xs text-muted-foreground border-gray-700 hidden md:inline-flex">Draft</Badge>}
        {aiGenerated && (
          <Badge className="text-xs bg-purple-500/20 text-purple-400 border-0 hidden md:inline-flex">
            <PivtIcon className="w-3 h-3 mr-1" />
            AI Generated
          </Badge>
        )}
        {sigmaImported && (
          <Badge className="text-xs bg-blue-500/20 text-blue-400 border-0 hidden md:inline-flex">
            <Import className="w-3 h-3 mr-1" />
            Sigma Import
          </Badge>
        )}
      </div>

      <div className="flex items-center gap-1 md:gap-2 shrink-0">
        {ruleId && (
          <Link to={`/rules/${ruleId}/matches`}>
            <Button variant="outline" size="sm" className="bg-accent/50 border-border text-foreground hover:bg-accent h-8 hidden md:inline-flex">
              <Eye className="w-4 h-4" />
              View Matches
            </Button>
          </Link>
        )}

        <Button
          variant="outline"
          size="sm"
          className="bg-accent/50 border-border text-foreground hover:bg-accent h-8"
          onClick={onValidate}
          disabled={validating || disableValidate}
        >
          {validating ? <Loader2 className="w-4 h-4 md: animate-spin" /> : <Play className="w-4 h-4 md:" />}
          <span className="hidden md:inline">Validate</span>
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="bg-accent/50 border-border text-foreground hover:bg-accent h-8">
              <MoreHorizontal className="w-4 h-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            {onFormat && (
              <DropdownMenuItem onClick={onFormat} disabled={formatting || disableValidate}>
                {formatting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <WandSparkles className="w-4 h-4 mr-2" />}
                Format Query
              </DropdownMenuItem>
            )}
            {onDiscard && hasChanges && (
              <DropdownMenuItem onClick={onDiscard}>
                <Undo2 className="w-4 h-4 mr-2" />
                Discard Changes
              </DropdownMenuItem>
            )}
            {onTogglePause && (mode === 'alerting' || mode === 'live' || mode === 'paused') && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onTogglePause}>
                  <Power className="w-4 h-4 mr-2" />
                  {mode === 'paused' ? 'Resume Rule' : 'Pause Rule'}
                </DropdownMenuItem>
              </>
            )}
            <DropdownMenuSeparator />
            {onArchive && !archived && (
              <DropdownMenuItem onClick={onArchive}>
                <Archive className="w-4 h-4 mr-2" />
                Archive Rule
              </DropdownMenuItem>
            )}
            {onUnarchive && archived && (
              <DropdownMenuItem onClick={onUnarchive}>
                <ArchiveRestore className="w-4 h-4 mr-2" />
                Unarchive Rule
              </DropdownMenuItem>
            )}
            {onDelete && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onDelete} className="text-red-400 focus:text-red-400">
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete Rule
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <Button
          onClick={onSave}
          disabled={saving || disableSave || archived}
          className="bg-primary hover:bg-primary/90 text-foreground h-8"
        >
          {saving ? <Loader2 className="w-4 h-4 md: animate-spin" /> : <Save className="w-4 h-4 md:" />}
          <span className="hidden md:inline">{saveLabel}</span>
        </Button>
      </div>
    </div>
  );
}
