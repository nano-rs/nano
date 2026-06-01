// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VariableEditor Component
 *
 * Dialog for managing dashboard variables. Allows adding, editing, and deleting
 * variables with support for dropdown, text, and query-based types.
 */

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Plus,
  Trash2,
  Variable,
  ChevronDown,
  ChevronUp,
  GripVertical,
} from 'lucide-react';
import type { DashboardVariable, DashboardVariableType } from '@/lib/api';

export interface VariableEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  variables: DashboardVariable[];
  onSave: (variables: DashboardVariable[]) => void;
}

interface VariableFormState extends DashboardVariable {
  isExpanded: boolean;
  optionsText: string; // For editing options as newline-separated text
}

function createEmptyVariable(): VariableFormState {
  return {
    name: '',
    label: '',
    type: 'dropdown',
    defaultValue: '',
    options: [],
    optionsText: '',
    query: '',
    queryField: '',
    multi: false,
    isExpanded: true,
  };
}

function variableToFormState(variable: DashboardVariable): VariableFormState {
  return {
    ...variable,
    optionsText: variable.options?.join('\n') || '',
    isExpanded: false,
  };
}

function formStateToVariable(state: VariableFormState): DashboardVariable {
  const base: DashboardVariable = {
    name: state.name.trim().replace(/\s+/g, '_').toLowerCase(),
    label: state.label.trim(),
    type: state.type,
    defaultValue: state.defaultValue || undefined,
    multi: state.multi || undefined,
  };

  if (state.type === 'dropdown') {
    base.options = state.optionsText
      .split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0);
  } else if (state.type === 'query') {
    base.query = state.query || undefined;
    base.queryField = state.queryField || undefined;
  }

  return base;
}

function validateVariable(state: VariableFormState): string | null {
  if (!state.name.trim()) {
    return 'Variable name is required';
  }
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(state.name.trim().replace(/\s+/g, '_'))) {
    return 'Variable name must start with a letter and contain only letters, numbers, and underscores';
  }
  if (!state.label.trim()) {
    return 'Label is required';
  }
  if (state.type === 'dropdown' && (!state.optionsText || state.optionsText.trim().length === 0)) {
    return 'At least one option is required for dropdown variables';
  }
  if (state.type === 'query' && !state.query?.trim()) {
    return 'Query is required for query-based variables';
  }
  if (state.type === 'query' && !state.queryField?.trim()) {
    return 'Field name is required for query-based variables';
  }
  return null;
}

export function VariableEditor({
  open,
  onOpenChange,
  variables,
  onSave,
}: VariableEditorProps) {
  const [formVariables, setFormVariables] = useState<VariableFormState[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [removeIndex, setRemoveIndex] = useState<number | null>(null);

  // Initialize form state from props
  useEffect(() => {
    if (open) {
      setFormVariables(
        variables.length > 0
          ? variables.map(variableToFormState)
          : []
      );
      setError(null);
    }
  }, [open, variables]);

  const handleAddVariable = () => {
    setFormVariables(prev => [...prev, createEmptyVariable()]);
  };

  const handleRemoveVariable = (index: number) => {
    setFormVariables(prev => prev.filter((_, i) => i !== index));
  };

  const handleUpdateVariable = (index: number, updates: Partial<VariableFormState>) => {
    setFormVariables(prev =>
      prev.map((v, i) => (i === index ? { ...v, ...updates } : v))
    );
  };

  const handleToggleExpand = (index: number) => {
    setFormVariables(prev =>
      prev.map((v, i) => (i === index ? { ...v, isExpanded: !v.isExpanded } : v))
    );
  };

  const handleMoveUp = (index: number) => {
    if (index === 0) return;
    setFormVariables(prev => {
      const newArr = [...prev];
      [newArr[index - 1], newArr[index]] = [newArr[index], newArr[index - 1]];
      return newArr;
    });
  };

  const handleMoveDown = (index: number) => {
    if (index === formVariables.length - 1) return;
    setFormVariables(prev => {
      const newArr = [...prev];
      [newArr[index], newArr[index + 1]] = [newArr[index + 1], newArr[index]];
      return newArr;
    });
  };

  const handleSave = () => {
    // Validate all variables
    for (let i = 0; i < formVariables.length; i++) {
      const validationError = validateVariable(formVariables[i]);
      if (validationError) {
        setError(`Variable ${i + 1}: ${validationError}`);
        return;
      }
    }

    // Check for duplicate names
    const names = formVariables.map(v => v.name.trim().replace(/\s+/g, '_').toLowerCase());
    const duplicates = names.filter((name, i) => names.indexOf(name) !== i);
    if (duplicates.length > 0) {
      setError(`Duplicate variable name: ${duplicates[0]}`);
      return;
    }

    // Convert to DashboardVariable and save
    const savedVariables = formVariables.map(formStateToVariable);
    onSave(savedVariables);
    onOpenChange(false);
  };

  return (
    <>
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[560px] max-w-[min(560px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
          <Variable className="w-[13px] h-[13px] text-primary" />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Dashboard Variables
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              Reference in queries via <code className="font-mono text-primary">$variable_name</code>.
            </div>
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-3">
        <SheetHeader className="hidden">
          <SheetTitle>Dashboard Variables</SheetTitle>
          <SheetDescription>Manage dashboard variables.</SheetDescription>
        </SheetHeader>
          {formVariables.length === 0 ? (
            <div className="text-center py-10 flex flex-col items-center gap-2">
              <Variable className="w-10 h-10 text-muted-foreground/40" />
              <p className="text-[13px] font-medium text-foreground">No variables defined</p>
              <p className="text-[11.5px] text-muted-foreground">Add a variable to get started.</p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {formVariables.map((variable, index) => (
                <div
                  key={index}
                  className="rounded-md border border-border bg-card overflow-hidden"
                >
                  {/* Variable header */}
                  <button
                    type="button"
                    className="w-full h-[34px] px-2 flex items-center gap-2 hover:bg-foreground/[0.03] transition-colors text-left"
                    onClick={() => handleToggleExpand(index)}
                  >
                    <GripVertical className="w-[12px] h-[12px] text-muted-foreground/60 shrink-0" />
                    <div className="flex-1 min-w-0 flex items-center gap-2">
                      <span className="text-[12.5px] font-semibold text-foreground truncate">
                        {variable.label || variable.name || `Variable ${index + 1}`}
                      </span>
                      {variable.name && (
                        <code className="font-mono text-[10.5px] text-primary bg-primary/10 px-1.5 py-0.5 rounded-[3px]">
                          ${variable.name.replace(/\s+/g, '_').toLowerCase()}
                        </code>
                      )}
                    </div>
                    <span className="font-mono text-[9.5px] uppercase tracking-[0.1em] text-muted-foreground/70 shrink-0">
                      {variable.type}
                    </span>
                    <span className="flex items-center gap-0.5 shrink-0">
                      <span
                        role="button"
                        aria-disabled={index === 0}
                        className={`w-5 h-5 rounded flex items-center justify-center text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground ${
                          index === 0 ? 'opacity-40 pointer-events-none' : ''
                        }`}
                        onClick={e => {
                          e.stopPropagation();
                          if (index !== 0) handleMoveUp(index);
                        }}
                      >
                        <ChevronUp className="w-[12px] h-[12px]" />
                      </span>
                      <span
                        role="button"
                        aria-disabled={index === formVariables.length - 1}
                        className={`w-5 h-5 rounded flex items-center justify-center text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground ${
                          index === formVariables.length - 1 ? 'opacity-40 pointer-events-none' : ''
                        }`}
                        onClick={e => {
                          e.stopPropagation();
                          if (index !== formVariables.length - 1) handleMoveDown(index);
                        }}
                      >
                        <ChevronDown className="w-[12px] h-[12px]" />
                      </span>
                      <span
                        role="button"
                        className="w-5 h-5 rounded flex items-center justify-center text-rose-400 hover:bg-rose-500/10"
                        onClick={e => {
                          e.stopPropagation();
                          setRemoveIndex(index);
                        }}
                      >
                        <Trash2 className="w-[12px] h-[12px]" />
                      </span>
                    </span>
                    {variable.isExpanded ? (
                      <ChevronUp className="w-[12px] h-[12px] text-muted-foreground shrink-0" />
                    ) : (
                      <ChevronDown className="w-[12px] h-[12px] text-muted-foreground shrink-0" />
                    )}
                  </button>

                  {/* Expanded form */}
                  {variable.isExpanded && (
                    <div className="p-3 flex flex-col gap-3 border-t border-border">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="flex flex-col gap-1.5">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Variable name
                          </Label>
                          <Input
                            value={variable.name}
                            onChange={e => handleUpdateVariable(index, { name: e.target.value })}
                            placeholder="e.g., host"
                            className="h-[28px] text-[12px]"
                          />
                          <p className="text-[10.5px] text-muted-foreground">
                            Use <code className="font-mono text-primary">${variable.name || 'name'}</code> in queries
                          </p>
                        </div>
                        <div className="flex flex-col gap-1.5">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Display label
                          </Label>
                          <Input
                            value={variable.label}
                            onChange={e => handleUpdateVariable(index, { label: e.target.value })}
                            placeholder="e.g., Host"
                            className="h-[28px] text-[12px]"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="flex flex-col gap-1.5">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Type
                          </Label>
                          <Select
                            value={variable.type}
                            onValueChange={v => handleUpdateVariable(index, { type: v as DashboardVariableType })}
                          >
                            <SelectTrigger className="h-[28px] text-[12px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="dropdown" className="text-[12px]">
                                Dropdown (static options)
                              </SelectItem>
                              <SelectItem value="text" className="text-[12px]">
                                Text input
                              </SelectItem>
                              <SelectItem value="query" className="text-[12px]">
                                Query (dynamic options)
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex flex-col gap-1.5">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Default value
                          </Label>
                          <Input
                            value={variable.defaultValue || ''}
                            onChange={e => handleUpdateVariable(index, { defaultValue: e.target.value })}
                            placeholder="Optional default"
                            className="h-[28px] text-[12px]"
                          />
                        </div>
                      </div>

                      {variable.type === 'dropdown' && (
                        <div className="flex flex-col gap-1.5">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Options (one per line)
                          </Label>
                          <Textarea
                            value={variable.optionsText}
                            onChange={e => handleUpdateVariable(index, { optionsText: e.target.value })}
                            placeholder={'Option 1\nOption 2\nOption 3'}
                            rows={4}
                            className="font-mono text-[11.5px] resize-none"
                          />
                        </div>
                      )}

                      {variable.type === 'query' && (
                        <>
                          <div className="flex flex-col gap-1.5">
                            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                              Query
                            </Label>
                            <Textarea
                              value={variable.query || ''}
                              onChange={e => handleUpdateVariable(index, { query: e.target.value })}
                              placeholder="* | stats count by host | table host"
                              rows={2}
                              className="font-mono text-[11.5px] resize-none"
                            />
                            <p className="text-[10.5px] text-muted-foreground">
                              Query to fetch options. Should return distinct values for the field.
                            </p>
                          </div>
                          <div className="flex flex-col gap-1.5">
                            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                              Field name
                            </Label>
                            <Input
                              value={variable.queryField || ''}
                              onChange={e => handleUpdateVariable(index, { queryField: e.target.value })}
                              placeholder="e.g., host"
                              className="h-[28px] text-[12px]"
                            />
                            <p className="text-[10.5px] text-muted-foreground">
                              Field from query results to use as dropdown options.
                            </p>
                          </div>
                        </>
                      )}

                      {(variable.type === 'dropdown' || variable.type === 'query') && (
                        <div className="flex items-center justify-between">
                          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                            Allow multiple selections
                          </Label>
                          <Switch
                            checked={variable.multi || false}
                            onCheckedChange={checked => handleUpdateVariable(index, { multi: checked })}
                          />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={handleAddVariable}
            className="w-full h-[34px] rounded-md border border-dashed border-border text-muted-foreground text-[12px] flex items-center justify-center gap-1.5 hover:border-primary/40 hover:bg-primary/5 hover:text-foreground transition-colors"
          >
            <Plus className="w-[12px] h-[12px]" />
            Add variable
          </button>

          {error && (
            <p className="text-[11.5px] text-rose-400 mt-1">{error}</p>
          )}
        </div>

        <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
          <Button variant="ghost" size="sm" className="h-[28px]" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button size="sm" className="h-[28px]" onClick={handleSave}>
            Save variables
          </Button>
        </div>
      </SheetContent>
    </Sheet>

    {/* Remove Variable Confirmation */}
    <ConfirmDialog
      open={removeIndex !== null}
      onOpenChange={() => setRemoveIndex(null)}
      variant="danger"
      title="Remove variable?"
      description={
        <>
          Are you sure you want to remove
          {removeIndex !== null && formVariables[removeIndex]
            ? ` "${formVariables[removeIndex].label || formVariables[removeIndex].name || `Variable ${removeIndex + 1}`}"`
            : ' this variable'}
          ? Panels referencing it may break.
        </>
      }
      confirmLabel="Remove"
      onConfirm={() => {
        if (removeIndex !== null) handleRemoveVariable(removeIndex);
        setRemoveIndex(null);
      }}
    />
    </>
  );
}

export default VariableEditor;
