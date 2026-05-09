// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 PR 2 — FORM lens. Labeled fields that round-trip through the
// same YAML frontmatter the CODE lens edits. Everything here is a thin
// controlled wrapper over `serializeDetectionMetadata` — switching lenses
// is free because the document IS the frontmatter.
//
// Mirrors `design-ref/shadcn/editor-form.jsx` structure (Identity /
// Severity & lifecycle / Schedule / MITRE / Routing / Query body) but
// adapted to the real primitives + token palette.

import { useCallback, useMemo } from 'react';
import { List as ListIcon, Shield, Clock, Globe, Terminal, Signature } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import {
  parseDetectionMetadata,
  serializeDetectionMetadata,
  type DetectionMetadata,
} from '@/lib/detection-metadata';
import { cronHuman } from './helpers';

interface FormLensProps {
  value: string;
  onChange: (next: string) => void;
  readOnly?: boolean;
}

type SevKey = NonNullable<DetectionMetadata['severity']>;
type ModeKey = NonNullable<DetectionMetadata['mode']>;
type DetectionModeKey = NonNullable<DetectionMetadata['detection_mode']>;
type AlertModeKey = NonNullable<DetectionMetadata['alert_mode']>;

function FormField({
  label,
  hint,
  yamlKey,
  required,
  children,
}: {
  label: string;
  hint?: string;
  yamlKey?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[200px_1fr] gap-5 py-3 border-b border-border/60 items-start">
      <div className="pt-1.5">
        <div className="text-[12px] font-medium text-foreground">
          {label}
          {required && <span className="text-[var(--destructive)] ml-0.5">*</span>}
        </div>
        {hint && <div className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{hint}</div>}
        {yamlKey && (
          <div className="mt-1 font-mono text-[10px] text-muted-foreground/70">
            <span className="opacity-60">yaml:</span> {yamlKey}
          </div>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}

function SectionHead({ icon, title, note }: { icon: React.ReactNode; title: string; note?: string }) {
  return (
    <div className="flex items-center gap-2 py-2 border-b border-border bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] px-4 sticky top-0 z-10 -mx-6">
      <span className="text-muted-foreground">{icon}</span>
      <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] font-semibold text-foreground/80">
        {title}
      </div>
      {note && <div className="ml-auto text-[10.5px] font-mono text-muted-foreground">{note}</div>}
    </div>
  );
}

const SEV_CHIP_BG: Record<SevKey, string> = {
  critical: 'color-mix(in srgb, oklch(62% 0.22 18) 20%, transparent)',
  high: 'color-mix(in srgb, oklch(72% 0.18 28) 20%, transparent)',
  medium: 'color-mix(in srgb, oklch(80% 0.15 78) 20%, transparent)',
  low: 'color-mix(in srgb, oklch(68% 0.11 215) 20%, transparent)',
};
const SEV_CHIP_FG: Record<SevKey, string> = {
  critical: 'oklch(62% 0.22 18)',
  high: 'oklch(72% 0.18 28)',
  medium: 'oklch(80% 0.15 78)',
  low: 'oklch(68% 0.11 215)',
};

export function FormLens({ value, onChange, readOnly }: FormLensProps) {
  const parsed = useMemo(() => parseDetectionMetadata(value), [value]);
  const meta = parsed.metadata;
  const query = parsed.query;

  const setField = useCallback(
    <K extends keyof DetectionMetadata>(key: K, next: DetectionMetadata[K]) => {
      if (readOnly) return;
      const updated = { ...meta, [key]: next };
      onChange(serializeDetectionMetadata(updated, query));
    },
    [meta, query, onChange, readOnly],
  );

  // Tag array helpers — tags / mitre_tactics / mitre_techniques are each a
  // comma-separated string in the YAML. We split for display, rebuild on
  // change. Trailing empty tokens are discarded.
  const splitList = (s: string | undefined) =>
    (s || '')
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
  const joinList = (arr: string[]) => arr.join(', ');

  const tagsArr = splitList(meta.tags);
  const tacticsArr = splitList(meta.mitre_tactics);
  const techniquesArr = splitList(meta.mitre_techniques);

  const addChip = (field: 'tags' | 'mitre_tactics' | 'mitre_techniques', raw: string) => {
    const next = raw.trim();
    if (!next) return;
    const current = splitList(meta[field]);
    if (current.includes(next)) return;
    setField(field, joinList([...current, next]));
  };
  const removeChip = (field: 'tags' | 'mitre_tactics' | 'mitre_techniques', target: string) => {
    const current = splitList(meta[field]);
    setField(field, joinList(current.filter((v) => v !== target)));
  };

  return (
    <div className="flex-1 min-w-0 h-full flex flex-col min-h-0">
      <div className="h-8 flex items-center px-3 gap-3 border-b border-border bg-background/60 text-[10.5px] font-mono shrink-0">
        <span className="inline-flex items-center gap-1.5 text-muted-foreground">
          <ListIcon className="w-3 h-3" strokeWidth={1.75} />
          FORM
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span className="text-muted-foreground">every field writes to YAML — switch to CODE any time</span>
      </div>
      <ScrollArea className="flex-1 min-h-0">
        <div className="max-w-[880px] mx-auto px-6 pb-24">
          <section>
            <SectionHead icon={<Signature className="w-3.5 h-3.5" strokeWidth={1.75} />} title="Identity" />
            <div className="pt-1">
              <FormField label="Rule name" required yamlKey="title" hint="Used as filename and alert title. snake_case.">
                <Input
                  value={meta.title || ''}
                  onChange={(e) => setField('title', e.target.value)}
                  className="h-8 text-[12px] font-mono"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Description" yamlKey="description" hint="Shown in alerts and the rule catalog.">
                <Textarea
                  value={meta.description || ''}
                  onChange={(e) => setField('description', e.target.value)}
                  rows={2}
                  className="text-[12px]"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Author" yamlKey="author" hint="Contact for triage questions.">
                <Input
                  value={meta.author || ''}
                  onChange={(e) => setField('author', e.target.value)}
                  className="h-8 text-[12px] font-mono"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Tags" yamlKey="tags" hint="Used to organize rules and feed reporting.">
                <ChipEditor
                  values={tagsArr}
                  onAdd={(v) => addChip('tags', v)}
                  onRemove={(v) => removeChip('tags', v)}
                  placeholder="+ tag"
                  prefix="#"
                  readOnly={readOnly}
                />
              </FormField>
            </div>
          </section>

          <section className="mt-6">
            <SectionHead icon={<Shield className="w-3.5 h-3.5" strokeWidth={1.75} />} title="Severity & lifecycle" />
            <div className="pt-1">
              <FormField label="Severity" required yamlKey="severity" hint="Drives routing priority and SLA.">
                <div className="inline-flex items-center gap-1 rounded-md border border-border p-0.5">
                  {(['low', 'medium', 'high', 'critical'] as SevKey[]).map((s) => {
                    const active = (meta.severity || 'medium') === s;
                    return (
                      <button
                        key={s}
                        type="button"
                        onClick={() => setField('severity', s)}
                        disabled={readOnly}
                        className={cn(
                          'h-7 px-3 rounded text-[11px] font-mono font-semibold uppercase tracking-[0.08em] transition-colors',
                          active ? '' : 'text-muted-foreground hover:text-foreground',
                        )}
                        style={
                          active
                            ? { background: SEV_CHIP_BG[s], color: SEV_CHIP_FG[s] }
                            : undefined
                        }
                      >
                        {s}
                      </button>
                    );
                  })}
                </div>
              </FormField>
              <FormField label="Mode" required yamlKey="mode" hint="Live fires alerts. Staging evaluates silently.">
                <div className="space-y-1.5">
                  {([
                    { k: 'staging', d: 'Evaluates but suppresses output (bake-in)' },
                    { k: 'live', d: 'Counts matches; no alerts' },
                    { k: 'alerting', d: 'Full production — emits alerts to routed channels' },
                    { k: 'paused', d: 'Rule does not run' },
                  ] as Array<{ k: ModeKey; d: string }>).map((o) => (
                    <label
                      key={o.k}
                      className={cn(
                        'flex items-center gap-2 p-1.5 rounded cursor-pointer',
                        readOnly ? 'cursor-not-allowed' : 'hover:bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)]',
                      )}
                    >
                      <input
                        type="radio"
                        name="mode"
                        checked={(meta.mode || 'staging') === o.k}
                        onChange={() => setField('mode', o.k)}
                        disabled={readOnly}
                        className="accent-[var(--primary)]"
                      />
                      <div className="text-[12px] font-semibold capitalize">{o.k}</div>
                      <div className="text-[11px] text-muted-foreground">— {o.d}</div>
                    </label>
                  ))}
                </div>
              </FormField>
            </div>
          </section>

          <section className="mt-6">
            <SectionHead icon={<Clock className="w-3.5 h-3.5" strokeWidth={1.75} />} title="Schedule" />
            <div className="pt-1">
              <FormField label="Detection mode" yamlKey="detection_mode">
                <div className="inline-flex rounded-md border border-border p-0.5">
                  {(['realtime', 'scheduled'] as DetectionModeKey[]).map((m) => {
                    const active = (meta.detection_mode || 'realtime') === m;
                    return (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setField('detection_mode', m)}
                        disabled={readOnly}
                        className={cn(
                          'h-7 px-2.5 rounded text-[11px] font-mono',
                          active
                            ? 'bg-[color-mix(in_srgb,var(--primary)_18%,transparent)] text-[var(--primary)]'
                            : 'text-muted-foreground hover:text-foreground',
                        )}
                      >
                        {m === 'realtime' ? 'real-time' : m}
                      </button>
                    );
                  })}
                </div>
              </FormField>
              {meta.detection_mode === 'scheduled' && (
                <FormField label="Cron expression" yamlKey="schedule" hint="5 fields: minute hour dom month dow">
                  <div className="flex items-center gap-2">
                    <Input
                      value={meta.schedule || ''}
                      onChange={(e) => setField('schedule', e.target.value)}
                      className="h-8 text-[12px] font-mono flex-1"
                      readOnly={readOnly}
                    />
                    <div className="text-[11px] font-mono text-muted-foreground">= {cronHuman(meta.schedule)}</div>
                  </div>
                </FormField>
              )}
              <FormField label="Lookback" yamlKey="lookback" hint="Window each evaluation considers (max 7d).">
                <Input
                  value={meta.lookback || ''}
                  onChange={(e) => setField('lookback', e.target.value)}
                  placeholder="15m"
                  className="w-24 h-8 text-[12px] font-mono"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Alert mode" yamlKey="alert_mode" hint="How matches batch into alerts.">
                <div className="inline-flex rounded-md border border-border p-0.5">
                  {(['grouped', 'per_event'] as AlertModeKey[]).map((m) => {
                    const active = (meta.alert_mode || 'grouped') === m;
                    return (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setField('alert_mode', m)}
                        disabled={readOnly}
                        className={cn(
                          'h-7 px-2.5 rounded text-[11px] font-mono',
                          active
                            ? 'bg-[color-mix(in_srgb,var(--primary)_18%,transparent)] text-[var(--primary)]'
                            : 'text-muted-foreground hover:text-foreground',
                        )}
                      >
                        {m}
                      </button>
                    );
                  })}
                </div>
              </FormField>
            </div>
          </section>

          <section className="mt-6">
            <SectionHead icon={<Globe className="w-3.5 h-3.5" strokeWidth={1.75} />} title="MITRE mapping" />
            <div className="pt-1">
              <FormField label="Tactics" yamlKey="mitre_tactics" hint="Comma-separated TA0000 IDs.">
                <ChipEditor
                  values={tacticsArr}
                  onAdd={(v) => addChip('mitre_tactics', v)}
                  onRemove={(v) => removeChip('mitre_tactics', v)}
                  placeholder="+ TA0000"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Techniques" yamlKey="mitre_techniques" hint="Comma-separated T0000 IDs.">
                <ChipEditor
                  values={techniquesArr}
                  onAdd={(v) => addChip('mitre_techniques', v)}
                  onRemove={(v) => removeChip('mitre_techniques', v)}
                  placeholder="+ T0000"
                  readOnly={readOnly}
                />
              </FormField>
              <FormField label="Reference URL" yamlKey="reference_url" hint="Link to playbook / runbook / analysis.">
                <Input
                  value={meta.reference_url || ''}
                  onChange={(e) => setField('reference_url', e.target.value)}
                  className="h-8 text-[12px] font-mono"
                  readOnly={readOnly}
                />
              </FormField>
            </div>
          </section>

          <section className="mt-6">
            <SectionHead
              icon={<Terminal className="w-3.5 h-3.5" strokeWidth={1.75} />}
              title="Detection query"
              note="body of the rule file"
            />
            <div className="pt-3">
              <pre className="font-mono text-[12px] leading-[1.6] bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] border border-border rounded p-3 whitespace-pre-wrap overflow-x-auto">
                {query || <span className="text-muted-foreground">// empty query — switch to CODE to author it</span>}
              </pre>
              <div className="mt-1.5 text-[11px] font-mono text-muted-foreground">
                Edit in CODE view for syntax highlighting, autocomplete, and validation.
              </div>
            </div>
          </section>
        </div>
      </ScrollArea>
    </div>
  );
}

function ChipEditor({
  values,
  onAdd,
  onRemove,
  placeholder,
  prefix,
  readOnly,
}: {
  values: string[];
  onAdd: (v: string) => void;
  onRemove: (v: string) => void;
  placeholder: string;
  prefix?: string;
  readOnly?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1 items-center">
      {values.map((v) => (
        <span
          key={v}
          className="inline-flex items-center gap-1 px-1.5 h-6 rounded text-[11px] font-mono"
          style={{
            background: 'color-mix(in srgb, var(--foreground) 8%, transparent)',
            color: 'var(--foreground)',
          }}
        >
          {prefix}
          {v}
          {!readOnly && (
            <button
              type="button"
              onClick={() => onRemove(v)}
              className="text-muted-foreground hover:text-[var(--destructive)] -mr-0.5"
              aria-label={`Remove ${v}`}
            >
              ×
            </button>
          )}
        </span>
      ))}
      {!readOnly && (
        <input
          type="text"
          placeholder={placeholder}
          className="h-6 px-2 bg-transparent border border-dashed border-border rounded text-[11px] font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-[var(--foreground)]/40 min-w-[80px]"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              const v = (e.target as HTMLInputElement).value;
              if (v) {
                onAdd(v.replace(/,$/, ''));
                (e.target as HTMLInputElement).value = '';
              }
            }
          }}
        />
      )}
    </div>
  );
}
