// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 / NAN-5850 — per-technique drill-down panel (design 4.6).
// Docked to the right of the matrix: header, Detection, Telemetry, Hunts
// (enterprise slot), Next step (the rule-idea bridge, 4.7), Sub-techniques.
// Every technique ID is its own coverage unit; a parent's rules and telemetry
// never roll down to a child.

import { EnterpriseTerm } from '@/enterprise/components/glossary/EnterpriseTerm';
import { Term } from '@/components/ui/term';
import { type ReactNode, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertTriangle, ExternalLink, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import {
  type CoveringRule,
  type RequiredDataSource,
  type TacticCoverage,
  type TechniqueCoverage,
  readinessLabel,
  readinessOf,
} from './types';
import {
  type TechniqueLayers,
  COVERAGE_COLOR,
  classLabel,
  telemetryLabel,
} from './layers';
import { LayerStrip } from './CoverageMatrix';
import { ClassSwatch, TelemetryDot } from './Legend';

const MODE_GROUPS: { key: string; label: string; match: (mode: string) => boolean }[] = [
  { key: 'alerting', label: 'Alerting', match: (m) => m === 'alerting' },
  { key: 'live', label: 'Live', match: (m) => m === 'live' },
  { key: 'staging', label: 'Staging', match: (m) => m === 'staging' || m === 'review' },
  { key: 'paused', label: 'Paused', match: (m) => !['alerting', 'live', 'staging', 'review'].includes(m) },
];

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#f5a524',
  low: '#6b7280',
};

function SeverityDot({ severity }: { severity: string }) {
  return (
    <span
      className="w-1.5 h-1.5 rounded-full shrink-0"
      title={severity}
      style={{ background: SEVERITY_COLOR[severity.toLowerCase()] ?? SEVERITY_COLOR.low }}
    />
  );
}

function SectionHead({ title, count, gate }: { title: string; count?: ReactNode; gate?: string }) {
  return (
    <h3 className="mb-1.5 flex items-baseline gap-1.5 text-[10.5px] font-medium uppercase tracking-wider text-muted-foreground">
      {title}
      {count != null && <span className="font-mono normal-case tracking-normal text-foreground/80">{count}</span>}
      {gate && <span className="ml-auto font-mono text-[10px] normal-case tracking-normal">{gate}</span>}
    </h3>
  );
}

function RuleRow({ rule }: { rule: CoveringRule }) {
  return (
    <Link
      to={`/rules/editor/${encodeURIComponent(rule.id)}`}
      className="flex h-6 items-center gap-2 rounded-sm px-1 -mx-1 text-[11.5px] hover:bg-secondary"
    >
      <SeverityDot severity={rule.severity} />
      <span className="font-mono text-[10.5px] text-foreground truncate flex-1 min-w-0">{rule.name}</span>
      {rule.source && <span className="font-mono text-[10.5px] text-muted-foreground shrink-0">{rule.source}</span>}
    </Link>
  );
}

function sourceSeen(source: RequiredDataSource): string {
  if (source.last_seen_at) {
    const at = new Date(source.last_seen_at);
    if (!Number.isNaN(at.getTime())) return `seen ${at.toISOString().slice(5, 16).replace('T', ' ')}`;
  }
  return readinessLabel(source);
}

function DataSourceRow({ source }: { source: RequiredDataSource }) {
  const readiness = readinessOf(source);
  const state = readiness === 'active'
    ? 'active'
    : readiness === 'stale'
      ? 'stale'
      : source.mapping_known === false
        ? 'unmapped'
        : source.configured === false
          ? 'missing'
          : 'unknown';
  return (
    <div className="flex h-6 items-center gap-2 text-[11.5px]" data-testid="coverage-panel-data-source">
      <TelemetryDot state={state} />
      <span className="truncate flex-1 min-w-[96px]" title={source.name}>{source.name}</span>
      {(source.source_types ?? []).length > 0 && (
        <span className="font-mono text-[10px] text-muted-foreground truncate max-w-[110px]" title={(source.source_types ?? []).join(', ')}>
          {(source.source_types ?? []).join(', ')}
        </span>
      )}
      <span className="font-mono text-[10.5px] text-muted-foreground shrink-0" title={source.last_seen_at ? `Last event ${source.last_seen_at}` : undefined}>{sourceSeen(source)}</span>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Next step (design 4.7).
// ----------------------------------------------------------------------------

export type PanelActionKey =
  | 'review_idea'
  | 'draft_rule'
  | 'draft_from_findings'
  | 'hunt_first'
  | 'onboard_source'
  | 'open_log_sources'
  | 'generate_ai';

/**
 * What the viewer may do from the panel and the Gaps table. `/rules/coverage`
 * only needs `detections:view`, so every action that leaves the page is gated
 * on its destination's own permission and hidden without it.
 */
export interface CoverageActionPerms {
  /** `detections:create`: Draft rule opens /rules/editor/new. */
  createRule: boolean;
  /** `log_sources:view`: Open log sources. */
  viewSources: boolean;
  /** `log_sources:create`: Onboard opens /ingestion/log-sources/new. */
  onboard: boolean;
}

const NO_ACTIONS: CoverageActionPerms = { createRule: false, viewSources: false, onboard: false };

interface NextStepProps {
  technique: TechniqueCoverage;
  facts: TechniqueLayers;
  huntLayer: boolean;
  tacticIds: string[];
  perms: CoverageActionPerms;
  onDraftFromFindings?: (() => void) | null;
  onHuntFirst?: (() => void) | null;
  onGenerateAi?: (() => void) | null;
}

export function draftRuleHref(techniqueId: string, tacticIds: string[]): string {
  const params = new URLSearchParams({ mitre: techniqueId });
  if (tacticIds.length) params.set('mitre_tactics', tacticIds.join(','));
  return `/rules/editor/new?${params.toString()}`;
}

function ActionButton({
  action,
  primary = false,
  onClick,
  children,
}: {
  action: PanelActionKey;
  primary?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Button
      size="sm"
      variant={primary ? 'default' : 'outline'}
      className="h-[26px] px-2.5 text-[11.5px]"
      data-testid={`coverage-panel-action-${action}`}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}

function NextStep({ technique, facts, huntLayer, tacticIds, perms, onDraftFromFindings, onHuntFirst, onGenerateAi }: NextStepProps) {
  const navigate = useNavigate();
  const id = technique.technique_id;
  const draft = () => navigate(draftRuleHref(id, tacticIds));
  const draftBtn = (primary = false) => (perms.createRule
    ? <ActionButton action="draft_rule" primary={primary} onClick={draft}>Draft rule</ActionButton>
    : null);
  const ideas = facts.layer?.rule_ideas;
  const firstSource = (technique.data_sources ?? []).flatMap((d) => d.source_types ?? [])[0];

  let body: ReactNode;
  let acts: ReactNode;

  if (facts.cls === 'both' || facts.cls === 'detected') {
    if (facts.noTelemetry) {
      body = 'Rules exist but their telemetry is not arriving. They cannot fire.';
      acts = perms.viewSources ? (
        <ActionButton action="open_log_sources" primary onClick={() => navigate('/ingestion/log-sources')}>
          Open log sources
        </ActionButton>
      ) : null;
    } else {
      body = `Covered by ${facts.live} live rule${facts.live === 1 ? '' : 's'}${facts.h === 'hunted' ? ' and hunted in the window' : ''}.`;
      acts = (
        <>
          {perms.createRule && <ActionButton action="draft_rule" onClick={draft}>Draft another rule</ActionButton>}
          {huntLayer && facts.h !== 'hunted' && onHuntFirst && (
            <ActionButton action="hunt_first" onClick={onHuntFirst}>Hunt it</ActionButton>
          )}
        </>
      );
    }
  } else if (huntLayer && ideas && ideas.ready > 0) {
    body = `A rule idea for ${id} passed the gate and is ready to send.`;
    acts = (
      <>
        <ActionButton
          action="review_idea"
          primary
          onClick={() => navigate(`/rules/ideas?technique=${encodeURIComponent(id)}`)}
        >
          Review <EnterpriseTerm id="rule-idea" nested>rule idea</EnterpriseTerm>
        </ActionButton>
        {draftBtn()}
      </>
    );
  } else if (huntLayer && ideas && ideas.keep_hunting > 0) {
    body = 'A rule idea is still gathering evidence. It needs the same lead in 3 sweeps, with 2 promoted to cases.';
    acts = (
      <>
        <Button
          size="sm"
          variant="outline"
          className="h-[26px] px-2.5 text-[11.5px]"
          onClick={() => navigate(`/rules/ideas?technique=${encodeURIComponent(id)}`)}
        >
          View rule idea
        </Button>
        {draftBtn()}
      </>
    );
  } else if (huntLayer && facts.cls === 'hunted' && facts.findings > 0) {
    body = `Hunted with ${facts.findings} finding${facts.findings === 1 ? '' : 's'} and no rule. Good rule input.`;
    acts = (
      <>
        {onDraftFromFindings && (
          <ActionButton action="draft_from_findings" primary onClick={onDraftFromFindings}>
            Draft rule from findings
          </ActionButton>
        )}
        {draftBtn(!onDraftFromFindings)}
      </>
    );
  } else if (facts.cls === 'hunted') {
    body = 'Hunted in the window with no findings yet and no rule.';
    acts = draftBtn(true);
  } else if (facts.cls === 'huntable') {
    body = huntLayer
      ? 'Telemetry is live and nothing watches this technique.'
      : 'Telemetry is live and no rule watches this technique.';
    acts = (
      <>
        {huntLayer && onHuntFirst && (
          <ActionButton action="hunt_first" primary onClick={onHuntFirst}>Hunt it first</ActionButton>
        )}
        {draftBtn(!(huntLayer && onHuntFirst))}
        {!huntLayer && onGenerateAi && (
          <ActionButton action="generate_ai" onClick={onGenerateAi}>Generate with AI</ActionButton>
        )}
      </>
    );
  } else {
    body = 'No telemetry for this technique. Onboard a source to make it detectable or huntable.';
    acts = (
      <>
        {perms.onboard && (
          <ActionButton action="onboard_source" primary onClick={() => navigate('/ingestion/log-sources/new')}>
            Onboard {firstSource ?? 'a source'}
          </ActionButton>
        )}
        {draftBtn()}
      </>
    );
  }

  return (
    <div className="rounded-[4px] border border-border px-2.5 py-2" data-testid="coverage-panel-next-step">
      <p className="mb-2 text-[11.5px] text-foreground/80">{body}</p>
      <div className="flex flex-wrap gap-1.5 empty:hidden">{acts}</div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Panel.
// ----------------------------------------------------------------------------

interface TechniqueDetailSheetProps {
  technique: TechniqueCoverage | null;
  parentTechnique?: TechniqueCoverage | null;
  /** Sub-techniques of the selected parent (or of the selected sub's parent). */
  subs?: TechniqueCoverage[];
  tacticsById: Map<string, TacticCoverage>;
  factsById: Map<string, TechniqueLayers>;
  huntLayer: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelectTechnique: (techniqueId: string) => void;
  /** Destination permissions for the Next step actions. */
  actionPerms?: CoverageActionPerms;
  /** Recon saw this technique regress from covered to blind since the last run. */
  regressed?: boolean;
  /** Enterprise: hunts targeting this technique (design 4.6 section 4). */
  huntsSection?: ReactNode;
  /** Enterprise: source-capability bindings for this technique's source types. */
  telemetryExtra?: ReactNode;
  onDraftFromFindings?: (() => void) | null;
  onHuntFirst?: (() => void) | null;
  onGenerateAi?: (() => void) | null;
}

export function TechniqueDetailSheet({
  technique,
  parentTechnique,
  subs = [],
  tacticsById,
  factsById,
  huntLayer,
  open,
  onOpenChange,
  onSelectTechnique,
  actionPerms = NO_ACTIONS,
  regressed = false,
  huntsSection,
  telemetryExtra,
  onDraftFromFindings,
  onHuntFirst,
  onGenerateAi,
}: TechniqueDetailSheetProps) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onOpenChange]);

  if (!open || !technique) return null;
  const facts = factsById.get(technique.technique_id);
  if (!facts) return null;

  const id = technique.technique_id;
  const mitreUrl = `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
  const rules = technique.rules || [];
  const color = facts.cls === 'unmapped' ? undefined : COVERAGE_COLOR[facts.cls];
  const parentContext = technique.is_subtechnique ? parentTechnique : null;
  const sources = technique.data_sources ?? [];

  return (
    <aside
      role="dialog"
      aria-label={`Technique ${id}`}
      data-testid="coverage-panel"
      data-technique={id}
      className="w-[420px] max-w-full shrink-0 border-l border-border bg-card overflow-y-auto max-[900px]:fixed max-[900px]:inset-y-0 max-[900px]:right-0 max-[900px]:z-40 max-[900px]:shadow-[0_24px_60px_rgba(0,0,0,0.5)]"
    >
      {/* Header */}
      <div className="px-3.5 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[12px] text-foreground/80">{id}</span>
          <span
            className="inline-flex items-center gap-1.5 rounded-[3px] border px-1.5 font-mono text-[10.5px] leading-[17px]"
            style={color ? { color, borderColor: color } : undefined}
            data-testid="coverage-panel-class"
          >
            <ClassSwatch cls={facts.cls} className="w-2 h-2" />
            {classLabel(facts.cls, huntLayer)}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto h-6 w-6"
            onClick={() => onOpenChange(false)}
            aria-label="Close technique panel"
          >
            <X className="w-[13px] h-[13px]" strokeWidth={1.5} />
          </Button>
        </div>
        <h2 className="mt-0.5 text-[14px] font-semibold text-foreground break-words">{technique.technique_name}</h2>
        <div className="mt-1 flex flex-wrap items-center gap-x-2 font-mono text-[10.5px] text-muted-foreground">
          {parentContext && (
            <button
              type="button"
              className="hover:text-foreground"
              onClick={() => onSelectTechnique(parentContext.technique_id)}
            >
              parent {parentContext.technique_id}
            </button>
          )}
          {technique.tactic_ids.map((tid) => (
            <span key={tid}>{tid} {tacticsById.get(tid)?.tactic_name ?? ''}</span>
          ))}
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            Open on attack.mitre.org <ExternalLink className="w-[10px] h-[10px]" strokeWidth={1.5} />
          </a>
        </div>
        {facts.noTelemetry && (
          <div
            className="mt-2 flex items-start gap-1.5 rounded-[4px] border px-2 py-1.5 text-[11px]"
            style={{ borderColor: `${COVERAGE_COLOR.warn}55`, color: COVERAGE_COLOR.warn }}
            data-testid="coverage-panel-no-telemetry"
          >
            <AlertTriangle className="mt-px h-3 w-3 shrink-0" strokeWidth={1.5} />
            <span><Term id="rule-no-telemetry">Rule, no telemetry</Term>: none of the data this rule needs arrived in the last 60 minutes, so it can&apos;t fire.</span>
          </div>
        )}
      </div>

      {/* Detection */}
      <section className="px-3.5 py-2.5 border-b border-border" data-testid="coverage-panel-detection">
        <SectionHead
          title="Detection"
          count={`${facts.live} live · ${rules.length} total`}
          gate="detections:view"
        />
        {rules.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground">No rule covers {id}.</div>
        ) : (
          MODE_GROUPS.map((group) => {
            const rows = rules.filter((r) => group.match(r.mode.toLowerCase()));
            if (rows.length === 0) return null;
            return (
              <div key={group.key}>
                <div className="mt-1 font-mono text-[10px] uppercase text-muted-foreground">
                  {group.label} · {rows.length}
                </div>
                {rows.map((rule) => <RuleRow key={rule.id} rule={rule} />)}
              </div>
            );
          })
        )}
      </section>

      {/* Telemetry */}
      <section className="px-3.5 py-2.5 border-b border-border" data-testid="coverage-panel-telemetry">
        <SectionHead title="Telemetry" count={telemetryLabel(facts.t)} />
        {sources.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground">ATT&amp;CK lists no <Term id="data-component">data components</Term> for {id}.</div>
        ) : (
          sources.map((d) => <DataSourceRow key={d.id} source={d} />)
        )}
        {facts.t === 'unmapped' && sources.length > 0 && (
          <div className="mt-1 text-[11px] text-muted-foreground">nano doesn&apos;t know which of your log sources carry this data yet.</div>
        )}
        {regressed && (
          <div className="mt-1 text-[11px]" style={{ color: COVERAGE_COLOR.warn }} data-testid="coverage-panel-regressed">
            <span><EnterpriseTerm id="regressed">Regressed</EnterpriseTerm> to blind: this technique had data coming in at the last <EnterpriseTerm id="recon">recon</EnterpriseTerm>, but none now.</span>
          </div>
        )}
        {telemetryExtra}
      </section>

      {/* Hunts (enterprise) */}
      {huntLayer && huntsSection}

      {/* Next step */}
      <section className="px-3.5 py-2.5 border-b border-border">
        <SectionHead title="Next step" />
        <NextStep
          technique={technique}
          facts={facts}
          huntLayer={huntLayer}
          tacticIds={technique.tactic_ids}
          perms={actionPerms}
          onDraftFromFindings={onDraftFromFindings}
          onHuntFirst={onHuntFirst}
          onGenerateAi={onGenerateAi}
        />
      </section>

      {/* Sub-techniques */}
      {subs.length > 0 && (
        <section className="px-3.5 py-2.5">
          <SectionHead title="Sub-techniques" count={subs.length} />
          {subs.map((s) => {
            const sf = factsById.get(s.technique_id);
            const active = s.technique_id === id;
            return (
              <button
                key={s.technique_id}
                type="button"
                onClick={() => onSelectTechnique(s.technique_id)}
                className={cn(
                  'flex h-6 w-full items-center gap-2 rounded-sm px-1 -mx-1 text-left text-[11.5px] hover:bg-secondary',
                  active && 'bg-secondary',
                )}
              >
                <span className="font-mono text-[10.5px] text-muted-foreground w-[68px] shrink-0">{s.technique_id}</span>
                <span className="truncate flex-1 min-w-0">{s.technique_name}</span>
                {sf && <LayerStrip facts={sf} huntLayer={huntLayer} />}
              </button>
            );
          })}
        </section>
      )}
    </aside>
  );
}
