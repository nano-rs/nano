// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-577 — Getting Started page. Ported to Wave 18+ aesthetic.
 *
 * Source of truth: design-ref/onboarding.html.
 *
 * Behavior is unchanged from the previous shadcn implementation — same
 * hooks, same step list, same managed-mode AI override, same SSO
 * Pro-tier lock, same skip/dismiss/finish flows. Only the visual
 * language is new (numbered rail, mono status pills, segmented progress
 * bar, brand-accent buttons, pulse-dot footer).
 */

import { useMemo, useCallback } from 'react';
import { useNavigate, Navigate, Link } from 'react-router-dom';
import {
  Cloud,
  Building2,
  Users,
  Shield,
  Activity,
  Code,
  Search,
  Check,
  Loader2,
  X,
  ExternalLink,
  ArrowRight,
  SkipForward,
  Lock,
  Sparkles,
  ArrowUpRight,
} from 'lucide-react';
import {
  useOnboardingProgress,
  useOnboardingStatus,
  useCompleteOnboardingStep,
  useSkipOnboardingStep,
  useDismissOnboarding,
  useSystemConfig,
} from '@/hooks/use-api';
import { useTierContext } from '@/hooks/use-tier';
import { useCapabilities } from '@/hooks/use-capabilities';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { OnboardingStep, OnboardingStatus } from '@/lib/api/onboarding';
import { cn } from '@/lib/utils';

interface SetupStep {
  key: OnboardingStep;
  label: string;
  icon: typeof Cloud;
  description: string;
  href: string;
  statusKey: keyof OnboardingStatus;
  doneLabel: string;
  todoLabel: string;
  /** Build-time capability gate — open-core builds drop enterprise steps. */
  capability?: keyof Capabilities;
}

const STEPS: SetupStep[] = [
  {
    key: 'ai_setup',
    label: 'AI Setup',
    icon: Sparkles,
    description: 'Configure an LLM provider to power AI-assisted parsing, detection, and investigations.',
    href: '/settings/ai?tab=providers',
    statusKey: 'has_ai_provider',
    doneLabel: 'Provider configured',
    todoLabel: 'Not configured',
    capability: 'melod',
  },
  {
    key: 'org_context',
    label: 'Organization Context',
    icon: Building2,
    description: 'Tell the AI about your org so it can give more relevant guidance and detection tuning.',
    href: '/settings/ai?tab=guidance',
    statusKey: 'has_org_context',
    doneLabel: 'Context set',
    todoLabel: 'Not configured',
    capability: 'melod',
  },
  {
    key: 'team_setup',
    label: 'Team Setup',
    icon: Users,
    description: 'Add analysts, engineers, and admins. Assign groups and roles for access control.',
    href: '/settings/access-control',
    statusKey: 'has_users',
    doneLabel: 'Team members added',
    todoLabel: 'Only you so far',
  },
  {
    key: 'sso_setup',
    label: 'Single Sign-On',
    icon: Shield,
    description: 'Connect your identity provider (Entra ID, Okta, Google) for centralized authentication.',
    href: '/settings/access-control?tab=sso',
    statusKey: 'has_sso',
    doneLabel: 'SSO configured',
    todoLabel: 'Not configured',
    capability: 'sso',
  },
  {
    key: 'first_feed',
    label: 'Log Source',
    icon: Activity,
    description: 'Connect your first log source to start ingesting data into nano.',
    href: '/ingestion/log-sources/wizard',
    statusKey: 'has_log_sources',
    doneLabel: 'Feed connected',
    todoLabel: 'No feeds yet',
  },
  {
    key: 'create_parser',
    label: 'Log Parser',
    icon: Code,
    description: 'Create a parser to normalize raw logs into the Unified Data Model for searching and detection.',
    href: '/ingestion/log-sources/wizard',
    statusKey: 'has_parsers',
    doneLabel: 'Parser created',
    todoLabel: 'No parsers yet',
  },
  {
    key: 'first_searches',
    label: 'First Search',
    icon: Search,
    description: 'Run your first nPL query to explore your data and get familiar with the search experience.',
    href: '/search',
    statusKey: 'has_search_history',
    doneLabel: 'Searches run',
    todoLabel: 'No searches yet',
  },
];

const Eyebrow = ({ children }: { children: React.ReactNode }) => (
  <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
    {children}
  </span>
);

export function OnboardingWizard() {
  const navigate = useNavigate();
  const { data: progress, loading: progressLoading, refetch: refetchProgress } = useOnboardingProgress();
  const { data: status } = useOnboardingStatus();
  const { data: systemConfig } = useSystemConfig();
  const { hasSso } = useTierContext();
  const { capabilities } = useCapabilities();
  const isManaged = systemConfig?.deployment_mode === 'managed';

  const steps = useMemo(() => {
    // Build-time capability gate — open-core builds drop enterprise-only steps
    // (AI setup, org context, SSO) so we don't route users to upsell paywalls.
    const enabled = STEPS.filter((step) => !step.capability || capabilities[step.capability]);
    if (!isManaged) return enabled;
    return enabled.map((step) =>
      step.key === 'ai_setup'
        ? {
            ...step,
            description: 'AI is automatically configured for your managed deployment.',
            doneLabel: 'Automatically configured',
            todoLabel: 'Automatically configured',
          }
        : step,
    );
  }, [isManaged, capabilities]);

  const { mutate: completeStep } = useCompleteOnboardingStep();
  const { mutate: skipStep } = useSkipOnboardingStep();
  const { mutate: dismissOnboarding } = useDismissOnboarding();
  const completedSteps = useMemo(() => progress?.completed_steps || [], [progress]);
  const skippedSteps = useMemo(() => progress?.skipped_steps || [], [progress]);

  const stepStates = useMemo(
    () =>
      steps.map((s) => {
        const isLocked = s.key === 'sso_setup' && !hasSso;
        const isDone = (status?.[s.statusKey] ?? false) || completedSteps.includes(s.key);
        const isSkipped = skippedSteps.includes(s.key);
        // A locked step counts as "satisfied" for progress purposes so the bar
        // can fill to 100% without forcing the user onto an unavailable tier.
        const counted = isDone || isSkipped || isLocked;
        return { step: s, isDone, isSkipped, isLocked, counted };
      }),
    [steps, status, completedSteps, skippedSteps, hasSso],
  );

  const doneCount = stepStates.filter((s) => s.counted).length;
  const remaining = steps.length - doneCount;
  const progressPercent = Math.round((doneCount / steps.length) * 100);
  const estMinutes = Math.max(1, remaining * 2);

  const handleSkip = useCallback(
    async (step: OnboardingStep) => {
      try {
        await skipStep({ step });
        await refetchProgress();
      } catch (err) {
        console.error('Failed to skip step:', err);
      }
    },
    [skipStep, refetchProgress],
  );

  const handleDismiss = useCallback(async () => {
    try {
      await dismissOnboarding();
      navigate('/');
    } catch (err) {
      console.error('Failed to dismiss:', err);
    }
  }, [dismissOnboarding, navigate]);

  const handleFinish = useCallback(async () => {
    try {
      const pending = steps.filter((s) => {
        const isDone = status?.[s.statusKey] ?? false;
        return isDone && !completedSteps.includes(s.key);
      });
      await Promise.all(pending.map((s) => completeStep({ step: s.key })));
      await dismissOnboarding();
      navigate('/');
    } catch (err) {
      console.error('Failed to finish:', err);
    }
  }, [steps, status, completedSteps, completeStep, dismissOnboarding, navigate]);

  if (progressLoading) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // Once onboarding is dismissed or fully completed, redirect away —
  // the Getting Started page should no longer exist for this user.
  if (progress?.dismissed || progress?.completed_at) {
    return <Navigate to="/" replace />;
  }

  const allDone = doneCount === steps.length;

  return (
    <div className="mx-auto w-full max-w-[820px] space-y-3">
      {/* HEADER CARD */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="mb-3 flex items-center gap-2">
          <Sparkles className="h-3 w-3 text-primary" />
          <Eyebrow>Getting Started</Eyebrow>
        </div>
        <div className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-muted-foreground/70">
          <span>instance setup</span>
          <span className="text-muted-foreground/40">·</span>
          <span>first data source</span>
          <span className="text-muted-foreground/40">·</span>
          <span>search readiness</span>
        </div>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1
              className="font-semibold tracking-tight text-foreground"
              style={{ fontSize: '26px', lineHeight: 1.1 }}
            >
              Get nano running.
            </h1>
            <p className="mt-2 text-[12.5px] text-muted-foreground/80" style={{ textWrap: 'pretty' }}>
              Set up your nano instance step by step. Click any item to configure it &mdash; come back any time.
            </p>
          </div>
          <button
            type="button"
            onClick={handleDismiss}
            className="inline-flex h-7 shrink-0 items-center gap-1 rounded-md border border-border/70 px-2.5 text-[11.5px] text-muted-foreground hover:bg-muted/50 hover:text-foreground"
          >
            <X className="h-[11px] w-[11px]" />
            Dismiss
          </button>
        </div>
      </div>

      {/* PROGRESS CARD */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="mb-3 flex items-center gap-2">
          <Eyebrow>Setup progress</Eyebrow>
          <div className="flex-1" />
          <span className="font-display text-[20px] leading-none tabular-nums text-foreground">
            {doneCount}
            <span className="text-muted-foreground/70">/{steps.length}</span>
          </span>
        </div>
        <div className="flex gap-[3px]" role="progressbar" aria-valuenow={progressPercent} aria-valuemin={0} aria-valuemax={100}>
          {stepStates.map(({ step, counted }) => (
            <div
              key={step.key}
              className={cn(
                'h-2 flex-1 rounded-[1px]',
                counted ? 'bg-primary' : 'bg-foreground/[0.06]',
              )}
            />
          ))}
        </div>
        <div className="mt-2.5 flex items-center justify-between">
          <span className="font-mono text-[10.5px] text-muted-foreground/70">
            {progressPercent}% complete &middot;{' '}
            <span className="text-muted-foreground">{remaining}</span> remaining
          </span>
          <span className="font-mono text-[10.5px] text-muted-foreground/70">
            est. <span className="text-muted-foreground">~ {estMinutes} min</span> to finish
          </span>
        </div>
      </div>

      {/* STEP ROWS */}
      <div className="space-y-2">
        {stepStates.map(({ step, isDone, isSkipped, isLocked }, idx) => {
          const Icon = step.icon;
          return (
            <div
              key={step.key}
              className={cn(
                'group relative flex items-center gap-4 rounded-xl border bg-card px-4 py-3.5 transition-colors',
                isLocked
                  ? 'border-border/60 opacity-70'
                  : isDone
                  ? 'border-emerald-500/25 hover:border-emerald-500/40'
                  : isSkipped
                  ? 'border-border/60 opacity-70'
                  : 'border-border hover:border-border/70 hover:bg-muted/30',
              )}
            >
              {/* leading number + icon */}
              <div className="flex shrink-0 items-center gap-3">
                <span className="w-4 text-right font-mono text-[10px] tabular-nums text-muted-foreground/40">
                  {String(idx + 1).padStart(2, '0')}
                </span>
                <div
                  className={cn(
                    'flex h-8 w-8 shrink-0 items-center justify-center rounded-md border',
                    isLocked
                      ? 'border-border/70 bg-muted/30 text-muted-foreground/70'
                      : isDone
                      ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-500'
                      : 'border-border/70 bg-foreground/[0.025] text-muted-foreground',
                  )}
                >
                  {isLocked ? (
                    <Lock className="h-[14px] w-[14px]" />
                  ) : isDone ? (
                    <Check className="h-[14px] w-[14px]" />
                  ) : (
                    <Icon className="h-[14px] w-[14px]" />
                  )}
                </div>
              </div>

              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-[13.5px] font-semibold text-foreground">{step.label}</span>
                  <StatusPill isDone={isDone} isSkipped={isSkipped} isLocked={isLocked} step={step} />
                </div>
                <p
                  className="mt-1 text-[11.5px] leading-[1.5] text-muted-foreground/80"
                  style={{ textWrap: 'pretty' }}
                >
                  {isLocked
                    ? 'SSO is available on Pro and above. Upgrade to connect your identity provider.'
                    : step.description}
                </p>
              </div>

              <div className="flex shrink-0 items-center gap-1">
                {isLocked ? (
                  <Link
                    to="/settings/billing"
                    className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 text-[11.5px] font-medium text-amber-500 hover:bg-amber-500/15"
                  >
                    Upgrade
                    <ArrowUpRight className="h-[11px] w-[11px]" />
                  </Link>
                ) : (
                  <>
                    {!isDone && !isSkipped && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSkip(step.key);
                        }}
                        className="inline-flex h-7 items-center gap-1 px-2 text-[11px] text-muted-foreground/70 opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100"
                      >
                        <SkipForward className="h-3 w-3" />
                        Skip
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => navigate(step.href)}
                      className={cn(
                        'inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md px-2.5 text-[11.5px] font-medium',
                        isDone
                          ? 'text-muted-foreground hover:bg-muted/40 hover:text-foreground'
                          : 'border border-primary/40 bg-primary/10 text-primary hover:bg-primary/15',
                      )}
                    >
                      {isDone ? (
                        <>
                          <ExternalLink className="h-[11px] w-[11px]" />
                          Review
                        </>
                      ) : (
                        <>
                          Configure
                          <ArrowRight className="h-[11px] w-[11px]" />
                        </>
                      )}
                    </button>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* FOOTER ACTION ROW */}
      <div className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-3">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
        <span className="text-[12.5px] text-muted-foreground">
          Complete each step or finish early to get started.
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => navigate('/')}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border/70 px-3 text-[12px] text-muted-foreground hover:bg-muted/50 hover:text-foreground"
        >
          Skip for now
        </button>
        <button
          type="button"
          onClick={handleFinish}
          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12px] font-medium text-primary-foreground hover:bg-primary/90"
        >
          <Check className="h-[12px] w-[12px]" />
          {allDone ? 'Finish setup' : 'Finish early'}
        </button>
      </div>

      {/* SUB-FOOTER */}
      <div className="mt-4 flex items-center border-t border-border pt-3 font-mono text-[10.5px] tabular-nums text-muted-foreground/70">
        <span>nano &middot; home &middot; first run</span>
        <span className="flex-1" />
        <span>
          need a hand?{' '}
          <a
            href="https://nano.rs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            talk to support
          </a>
        </span>
      </div>
    </div>
  );
}

interface StatusPillProps {
  isDone: boolean;
  isSkipped: boolean;
  isLocked: boolean;
  step: SetupStep;
}

function StatusPill({ isDone, isSkipped, isLocked, step }: StatusPillProps) {
  const tone = isLocked
    ? 'bg-amber-500/10 border-amber-500/30 text-amber-500'
    : isDone
    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500'
    : isSkipped
    ? 'bg-muted/40 border-border/70 text-muted-foreground'
    : 'bg-amber-500/10 border-amber-500/30 text-amber-500';

  const label = isLocked
    ? 'Pro tier'
    : isDone
    ? step.doneLabel
    : isSkipped
    ? 'Skipped'
    : step.todoLabel;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-[0.1em]',
        tone,
      )}
    >
      {isDone && (
        <span
          className="h-1 w-1 rounded-full bg-emerald-500"
          style={{ boxShadow: '0 0 4px currentColor' }}
        />
      )}
      {label}
    </span>
  );
}
