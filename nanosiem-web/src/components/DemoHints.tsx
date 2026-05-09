// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Demo onboarding hint components
 *
 * Contextual, dismissible hint cards shown to demo users on first visit
 * to key pages. Tracks dismissal in localStorage per-page.
 */

import { useState } from 'react';
import { X, Search, Shield, Briefcase, BarChart3, ArrowRight, Play } from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';

// ============================================================================
// Core DemoHint wrapper
// ============================================================================

interface DemoHintProps {
  id: string;
  children: React.ReactNode;
}

function DemoHint({ id, children }: DemoHintProps) {
  const { isDemoUser } = useAuth();
  const storageKey = `demo-hint-dismissed-${id}`;
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem(storageKey) === '1'; } catch { return false; }
  });

  if (!isDemoUser || dismissed) return null;

  const dismiss = () => {
    setDismissed(true);
    try { localStorage.setItem(storageKey, '1'); } catch { /* noop */ }
  };

  return (
    <div className="relative rounded-xl border border-primary/20 bg-primary/5 p-4 mb-4">
      <button
        onClick={dismiss}
        className="absolute top-3 right-3 rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
        aria-label="Dismiss hint"
      >
        <X className="h-3.5 w-3.5" />
      </button>
      {children}
    </div>
  );
}

// ============================================================================
// Sample query chip
// ============================================================================

interface QueryChipProps {
  query: string;
  label: string;
  onClick: (query: string) => void;
}

function QueryChip({ query, label, onClick }: QueryChipProps) {
  return (
    <button
      onClick={() => onClick(query)}
      className="inline-flex items-center gap-1.5 rounded-lg border bg-background px-3 py-1.5 text-xs font-mono hover:border-primary/50 hover:bg-primary/5 transition-colors"
    >
      <Play className="h-3 w-3 text-primary" />
      <span className="truncate max-w-[280px]">{label}</span>
    </button>
  );
}

// ============================================================================
// Page-specific hints
// ============================================================================

/**
 * Search page hint: sample queries users can click to try
 */
export function SearchDemoHint({ onRunQuery }: { onRunQuery: (query: string) => void }) {
  const SAMPLE_QUERIES = [
    { query: 'source_type=windows_event event_id=4625 | stats count by user | sort -count | head 20', label: 'Failed logins by user' },
    { query: 'source_type=conduit_proxy | stats count by dest_host | sort -count | head 20', label: 'Top proxy destinations' },
    { query: 'src_host="lt-eng-012.corp.local" | asset', label: 'Asset investigation' },
    { query: '* | timechart span=1m count by source_type', label: 'Activity by source type' },
    { query: 'source_type=aws_cloudtrail | cloud', label: 'Cloud activity' },
  ];

  return (
    <DemoHint id="search">
      <div className="flex items-start gap-3 pr-6">
        <Search className="h-5 w-5 text-primary shrink-0 mt-0.5" />
        <div>
          <h3 className="text-sm font-semibold mb-1">Try a search query</h3>
          <p className="text-xs text-muted-foreground mb-3">
            Click any query below to run it against the demo dataset, or type your own using nPL (nano Pipe Language).
          </p>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_QUERIES.map((sq) => (
              <QueryChip key={sq.query} {...sq} onClick={onRunQuery} />
            ))}
          </div>
        </div>
      </div>
    </DemoHint>
  );
}

/**
 * Detections page hint: create first rule CTA
 */
export function DetectionsDemoHint() {
  const navigate = useNavigate();

  return (
    <DemoHint id="detections">
      <div className="flex items-start gap-3 pr-6">
        <Shield className="h-5 w-5 text-primary shrink-0 mt-0.5" />
        <div>
          <h3 className="text-sm font-semibold mb-1">Detection rules</h3>
          <p className="text-xs text-muted-foreground mb-3">
            Rules run on a schedule or in real-time to detect threats. They progress through
            Staging → Live → Alerting. Try creating one — it'll execute against the demo data.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => navigate('/rules/editor/new')}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              <PivtIcon className="h-3 w-3" />
              Create a Rule
            </button>
            <button
              onClick={() => navigate('/rules/test')}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors"
            >
              Test a Query
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      </div>
    </DemoHint>
  );
}

/**
 * Cases page hint: investigate threats
 */
export function CasesDemoHint() {
  const navigate = useNavigate();

  return (
    <DemoHint id="cases">
      <div className="flex items-start gap-3 pr-6">
        <Briefcase className="h-5 w-5 text-primary shrink-0 mt-0.5" />
        <div>
          <h3 className="text-sm font-semibold mb-1">Case management</h3>
          <p className="text-xs text-muted-foreground mb-3">
            Cases track investigations. When you create one, our AI "Shadow Investigator"
            automatically extracts entities and hunts for related activity across all log sources.
          </p>
          <button
            onClick={() => navigate('/cases', { state: { openNewCase: true } })}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <PivtIcon className="h-3 w-3" />
            Create a Case
          </button>
        </div>
      </div>
    </DemoHint>
  );
}

/**
 * Home/Dashboard hint: quick orientation
 */
export function HomeDemoHint() {
  const navigate = useNavigate();

  return (
    <DemoHint id="home">
      <div className="flex items-start gap-3 pr-6">
        <BarChart3 className="h-5 w-5 text-primary shrink-0 mt-0.5" />
        <div>
          <h3 className="text-sm font-semibold mb-1">Welcome to your demo environment</h3>
          <p className="text-xs text-muted-foreground mb-3">
            This instance has sample log data flowing from multiple sources.
            Explore detection rules, search for threats, create cases, and try AI-powered investigation.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => navigate('/search')}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              <Search className="h-3 w-3" />
              Search Logs
            </button>
            <button
              onClick={() => navigate('/rules')}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors"
            >
              <Shield className="h-3 w-3" />
              View Detections
            </button>
            <button
              onClick={() => navigate('/cases')}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors"
            >
              <Briefcase className="h-3 w-3" />
              Cases
            </button>
          </div>
        </div>
      </div>
    </DemoHint>
  );
}
