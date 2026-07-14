import { useEffect, useState } from 'react';

import { Markdown } from '../lib/markdown';
import { api, errorMessage } from '../lib/ipc';
import type { NotebookEntry, PivtSession } from '../lib/types';
import { Spinner } from './ui';

/**
 * Past pivt investigations.
 *
 * A session is not a separate store — it IS the notebook pivt wrote itself into
 * while it worked (`agent.rs` records every question, tool call and answer as it
 * happens, so a closed panel or a crashed webview can't lose the record). This
 * screen reads them back: what was asked, what pivt did about it, what it found.
 *
 * That makes it the audit trail. Everything shown is agent output, which is
 * downstream of log content the attacker wrote, so it renders through the same
 * containment-first renderer the panel uses.
 */
interface Props {
  /** Pick this investigation back up in the pivt panel. */
  onContinue: (session: PivtSession, entries: NotebookEntry[]) => void;
  /** pivt is mid-answer — resuming another session now would fork it. */
  disabled?: boolean;
}

export function SessionsPane({ onContinue, disabled }: Props) {
  const [sessions, setSessions] = useState<PivtSession[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<PivtSession | null>(null);

  useEffect(() => {
    api
      .pivtSessions()
      .then(setSessions)
      .catch((caught) => setError(errorMessage(caught)));
  }, []);

  return (
    <div className="flex min-h-0 flex-1">
      <div className="flex w-[320px] shrink-0 flex-col border-r border-line">
        <div className="border-b border-line px-4 py-3">
          <div className="text-[13px] font-semibold text-t1">Sessions</div>
          <div className="mt-0.5 text-[11px] text-t4">
            Every pivt investigation, as it recorded itself.
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-auto p-2">
          {!sessions && !error && (
            <div className="flex items-center gap-2 p-2 text-[12px] text-t3">
              <Spinner className="text-accent" /> Loading…
            </div>
          )}

          {error && (
            <div className="m-2 rounded-[8px] border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">
              {/* Notebooks are an Enterprise handler. On an instance without them
                  this is a 403 — say so, rather than showing an empty list that
                  implies pivt has never been used. */}
              Sessions aren't available on this instance: {error}
            </div>
          )}

          {sessions?.length === 0 && (
            <div className="p-2 text-[12px] text-t4">
              No pivt sessions yet. Ask pivt something (⌘I) and it will keep a record here.
            </div>
          )}

          {sessions?.map((session) => (
            <button
              key={session.id}
              onClick={() => setSelected(session)}
              className={`flex w-full flex-col items-start gap-0.5 rounded-[7px] px-2.5 py-2 text-left ${
                selected?.id === session.id ? 'bg-accent-soft' : 'hover:bg-hover'
              }`}
            >
              <span className="w-full truncate text-[12.5px] text-t1">
                {stripPrefix(session.title)}
              </span>
              <span className="font-mono text-[10.5px] text-t4">
                {when(session.created_at)} · {session.status}
              </span>
            </button>
          ))}
        </div>
      </div>

      {selected ? (
        <Transcript session={selected} onContinue={onContinue} disabled={disabled} />
      ) : (
        <div className="flex flex-1 items-center justify-center text-[12.5px] text-t4">
          Pick a session to read what pivt did.
        </div>
      )}
    </div>
  );
}

/** What pivt was asked, what it ran, and what it concluded — in order. */
function Transcript({
  session,
  onContinue,
  disabled,
}: {
  session: PivtSession;
  onContinue: (session: PivtSession, entries: NotebookEntry[]) => void;
  disabled?: boolean;
}) {
  const [entries, setEntries] = useState<NotebookEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Guarded, and not optionally: click a big session then a small one, and the
    // slow first response lands last. Without this, session A's tool calls and
    // conclusions would render beneath session B's title — a fabricated record,
    // on the one screen whose entire job is to say what pivt actually did.
    let cancelled = false;

    setEntries(null);
    setError(null);
    api
      .notebookEntries(session.id)
      .then((response) => {
        if (cancelled) return;
        // The endpoint has returned both shapes across versions; tolerate either
        // rather than rendering an empty transcript for a session that has one.
        setEntries(Array.isArray(response) ? response : (response.entries ?? []));
      })
      .catch((caught) => {
        if (!cancelled) setError(errorMessage(caught));
      });

    return () => {
      cancelled = true;
    };
  }, [session.id]);

  return (
    <div className="flex min-w-0 flex-1 flex-col overflow-auto p-5">
      <div className="text-[15px] font-semibold text-t1">{stripPrefix(session.title)}</div>
      <div className="mt-1 flex items-center gap-3">
        <span className="font-mono text-[11px] text-t4">
          {session.id} · opened {when(session.created_at)}
        </span>
        <span className="flex-1" />
        {/* An investigation doesn't end when you close the app. */}
        <button
          onClick={() => entries && onContinue(session, entries)}
          disabled={!entries || disabled}
          title={disabled ? 'pivt is busy — wait for the current answer to finish' : undefined}
          className="shrink-0 rounded-[7px] border border-accent-line bg-accent-fill px-2.5 py-1 text-[11.5px] font-semibold text-accent disabled:opacity-40"
        >
          ✳ Continue in pivt
        </button>
      </div>

      {!entries && !error && (
        <div className="mt-4 flex items-center gap-2 text-[12px] text-t3">
          <Spinner className="text-accent" /> Loading the transcript…
        </div>
      )}

      {error && (
        <div className="mt-4 rounded-[8px] border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {error}
        </div>
      )}

      <div className="mt-4 space-y-3">
        {entries?.map((entry) => (
          <Entry key={entry.id} entry={entry} />
        ))}
        {entries?.length === 0 && (
          <div className="text-[12px] text-t4">This session recorded no entries.</div>
        )}
      </div>
    </div>
  );
}

function Entry({ entry }: { entry: NotebookEntry }) {
  const text = typeof entry.content.text === 'string' ? entry.content.text : '';

  switch (entry.entry_type) {
    case 'ai_chat_message':
      return (
        <div className="max-w-[80%] rounded-[11px_11px_11px_3px] border border-accent-line bg-accent-soft px-3 py-2 text-[12.5px] break-words text-t1">
          {text}
        </div>
      );

    case 'ai_query':
      // The tool call and its arguments — the part an auditor cares about.
      return (
        <div className="rounded-[8px] border border-line-strong bg-black/25 px-3 py-2 font-mono text-[11px]">
          <span className="text-accent">⏺ {String(entry.content.tool ?? 'tool')}</span>
          <div className="mt-0.5 break-all text-t4">
            {JSON.stringify(entry.content.input ?? {})}
          </div>
        </div>
      );

    case 'ai_chat_response':
      return (
        <div className="max-w-[92%] rounded-[11px] border border-line-strong bg-white/5 px-3 py-2.5 text-[12.5px] text-t2">
          <Markdown text={text} />
        </div>
      );

    case 'ai_summary':
      return (
        <div className="rounded-[8px] border border-line px-3 py-2 text-[11.5px] text-t3">
          <span className="font-semibold text-t2">Result</span>
          {entry.content.turns != null && <span> · {String(entry.content.turns)} turns</span>}
          {entry.content.cost_usd != null && (
            <span> · ${Number(entry.content.cost_usd).toFixed(4)}</span>
          )}
        </div>
      );

    default:
      return null;
  }
}

/** The list already says these are pivt's; the prefix is noise in it. */
function stripPrefix(title: string): string {
  return title.replace(/^pivt\s*·\s*/, '') || 'pivt session';
}

function when(timestamp: string): string {
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleString();
}
