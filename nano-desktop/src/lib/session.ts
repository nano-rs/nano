import type { NotebookEntry } from './types';

/**
 * Rebuilding a pivt session from the notebook it recorded itself into.
 *
 * An investigation does not finish when the analyst closes the app. The notebook
 * holds every question, every tool call and every answer — and, on each entry, the
 * Claude Code session id. With that, `claude --resume <id>` picks the conversation
 * back up exactly where it stopped, and the panel can be rehydrated with everything
 * that happened before, so the analyst is looking at their investigation rather
 * than an empty box that claims to be it.
 */

export interface ReplayItem {
  kind: 'text' | 'tool';
  text?: string;
  tool?: { name: string; input: Record<string, unknown> };
}

export interface ReplayExchange {
  question: string;
  items: ReplayItem[];
}

export interface Replay {
  exchanges: ReplayExchange[];
  /** What `--resume` needs. Absent on a session recorded before this existed. */
  sessionId: string | null;
  /** Entries the platform rejected leave holes; say so rather than imply completeness. */
  entryCount: number;
}

/**
 * The entries are a flat, ordered timeline. Group them back into exchanges: a
 * question opens one, and everything after it belongs to it until the next.
 */
export function replaySession(entries: NotebookEntry[]): Replay {
  const exchanges: ReplayExchange[] = [];
  let sessionId: string | null = null;

  const ordered = [...entries].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  );

  for (const entry of ordered) {
    const content = entry.content ?? {};
    const claude = content.claude_session_id;
    // The LAST id wins: a resumed session keeps the same one, and a fresh one
    // supersedes it.
    if (typeof claude === 'string' && claude) sessionId = claude;

    const text = typeof content.text === 'string' ? content.text : '';

    switch (entry.entry_type) {
      case 'ai_chat_message':
        exchanges.push({ question: text, items: [] });
        break;

      case 'ai_chat_response': {
        if (!text.trim()) break;
        current(exchanges).items.push({ kind: 'text', text });
        break;
      }

      case 'ai_query': {
        const name = typeof content.tool === 'string' ? content.tool : 'tool';
        const input =
          typeof content.input === 'object' && content.input !== null
            ? (content.input as Record<string, unknown>)
            : {};
        current(exchanges).items.push({ kind: 'tool', tool: { name, input } });
        break;
      }

      // ai_summary is the run's cost/turn tally, not something the analyst reads
      // back as part of the conversation.
      default:
        break;
    }
  }

  return { exchanges, sessionId, entryCount: ordered.length };
}

/**
 * The exchange being filled in. A transcript can legitimately begin with agent
 * output — a session resumed from elsewhere, or an entry the platform dropped —
 * so rather than lose it, open an exchange with no question rather than crash.
 */
function current(exchanges: ReplayExchange[]): ReplayExchange {
  if (exchanges.length === 0) exchanges.push({ question: '', items: [] });
  return exchanges[exchanges.length - 1];
}
