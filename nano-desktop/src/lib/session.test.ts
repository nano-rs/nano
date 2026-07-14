import { describe, expect, it } from 'vitest';

import { replaySession } from './session';
import type { NotebookEntry } from './types';

const entry = (
  entry_type: string,
  content: Record<string, unknown>,
  minute = 0
): NotebookEntry => ({
  id: `e${minute}`,
  entry_type,
  content,
  created_at: new Date(Date.UTC(2026, 6, 13, 9, minute)).toISOString(),
});

describe('replaySession', () => {
  it('rebuilds the conversation as exchanges, in order', () => {
    const replay = replaySession([
      entry('ai_chat_message', { text: 'what happened?' }, 0),
      entry('ai_query', { tool: 'search', input: { query: '* | stats count' } }, 1),
      entry('ai_chat_response', { text: 'Five events.' }, 2),
      entry('ai_chat_message', { text: 'and by host?' }, 3),
      entry('ai_chat_response', { text: 'Two hosts.' }, 4),
    ]);

    expect(replay.exchanges).toHaveLength(2);
    expect(replay.exchanges[0].question).toBe('what happened?');
    expect(replay.exchanges[0].items).toHaveLength(2);
    expect(replay.exchanges[0].items[0]).toMatchObject({ kind: 'tool' });
    expect(replay.exchanges[1].question).toBe('and by host?');
  });

  it('recovers the Claude session id, which is what makes it RESUMABLE', () => {
    const replay = replaySession([
      entry('ai_chat_message', { text: 'hi' }, 0),
      entry('ai_chat_response', { text: 'hello', claude_session_id: 'sess-1' }, 1),
    ]);
    expect(replay.sessionId).toBe('sess-1');
  });

  it('takes the LAST session id, so a resumed conversation supersedes an older one', () => {
    const replay = replaySession([
      entry('ai_chat_response', { text: 'a', claude_session_id: 'old' }, 0),
      entry('ai_chat_response', { text: 'b', claude_session_id: 'new' }, 1),
    ]);
    expect(replay.sessionId).toBe('new');
  });

  it('reports no session id rather than inventing one', () => {
    // A session recorded before the id was stamped cannot be continued. Saying so
    // beats silently starting a NEW conversation that looks like the old one.
    const replay = replaySession([entry('ai_chat_message', { text: 'hi' }, 0)]);
    expect(replay.sessionId).toBeNull();
  });

  it('sorts by time rather than trusting the array order', () => {
    const replay = replaySession([
      entry('ai_chat_response', { text: 'second' }, 5),
      entry('ai_chat_message', { text: 'first' }, 1),
    ]);
    expect(replay.exchanges[0].question).toBe('first');
    expect(replay.exchanges[0].items[0]).toMatchObject({ text: 'second' });
  });

  it('does not lose agent output that arrives before any question', () => {
    const replay = replaySession([entry('ai_chat_response', { text: 'orphan' }, 0)]);
    expect(replay.exchanges).toHaveLength(1);
    expect(replay.exchanges[0].items[0]).toMatchObject({ text: 'orphan' });
  });

  it('ignores the cost tally, which is not part of the conversation', () => {
    const replay = replaySession([
      entry('ai_chat_message', { text: 'hi' }, 0),
      entry('ai_summary', { turns: 3, cost_usd: 0.02 }, 1),
    ]);
    expect(replay.exchanges[0].items).toHaveLength(0);
  });

  it('survives an empty notebook', () => {
    expect(replaySession([]).exchanges).toEqual([]);
  });
});
