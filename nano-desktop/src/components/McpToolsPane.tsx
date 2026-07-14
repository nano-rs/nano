import { useCallback, useEffect, useMemo, useState } from 'react';

import { api, errorMessage } from '../lib/ipc';
import type { AgentStatus, McpTool } from '../lib/types';
import { Spinner } from './ui';

/**
 * What nano exposes to agents, and what they're actually allowed to do with it.
 *
 * The tool list is asked of the MCP server itself over stdio — the same server,
 * the same generated config, that Claude Code and Codex are launched with. It is
 * not a hardcoded list, because a hardcoded list is a promise the app can't keep:
 * the real server currently exposes 69 tools, the design mock drew 9, and a screen
 * that confidently shows the wrong inventory is worse than no screen.
 *
 * The mock also drew a per-tool POLICY column (auto-allow → ask each time →
 * 2-person confirm). That engine does not exist. It is not drawn here: a policy
 * dropdown that silently enforces nothing is a lie told in a security console.
 * What IS shown is what's true — the scopes the key actually holds, and which
 * tools it therefore cannot call.
 *
 * It is also where the key is connected and revoked. Those controls used to be in
 * two other places (the user menu and the terminal drawer), and this screen — the
 * one about the agent's tools — pointed at a third that had neither.
 */
export function McpToolsPane() {
  const [tools, setTools] = useState<McpTool[] | null>(null);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<McpTool | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.agentStatus().then(setStatus).catch(() => setStatus(null));
    setError(null);
    api
      .mcpTools()
      .then(setTools)
      .catch((caught) => setError(errorMessage(caught)));
  }, []);

  useEffect(load, [load]);

  /**
   * Connect / revoke the agent's key, HERE.
   *
   * These used to live in two different places — "Revoke key" hidden in the user
   * menu, "Connect" hidden inside the terminal drawer — and this screen, which is
   * literally about the agent's tools, told you to go and find them in the pivt
   * panel, where neither has ever been. Minting is also the only way to pick up a
   * permission the key didn't have when it was created, so it needs to be findable.
   */
  async function reconnect(revoke: boolean) {
    setBusy(true);
    setError(null);
    try {
      setStatus(revoke ? await api.revokeAgent() : await api.provisionAgent());
      // A fresh key means a fresh server; the cached tool list belonged to the old one.
      if (!revoke) setTools(null);
      load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  const granted = useMemo(() => new Set(status?.granted_permissions ?? []), [status]);

  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return tools ?? [];
    return (tools ?? []).filter(
      (tool) =>
        tool.name.toLowerCase().includes(needle) ||
        tool.description.toLowerCase().includes(needle)
    );
  }, [tools, filter]);

  return (
    <div className="flex min-h-0 flex-1">
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden p-5">
        <div className="text-[15px] font-semibold text-t1">MCP tools</div>
        <div className="mt-1 font-mono text-[11px] text-t3">
          {tools ? `${tools.length} tools exposed` : 'asking the server…'}
          {status?.provisioned && status.key_prefix && (
            <span className="text-t4">
              {' '}
              · key {status.key_prefix}…{' '}
              {/* No longer simply "read-only": pivt can write dashboards now. Saying
                  read-only in a security console when it isn't would be the worst
                  kind of wrong. */}
              {granted.has('dashboards:create') || granted.has('dashboards:edit') ? (
                <span className="text-warn">· can write dashboards</span>
              ) : (
                '· read-only'
              )}
            </span>
          )}
        </div>

        <div className="mt-3 flex items-center gap-2 rounded-[9px] border border-line bg-inset px-3.5 py-2.5">
          {status?.provisioned ? (
            <>
              <span className="min-w-0 flex-1 text-[11.5px] text-t3">
                Connected. pivt holds a key with {status.granted_permissions.length} scopes.
                Re-connect to mint a fresh one — a key does not gain permissions it was not
                created with.
              </span>
              <button
                onClick={() => void reconnect(false)}
                disabled={busy}
                className="shrink-0 rounded-[7px] border border-accent-line bg-accent-fill px-2.5 py-1.5 text-[11.5px] font-semibold text-accent disabled:opacity-40"
              >
                {busy ? 'Working…' : 'Re-connect (new key)'}
              </button>
              <button
                onClick={() => void reconnect(true)}
                disabled={busy}
                className="shrink-0 rounded-[7px] border border-line-strong px-2.5 py-1.5 text-[11.5px] text-danger disabled:opacity-40"
              >
                Revoke
              </button>
            </>
          ) : (
            <>
              <span className="min-w-0 flex-1 text-[11.5px] text-warn">
                The agent tools aren't connected. Connecting mints a scoped key for pivt and
                writes the MCP config that claude-code and codex read.
              </span>
              <button
                onClick={() => void reconnect(false)}
                disabled={busy}
                className="shrink-0 rounded-[7px] border border-accent-line bg-accent-fill px-2.5 py-1.5 text-[11.5px] font-semibold text-accent disabled:opacity-40"
              >
                {busy ? 'Connecting…' : 'Connect agent tools'}
              </button>
            </>
          )}
        </div>

        {status?.provisioned && !status.granted_permissions.includes('dashboards:create') && (
          <div className="mt-2 rounded-[9px] border border-warn/40 bg-warn-soft px-3.5 py-2.5 text-[11.5px] text-warn">
            This key was minted before pivt could build dashboards, so it cannot save one —
            `create_dashboard` will come back Forbidden. Re-connect to mint a key that can.
          </div>
        )}

        {error && (
          <div className="mt-3 rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[11.5px] break-words text-danger">
            {error}
          </div>
        )}

        {!tools && !error && (
          <div className="mt-4 flex items-center gap-2 text-[12px] text-t3">
            <Spinner className="text-accent" /> Starting the MCP server to ask what it
            exposes…
          </div>
        )}

        {tools && (
          <>
            <input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Filter tools…"
              className="mt-3 w-full shrink-0 rounded-[9px] border border-line-strong bg-input px-3 py-2 font-mono text-[12px] text-t1 outline-none placeholder:text-t4 focus:border-accent"
            />

            <div className="mt-3 min-h-0 flex-1 overflow-auto">
              <table className="w-full border-collapse text-left">
                <thead className="sticky top-0 bg-window">
                  <tr>
                    {['TOOL', 'WHAT IT DOES', 'NEEDS'].map((heading) => (
                      <th
                        key={heading}
                        className="border-b border-line px-2 py-1.5 text-[10.5px] font-bold tracking-[0.06em] whitespace-nowrap text-t4"
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shown.map((tool) => {
                    // Only claim "denied" where the requirement is actually known.
                    const denied = tool.permission != null && !granted.has(tool.permission);
                    return (
                      <tr
                        key={tool.name}
                        onClick={() => setSelected(tool)}
                        className={`cursor-default border-b border-line/50 hover:bg-hover ${
                          selected?.name === tool.name ? 'bg-accent-soft' : ''
                        }`}
                      >
                        <td className="px-2 py-1.5 align-top font-mono text-[11.5px] whitespace-nowrap text-accent">
                          {tool.name}
                        </td>
                        <td className="max-w-0 truncate px-2 py-1.5 align-top text-[12px] text-t2">
                          {firstLine(tool.description)}
                        </td>
                        <td className="px-2 py-1.5 align-top font-mono text-[11px] whitespace-nowrap">
                          {tool.permission ? (
                            <span className={denied ? 'text-danger' : 'text-info'}>
                              {tool.permission}
                              {denied && ' · denied'}
                            </span>
                          ) : (
                            <span className="text-t4" title="nano publishes no per-tool permission metadata">
                              unknown
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {selected && <ToolDetail tool={selected} granted={granted} />}
    </div>
  );
}

function ToolDetail({ tool, granted }: { tool: McpTool; granted: Set<string> }) {
  const denied = tool.permission != null && !granted.has(tool.permission);
  const properties = (tool.input_schema?.properties ?? {}) as Record<
    string,
    { type?: string; description?: string }
  >;
  const required = new Set((tool.input_schema?.required as string[] | undefined) ?? []);

  return (
    <div className="flex w-[380px] shrink-0 flex-col overflow-auto border-l border-line bg-panel p-4">
      <div className="font-mono text-[13px] font-semibold text-accent">{tool.name}</div>
      <div className="mt-0.5 font-mono text-[10.5px] text-t4">mcp__nano__{tool.name}</div>

      {denied && (
        <div className="mt-3 rounded-[8px] border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          pivt cannot call this. It needs <span className="font-mono">{tool.permission}</span>,
          which this app's read-only key does not hold — the call comes back Forbidden.
        </div>
      )}

      <div className="mt-3 text-[10.5px] font-bold tracking-[0.06em] text-t4">DESCRIPTION</div>
      <div className="mt-1.5 text-[12px] leading-[1.55] break-words whitespace-pre-wrap text-t2">
        {tool.description}
      </div>

      <div className="mt-4 text-[10.5px] font-bold tracking-[0.06em] text-t4">PARAMETERS</div>
      <div className="mt-1.5 space-y-2">
        {Object.entries(properties).length === 0 && (
          <div className="text-[12px] text-t4">(none)</div>
        )}
        {Object.entries(properties).map(([name, schema]) => (
          <div key={name}>
            <div className="font-mono text-[11.5px]">
              <span className="text-info">{name}</span>{' '}
              <span className="text-violet">{schema.type ?? 'any'}</span>
              {required.has(name) && <span className="text-t4"> · required</span>}
            </div>
            {schema.description && (
              <div className="mt-0.5 text-[11.5px] break-words text-t3">
                {firstLine(schema.description)}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Tool descriptions run to whole pages of guidance. The table wants a sentence. */
function firstLine(text: string): string {
  return text.split('\n')[0];
}
