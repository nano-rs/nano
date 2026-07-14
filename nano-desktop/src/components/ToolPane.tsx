import type { Tab } from '../state/tabs';

/**
 * The body of a `tool` tab: something pivt did that isn't an nPL search, kept as
 * an inspectable record rather than dropped on the floor.
 *
 * `search_sql` is the common case. It is deliberately NOT re-run here: the
 * product's search path takes nPL, not SQL, so a tab that offered to "run" this
 * would be running something else. What the analyst gets instead is the exact
 * call pivt made and the exact answer it got back — which is what an audit of an
 * agent's work actually needs.
 *
 * Everything rendered here is agent output, and pivt's context is log content the
 * attacker wrote. It is therefore rendered as TEXT, always.
 */
export function ToolPane({ tab }: { tab: Tab }) {
  const tool = tab.tool;
  if (!tool) return null;

  const args = Object.entries(tool.input).filter(([, value]) => value !== null && value !== '');

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-auto p-4">
      <div className="flex items-center gap-2">
        <span className={`text-[12px] ${tool.failed ? 'text-danger' : 'text-accent'}`}>⏺</span>
        <span className="font-mono text-[13px] font-semibold text-t1">{tool.name}</span>
        <span className="rounded-[20px] border border-accent-line bg-accent-soft px-2 py-0.5 font-mono text-[10.5px] text-accent">
          ✳ pivt
        </span>
        {tool.failed && (
          <span className="rounded-[20px] border border-danger/40 bg-danger-soft px-2 py-0.5 font-mono text-[10.5px] text-danger">
            failed
          </span>
        )}
      </div>

      <div className="mt-1.5 text-[11.5px] text-t4">
        pivt ran this against nano with its own read-only key. This is the record of the
        call, not a live query.
      </div>

      <div className="mt-4 text-[10.5px] font-bold tracking-[0.06em] text-t4">ARGUMENTS</div>
      <div className="mt-1.5 space-y-1.5 rounded-[8px] border border-line-strong bg-inset p-3">
        {args.length === 0 && <div className="text-[12px] text-t4">(none)</div>}
        {args.map(([key, value]) => (
          <div key={key} className="min-w-0">
            <div className="font-mono text-[11px] text-info">{key}</div>
            <div className="font-mono text-[11.5px] break-all whitespace-pre-wrap text-t2">
              {typeof value === 'string' ? value : JSON.stringify(value)}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-4 text-[10.5px] font-bold tracking-[0.06em] text-t4">RESULT</div>
      <div className="mt-1.5 min-h-0 flex-1 rounded-[8px] border border-line-strong bg-inset p-3">
        {tool.result ? (
          <pre className="font-mono text-[11.5px] leading-[1.5] break-all whitespace-pre-wrap text-t2">
            {tool.result}
          </pre>
        ) : (
          <div className="text-[12px] text-t4">
            {tool.failed ? 'The call failed and returned nothing.' : 'Waiting for pivt…'}
          </div>
        )}
      </div>
    </div>
  );
}
