// SPDX-License-Identifier: AGPL-3.0-or-later

interface LateralEmptyProps {
  reason: 'no-seed' | 'no-edges';
}

export function LateralEmpty({ reason }: LateralEmptyProps) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center px-6 py-10 text-center gap-3">
      <svg
        viewBox="0 0 64 64"
        className="w-10 h-10 text-muted-foreground/60"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <circle cx="12" cy="12" r="4" />
        <circle cx="52" cy="52" r="4" />
        <circle cx="52" cy="12" r="4" />
        <circle cx="32" cy="32" r="4" />
        <path d="M16 12h32M52 16v32M16 16l32 32M36 32l12 16" />
      </svg>

      {reason === 'no-seed' ? (
        <>
          <div className="font-mono text-[12px] text-foreground">
            No seed resolved for <span className="text-primary">| lateral</span>
          </div>
          <div className="font-mono text-[10.5px] text-muted-foreground/80 max-w-md leading-relaxed">
            Add a host, user, or IP before the pipe — e.g.{' '}
            <span className="text-foreground">src_host=WIN-HR11 | lateral</span>, or supply{' '}
            <span className="text-foreground">| lateral seed=user entity=user</span>.
          </div>
        </>
      ) : (
        <>
          <div className="font-mono text-[12px] text-foreground">No lateral movement edges</div>
          <div className="font-mono text-[10.5px] text-muted-foreground/80 max-w-md leading-relaxed">
            The seed entity didn't reach any peers in the selected window. Broaden the time range,
            relax the method set, or pivot from a different seed.
          </div>
        </>
      )}
    </div>
  );
}
