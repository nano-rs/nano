"""Delete cloud stragglers named nano-e2e-* older than N hours (scripts/e2e.sh gc --cloud).

Only resources whose name starts with the e2e prefix are ever considered, and
only past the age cutoff, so a concurrent run's live resources are safe.
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta

from nano_e2e import creds
from nano_e2e.cloud import aws, azure, gcp
from nano_e2e.runid import MIN_GC_HOURS


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--older-than-hours", type=int, default=6)
    ap.add_argument("--exclude-run", action="append", default=[], help="active run id (never swept)")
    args = ap.parse_args()
    if args.older_than_hours < MIN_GC_HOURS:
        ap.error(f"--older-than-hours must be >= {MIN_GC_HOURS}")
    age = timedelta(hours=args.older_than_hours)
    failed = False
    for name, load, sweep in (
        ("aws", creds.aws, aws.gc),
        ("gcp", creds.gcp, gcp.gc),
        ("azure", creds.azure, azure.gc),
    ):
        c, reason = load()
        if c is None:
            print(f"  {name}: skipped ({reason})")
            continue
        try:
            removed = sweep(c, age, frozenset(args.exclude_run))  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001 - report and continue with the other clouds
            print(f"  {name}: FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            failed = True
            continue
        print(f"  {name}: removed {len(removed)}")
        for r in removed:
            print(f"    - {r}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
