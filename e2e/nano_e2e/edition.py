"""What the open build shows in place of an enterprise surface (NAN-5747).

The e2e edition scenarios assert these panels, so their copy lives here once,
next to the web source file that renders it. `python3 -I
e2e/nano_e2e/edition.py` (stdlib only; the release preflight runs it) fails
when a marker is no longer in its source, so a copy change in the product
breaks the preflight in seconds instead of about 20 open-edition e2e tests
at RC time. That happened once: the v2 license panel (#9388) replaced the
"paid plans" placeholder on capability-gated routes, and the open lane kept
asserting the old copy for more than a week.

Three panels, by route shape (nanosiem-web/src/App.tsx):

- a route with a `capability` gate (`<PermissionRoute capability=...>`)
  renders `LicensedFeatureUnavailable`: "<Feature> is not licensed", the
  Feature name from `lib/capability-labels.ts`;
- a route whose page is an `@/enterprise` stub with no capability gate
  (`/settings/license`) renders the open-build placeholder;
- `SsoRouteGate` keeps its own "not available" notice, but on open the `sso`
  capability gate in front of it answers first.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

WEB_SRC = Path(__file__).resolve().parents[2] / "nanosiem-web" / "src"

UNLICENSED_TESTID = "licensed-feature-unavailable"
UNLICENSED = {"testid": UNLICENSED_TESTID}
UNLICENSED_COPY = "Open/core features, ingest, search, and stored data remain available"
PLACEHOLDER = "Available in nano paid plans"
SSO_PANEL = "Single sign-on is not available"

# (marker, web source file that must contain it). Whitespace is normalized
# before matching: JSX wraps copy across lines, the browser renders it as one.
MARKERS: tuple[tuple[str, str], ...] = (
    (f'data-testid="{UNLICENSED_TESTID}"', "components/LicensedFeatureUnavailable.tsx"),
    ("{feature} is not licensed", "components/LicensedFeatureUnavailable.tsx"),
    (UNLICENSED_COPY, "components/LicensedFeatureUnavailable.tsx"),
    (PLACEHOLDER, "enterprise-stubs/_placeholder.tsx"),
    (SSO_PANEL, "pages/Settings/SsoRouteGate.tsx"),
    # The Feature names the scenarios wait for.
    ("cases: 'Cases',", "lib/capability-labels.ts"),
    ("sso: 'Single sign-on',", "lib/capability-labels.ts"),
)


def unlicensed_title(feature: str) -> str:
    """The panel heading for a capability's label (`lib/capability-labels.ts`)."""
    return f"{feature} is not licensed"


def wait_unlicensed(page: Any, feature: str, timeout_ms: int = 30_000) -> None:
    """Wait for the v2 license panel naming `feature`."""
    page.wait_for(UNLICENSED, timeout_ms=timeout_ms)
    page.wait_text(unlicensed_title(feature), exact=True)


def missing_markers(web_src: Path = WEB_SRC) -> list[str]:
    out = []
    for marker, rel in MARKERS:
        path = web_src / rel
        text = " ".join(path.read_text(encoding="utf-8").split()) if path.is_file() else ""
        if " ".join(marker.split()) not in text:
            out.append(f"nanosiem-web/src/{rel} no longer contains {marker!r}")
    return out


def main() -> int:
    missing = missing_markers()
    if missing:
        print("open-edition e2e markers drifted from the web UI. Update e2e/nano_e2e/edition.py and the "
              "tests that use it, then run `scripts/e2e.sh run ui personas --edition open`:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        return 1
    print(f"ok open-edition e2e markers match the web UI ({len(MARKERS)} markers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
