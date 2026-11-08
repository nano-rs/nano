"""NAN-4961 asks that Add source > credentials > preview shows real vendor
events. The ClickHouse product has no preview step for pull feeds (no API
route, no UI; nano-connector's preview.rs is unwired): product gap NAN-4964.
An explicit placeholder so the gap stays visible in every connectors run."""

from __future__ import annotations

import pytest


def test_pull_feed_preview_shows_real_events() -> None:
    pytest.skip("pull feeds have no preview step yet: NAN-4964 (scenario lands with it)")
