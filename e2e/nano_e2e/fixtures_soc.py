"""`soc`: the deep-workflow OCSF dataset (nano_e2e.soc_seed), seeded once per
session and visible through the search API before any scenario uses it
(NAN-5684). Import it into a conftest next to the UI fixtures."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest

from nano_e2e import schema, soc_seed
from nano_e2e.client import Journal, Nano
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


def soc_count(nano: Nano, data: soc_seed.SocData, query: str) -> int:
    """`total_count` of a query over the seeded window."""
    return int(nano.search(query, limit=1, time_range=data.window())["total_count"])


@pytest.fixture(scope="session")
def soc(stack: Stack) -> Iterator[soc_seed.SocData]:
    if not schema.is_ocsf():
        pytest.skip("the deep workflows seed OCSF events; this stack runs the legacy udm profile")
    if stack.target == "existing":
        pytest.skip("the deep workflows seed through the stack's own ClickHouse (a throwaway stack only)")
    tag = hashlib.sha256(stack.run_id.encode()).hexdigest()[:8]
    anchor = soc_seed.existing_anchor(stack, tag)
    data, rows = soc_seed.build(tag, now=anchor)
    if anchor is None:
        soc_seed.insert(stack, rows)
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    try:
        eventually(
            lambda: {s: soc_count(nano, data, f'source_type="{s}"') for s in data.sources},
            timeout=120,
            interval=3,
            desc=f"the {data.total} seeded OCSF events searchable per source type",
            ok=lambda got: got == data.by_source,
        )
        yield data
    finally:
        nano.close()
