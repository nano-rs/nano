"""Zero-clicks suite (NAN-5763): data flows for the whole session."""

from collections.abc import Iterator

import pytest

from nano_e2e import zero_clicks as zc
from nano_e2e.stack import Stack


@pytest.fixture(scope="session", autouse=True)
def data_flowing(stack: Stack) -> Iterator[zc.DataFlow]:
    yield from zc.data_flow_fixture(stack)
