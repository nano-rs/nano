"""UI suite (NAN-4937): the real web UI on the probe stack, driven by
the puppeteer driver, same stack and admin as the API scenarios. Fixtures live in
nano_e2e.fixtures_ui (shared with tests/enterprise/ui)."""

from __future__ import annotations

from nano_e2e.fixtures_cloud import (  # noqa: F401 - fixtures
    aws_creds,
    azure_hub,
    gcp_pubsub,
    s3_bucket,
    sqs_queue,
)
from nano_e2e.fixtures_ui import anon_page, page, ui, web  # noqa: F401 - fixtures
