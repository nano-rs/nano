"""nano-e2e: black-box scenario harness for the nano ClickHouse product (NAN-4920).

Everything here talks to a running stack over its public interfaces (HTTP API,
Vector ingest endpoints, the runner's `svc` seam for restarts). Nothing imports
product code. The stack is described by the `stack.env` that `scripts/e2e.sh up`
writes; see `nano_e2e.stack.Stack`.
"""
