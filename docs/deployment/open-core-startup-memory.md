# Open-core startup memory sizing

`config/lean-startup-memory.json` is shared by the compiled initializer and
installer preflight. A service floor is
`ceil_MiB(max(guard, 1.25 × measured_peak))`. For the 1.0.17 burst measurements,
peak is the larger of cgroup `memory.peak` and process `VmHWM`. A paced startup
capture alone did not size Vector for a burst, and reading an already cached
feed bundle hid its charged file pages.

A nominal **8 GiB VM** remains supported. Up to **512 MiB** may be reserved by
the kernel: the Docker-visible minimum is **7,680 MiB**, or a higher MiB-rounded
threshold if the service and minimum cell budgets require it. The tolerance
never increases the RAM used by sizing: every budget uses actual `MemTotal`.
Compose plus the cell must fit within **95%** of that value, leaving 5% outside
containers. Both validated small VMs report about 7,934 MiB (7,933.6 MiB before
rounding). Unsupported upgrades stop before changing the checkout or config.

The retired five-value `NANO_LAKE_*` query-memory plan was unused by the lean
Compose topology. Its second 12 GiB gate and example overrides have been removed.
Old values in an upgraded `.env` do not control these budgets.

## Burst floors

Disposable GCP Ubuntu 24.04 hosts, four CPUs, digest-pinned 1.0.16 images; the
burst is 10,000 HEC events in 500-event batches with no sender pacing, plus five
JSON HTTP events. These are short-burst measurements, not sustained throughput
certification.

| Service | Measured peak bytes | Guard MiB | Derived floor MiB |
|---|---:|---:|---:|
| Vector | 253,726,720 (peak RSS; cgroup peak 196,648,960) | 0 | 303 |
| Platform feed import | 107,974,656 (cold-cache cgroup peak) | 0 | 129 |
| HEC gateway | 19,492,864 (RSS; cgroup peak 8,105,984) | 128 | 128 |

The public feed payload is 101,289,793 bytes, SHA-256
`0055e0790714ac2f1e264348ed295f579ae03247cf0b1d18f3c4111377df025d`.
The cold measurement drops host caches only on the disposable validation VM,
then runs the actual `lake_platform_feeds import` command without a cap.

The gateway guard covers one 50 MiB request body and runtime overhead. It
allows sixteen header/authentication connections, authenticates before reading
an upload, and admits only one large ingest body at a time. Busy senders receive
a retryable error. It closes keep-alive connections after each request and bounds
header reads and total delivery time. ACK queries have a
128 KiB body limit and at most 1,024 IDs. Receipts expire after ten minutes and
are capped at 8,192 entries. Eviction or restart can cause a safe retry.

## Allocation

Compose receives `max(45% of host RAM, sum of active service minima)`. Landing
gets whole CPU/memory-fitted lanes after sibling minima are paid: 1,152 MiB for
one, 2,240 for two, and 4,416 for four. Surplus is shared by existing weights.
The cell receives the rest of the 95% envelope. Its 20 EPS minimum remains
2,061 MiB. Small cells choose the highest fitting integer EPS from
`TenantBudget::from_eps`; reported EPS is a memory planning figure.

| Host GiB / CPUs | Ingest path | Compose MiB | Cell MiB | Planning EPS |
|---|---|---:|---:|---:|
| 8 / 4 | vector | 4,958 | 2,824 | 57 |
| 8 / 4 | tenzir | 4,015 | 3,767 | 97 |
| 16 / 8 | vector | 7,361 | 8,192 | 630 |
| 16 / 8 | tenzir | 7,371 | 8,192 | 630 |
| 32 / 16 | vector | 14,738 | 16,384 | 1100 |
| 32 / 16 | tenzir | 14,736 | 16,384 | 1100 |
| 64 / 32 | vector | 29,485 | 32,768 | 3970 |
| 64 / 32 | tenzir | 29,482 | 32,768 | 3970 |
| 128 / 64 | vector | 58,974 | 65,536 | 9380 |
| 128 / 64 | tenzir | 58,975 | 65,536 | 9380 |

At exactly 8 GiB, Vector Compose uses 4,958 MiB and the cell 2,824 MiB:
7,782 MiB total, within 7,782.4 MiB. The larger Vector/feed floors and the HEC
gateway are paid before selecting the cell rate. Tenzir-direct excludes Vector,
its connector runner, and the gateway. No operator sizing knob was added.

Every ordinary install/upgrade re-reads Docker-visible host RAM and CPU count,
re-renders placement and `compose.resources.json`, and applies the new limits.
A grown host receives a larger plan while retaining its identity and data.

## Durable ingestion

Vector HEC's initial 200 allocates an `ackId`; it is not a sink receipt. Hosted
forwarders already poll `/services/collector/ack` until the Bronze PUT is
confirmed. Open-core now publishes port 8088 through a small gateway in the
existing cell image that performs that same wait before returning success.
Vector's HEC listener stays internal. API and job connector HEC delivery uses
the gateway as well. It forwards the sender credential, never an admin token.

Polling clients receive a separate receipt bound to their credential and
request channel (header or query parameter). Reading that receipt revalidates
the credential with Vector, including revocation. A restart, missing receipt,
upstream failure, or a 25-second deadline produces a retryable error. Timeouts
may produce duplicates on retry; delivery is at least once.

The HTTP log source now enables end-to-end acknowledgements too. With the lake
sink's existing blocking memory buffer, success follows the completed Bronze
object PUT. Search visibility may follow later during landing conversion.
Acknowledged events survive a Vector crash because Bronze is already durable.

The baseline volatile HEC front door submitted all 10,005 events in 1.0 second;
all were searchable 10.8 seconds later on the 16 GiB host. Durable submission
including the five JSON requests took 27–28 seconds. That latency includes
actual storage confirmation instead of acknowledgement of a volatile queue.
Final validation covered two 8 GiB hosts, a fresh 16 GiB host, and a 16 GiB
upgrade from 1.0.16. All 40,020 acknowledged events became searchable, with
zero OOM kills or restarts during each host's 20-minute final window.
