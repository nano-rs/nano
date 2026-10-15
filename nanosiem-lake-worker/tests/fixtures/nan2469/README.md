NAN-2469 read-only reproduction
=============================

`claim.json`, `registry.json`, `selections.json`, and `active.txt` are the
pre-existing local captures, rechecked against the live tenant1 shard-0 cache
and feedowner SELECTs during this investigation. `claim.json` removes delivery
observation metadata; its decision vector and feed times are unchanged. The
active file contains the three pointer contents concatenated without newlines,
as they were returned by cat. Selections are the signed manifest array.

Confirmed refusal: the baseline registry rows are `inactive`, while publication
is enabled, redistribution approved, and an active revision exists. The
`bronze_platform_pin_object` CASE in 9001370 tests `f.status<>'ready'` and freezes
`unknown/unavailable` in the object pin. `bronze_platform_claim` copies that
vector. Rust short circuits before looking up even an available matching MMDB.
Publisher activation advanced active_revision without advancing registry status.
A rev-1 decision remaining rev 1 after a refresh is expected immutable replay.

9001380 repairs eligible published baseline registry rows and the publisher
transition for future publications. Explicit `unavailable`, unapproved terms,
premium consent, deny checks, and existing durable object/UID decisions are
preserved. Refusal details are separate from the canonical admission vector.
This migration has NOT been applied to the live database.

Local reproduction:

* `cargo test -p nanosiem-lake-worker -j 8 --features enterprise --lib platform_stamping`
* Run the compiled test executable with `--exact
  platform_stamping::tests::real_artifact_live_bronze_admission --ignored
  --nocapture`, setting `NANO_REAL_CACHE_ROOT` to a LOCAL directory containing
  the three selected artifact files, the captured Tor revision-1 artifact and
  `tor-rev1-manifest.json`, `.active` files, a `gate` file, the complete
  `selections.json` config, and `keys.json` with the separately obtained public
  trust ring. The files must retain their signed SHA-256 and be mode 0400.
  This run used `target/nan2469-live`; large payloads are not checked in.
* In an empty disposable LOCAL database named `nan2469_*`, run
  `psql -X -v ON_ERROR_STOP=1 -f migration-smoke.sql`. The test uses minimal
  authority tables and a stub publication function to validate migration SQL,
  pre/post pin behavior, preserved old pins and refusal details. It does not
  substitute for a full migration/ACL integration suite. `pin-before.sql` is
  the four-argument function from 9001370.

The real-artifact test runs actual Runtime::attach and bronze admission while
cold validation is in progress, bounds each admission and the readiness wait,
checks shared inode leases with a conflicting flock attempt, reproduces the
original pin refusal with loaded artifacts, then exercises shadow and live
using the same claim shape with the NEW-publication readiness outcome. Both
151.101.3.5 and 104.4.24.66 must match IPinfo. No live authority function or live
writer is called by the test.

The reported historical 15-minute stall is not proven to originate in a
specific process stack. The read-only snapshot offers no stack trace of that
wait. The synchronous channel could previously wait forever; a blocked-worker
regression now verifies bounded response and queue handling. Artifact loading
is moved off admission, and the real-artifact test verifies continuous progress.
The real Tor revision-1 claim and signed manifest also exercise retention
against the live revision-2 active pointer through four refreshes.
Two ready generations survive repeated refreshes of the same selection. An
actual third generation rotates the oldest runtime reference, but admission
snapshots keep their existing handles and readiness sets. The third generation
waits under the existing memory cap until those older leases drain.
