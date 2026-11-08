# Marketplace UI scenarios (NAN-4946)

Puppeteer-core scenarios for the inventory Marketplace, run against a throwaway
`scripts/e2e.sh up --app native` stack and a built SPA. To be folded into the
NAN-4937 UI driver once it lands.

```sh
scripts/e2e.sh up --app native --edition enterprise     # or --edition open
set -a; . target/e2e/<run>/stack.env; set +a
(cd nanosiem-web && npm run build)
node nanosiem-web/tests/e2e/marketplace/serve.mjs nanosiem-web/dist 18946 <E2E_API_PORT> <E2E_SEARCH_PORT> &
B=http://127.0.0.1:18946
node nanosiem-web/tests/e2e/marketplace/browse.mjs    $B ent   # browse, chips, search, 1440/2560 shots
node nanosiem-web/tests/e2e/marketplace/enrich.mjs    $B ent   # install (credentials), toggle, configure, uninstall
node nanosiem-web/tests/e2e/marketplace/collector.mjs $B ent   # pull collector against okta-mock.mjs (below)
node nanosiem-web/tests/e2e/marketplace/rest.mjs      $B ent   # cloud pull deep link, first-party catalogs only, TI provider
node nanosiem-web/tests/e2e/marketplace/open.mjs      $B open  # open edition: stubs, no dead buttons
```

The collector scenario needs a deployed HEC log source for lane `okta`, the
mock vendor and the connector runner in loopback test mode:

```sh
node nanosiem-web/tests/e2e/marketplace/okta-mock.mjs 18990 &
NANO_PLATFORM_INGEST_TOKEN=... CONNECTOR_TEST_MODE=1 CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:18990 \
  CONNECTOR_HEC_URL=$NANOSIEM_HEC_URL CONNECTOR_HEC_REQUIRE_ACK=0 target/debug/nano-connector-runner
```

Screenshots go to `$E2E_SHOTS_DIR` (default: a fresh temp dir).
