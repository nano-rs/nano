"""Real-cloud test resource helpers (create / publish / inspect / tear down).

Every resource is named `nano-e2e-<runid>-...` (see nano_e2e.runid.cloud_name)
and carries a creation stamp where the provider supports labels/tags, so
`scripts/e2e.sh gc --cloud` can delete stragglers by prefix and age.
"""
