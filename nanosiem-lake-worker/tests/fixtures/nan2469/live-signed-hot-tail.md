# Durable-runner signed-envelope regression

Captured read-only on 2026-09-21 with `kubectl exec ... -c query -- cat` from
`/var/lib/nano-lake/generations/event-config-archive/hot-tails/006a717068c4fbef8673a16f421d7ad85cc24d4ec5725f2e00450f4677763967.json`
in the user-designated tenant1 query deployment. The original bytes' SHA-256
matched that filename. This is a representative archived document, not a claim
that this particular digest was the failing job's admission pin.

`live-signed-hot-tail.redacted.json` preserves the envelope, all 32 objects,
field presence, read schema, available paths, object sizes, row counts and tier
flags. Tenant, table, bucket/object locations, snapshot identities, tail ID,
object digests, versions, ETags, timestamps and HMAC were replaced with synthetic
values. No key material was read. Redaction invalidates the HMAC and tail ID;
this fixture tests the accounting reader, not signature verification. The
round-trip test separately calls the production signer with a synthetic key and
checks both accounting and signature verification, including tamper rejection.

The staged-tail publisher calls `generation::sign_hot_tail_manifest`, which
serializes `SignedHotTailManifest { manifest, hmac_sha256 }`. The query worker
archives these exact bytes by SHA-256. The runner incorrectly tried to decode
those bytes as the inner `HotTailManifest` while counting objects and bytes,
before launching the child. The resulting serde error propagated out of the
claimed attempt and terminated the runner.

The accounting reader now projects `manifest.objects[].size_bytes` from that
envelope after checking the admission digest. It tolerates additive envelope,
manifest and object fields. It does not authorize object reads or substitute
for the child's existing HMAC, schema, tenant and object validation. The full
security reader intentionally retains `deny_unknown_fields`: its HMAC is
checked against a reserialization of the typed payload, so silently dropping
unknown fields there would change the authenticated contract.
