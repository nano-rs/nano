# Vector-native listener TLS files (NAN-5515)

Mounted read-only into Vector at `/etc/nano/vector-native`. The Vector-native
listener (port 6000) is mutual TLS only; `install.sh` and `scripts/nano upgrade`
write these files here:

- `server.crt`, `server.key` (0600): the listener certificate (single host; a
  role-split ingest host uses the cluster's private TLS certificate instead)
- `client-ca.crt`: the bundle of per-sender anchors a sender certificate must
  chain to (one anchor per sender, so revoking one sender removes only its anchor)
- `.sans`: the names and addresses in `server.crt`

No CA key is here: the listener CA and the anchor keys live in
`.nano-pki/vector-native/` (mode 0700), are never mounted into a container and
are included in `scripts/nano backup`. Issue, renew and revoke senders with
`scripts/nano vector-client-cert`. Generated files are not tracked by git.
