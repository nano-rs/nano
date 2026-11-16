# Single node (Docker Compose)

One Linux host runs the whole stack from the **enterprise compose bundle**.
Never use the open-source one-line installer (`get.nano.rs`) for a Self-run
deployment. It installs the open edition, and an install never switches
edition later.

Conventions below: `H` is `user@host`, `SSH="ssh -o BatchMode=yes"`, the
install directory is `~/nano` for the SSH user, and `V` is the release (for
example `2.0.30`). Before each step, show the operator the commands and ask.

**2.0.29 and earlier:** add `NANO_IMAGES_LOCK=images.enterprise.customer.lock`
to every `./install.sh` command below and do Step 3. From 2.0.30 the installer
picks that lock itself and needs neither.

What the 2.0.30+ installer does on its own (the commands below rely on it):

- **Host size first.** Before any prompt it refuses a host under 2 vCPU, 8 GB
  RAM (16 GB with the enrichment feeds on, the default) or 40 GB free on
  Docker's data filesystem, and needs 4 vCPU when app and ClickHouse share the
  host with Keeper or Tenzir (the `ocsf+tenzir` profile). Fix the host;
  `NANO_SKIP_HOST_MINIMUMS=1` installs anyway, unsupported, so use it only on
  a lab the operator names as one.
- **Registry login.** With an online license in `.env` (Step 7) it fetches a
  one-hour pull credential from the license API right before the pull and
  uses it from a private temporary `DOCKER_CONFIG`; `~/.docker` is never
  touched. Offline and air-gapped licenses never call the API: load the image
  bundle (`scripts/nano bundle load`) or do Step 3 first.
- **Prompts.** On a terminal it asks its questions, then shows a review
  screen (Enter installs, a number changes that answer, `q` quits with nothing
  written; `back` re-asks the previous question). Over `ssh` without `-t`
  there is no terminal, so the environment variables below are the answers.
- **Upgrade question.** A re-run that would move the install to another
  release asks `Upgrade to X now?` on a terminal; declining exits 3 (no) or 4
  (no answer) with nothing changed. `NANO_CONFIRM_UPGRADE=1` answers yes and is
  the reliable unattended form (the terminal default changes in 2.0.31).
- **Failures** print the full ClickHouse error and the logs of every failing
  service. Quote them to the operator before you retry anything.

## Step 0: fetch and verify the bundle locally

With the operator's enrollment values file (downloads only; nothing on the host
changes):

The operator downloads three files from the deployment's page in app.nano.rs
(**1 · Get the installer**; only an owner or admin can, and no API fetches
them with the license token): `nano-compose-enterprise-$V.tar.gz`, `.sha256`
and `.sha256.sig`. Verify the signature, then the checksum, with nano's
release key from the public Self-run install guide (never from inside the
archive). The exact commands and the key are in
[cloud-vm.md](cloud-vm.md#6-license-download-verify-install), step 2:

```bash
bash scripts/fetch-bundle.sh --enrollment ./nano-deploy-work/enrollment.env \
  --out ./nano-deploy-work/bundle --version $V
cd ./nano-deploy-work/bundle
tar -tzf nano-compose-enterprise-$V.tar.gz | head -3   # top directory: nano-$V/
```

Continue only after it prints `VERIFIED nano-compose-enterprise-$V.tar.gz`. It
checks the pinned release key, the signature on the `.sha256` and the bundle
against that signed line, and keeps nothing on a failure. If the operator gave
you files instead, run the same checks (Self-run docs, "Get the bundle"), not
`sha256sum -c`.

## Step 1: host prerequisites (only if preflight failed on them)

Propose the minimum fix for each `FAIL` and run it only after approval. On
Debian or Ubuntu, install Docker Engine and the Compose plugin from Docker's
official apt repository (docs.docker.com/engine/install), the tested path. A
distribution package (Ubuntu's `docker.io` with `docker-compose-v2`) is fine
when it is Docker 24 or newer with the Compose v2 plugin; preflight checks
the versions. Then:

```bash
sudo apt-get install -y git curl openssl python3 tar iproute2
sudo usermod -aG docker "$USER"     # then open a NEW SSH session
```

Re-run preflight until it shows zero `FAIL`.

## Step 2: stage the bundle (mutating)

```bash
scp -p nano-compose-enterprise-$V.tar.gz $H:~/
$SSH $H 'set -e; test ! -e ~/nano || { echo "~/nano exists: this is an upgrade, see upgrade.md"; exit 3; }
  tar -xzf ~/nano-compose-enterprise-'$V'.tar.gz -C ~ && mv ~/nano-'$V' ~/nano
  cat ~/nano/.nano-edition; grep "^# Release:" ~/nano/images.enterprise.lock'
```

Expect `enterprise` and `# Release: v$V`. Keep the whole extracted directory:
the compose files, scripts and image lock are one release artifact.

## Step 3: registry login (2.0.29 and earlier, or an offline license; mutating, secret)

Skip this step for 2.0.30 or later with an online license: the installer logs
in itself (see above). The registry host is the prefix of the image lines in `images.enterprise.customer.lock`
(for example `us-central1-docker.pkg.dev`). Get a one-hour credential with the
license values just before this step (`bash scripts/fetch-bundle.sh --enrollment
./nano-deploy-work/enrollment.env --version $V --registry-cred
./nano-deploy-work/registry.cred`, user `oauth2accesstoken`), or use the
operator's credential file. Copy it and log in from stdin:

```bash
scp -p "$REGISTRY_CRED_FILE" $H:~/.nano-registry-cred
$SSH $H 'chmod 600 ~/.nano-registry-cred && docker login REGISTRY_HOST -u "REGISTRY_USER" --password-stdin < ~/.nano-registry-cred; rm -f ~/.nano-registry-cred'
```

Log in as the user that runs `install.sh`, never with `sudo` (root's login is
not that user's). If the operator has already logged in on the host, skip this
step. Confirm with `docker pull` of one image from the lock, or let the install
step report it.

## Step 4: admin credential file (mutating, secret stays on host)

```bash
$SSH $H "bash -s -- --email ADMIN_EMAIL --name 'ADMIN NAME'" < scripts/admin-credentials.sh
```

## Step 5: check-only (read-only)

```bash
$SSH $H 'cd ~/nano && NANO_CHECK_ONLY=1 ./install.sh'
```

It prints the edition, release and image source and writes nothing. It must
say `edition=enterprise`, the release you expect and (2.0.30+)
`lock=images.enterprise.customer.lock`. It stops before the host-size check,
so an undersized host first fails at Step 6.

## Step 6: prepare without starting (mutating)

`BASE_URL` is the public URL users will open. Use `https://` for anything
beyond a lab. With `http://` the installer turns on dev mode (cookies without
`Secure`).

```bash
$SSH $H 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_BASE_URL=BASE_URL NANO_SCHEMA_PROFILE=ocsf NANO_PREPARE_ONLY=1 ./install.sh'
```

This writes `~/nano/.env` (mode `0600`) with generated secrets. It does not
pull or start the application. The schema profile is fixed at first install.
`ocsf` is the default for new installs; ask before choosing anything else.

## Step 7: enrollment (mutating, secret)

```bash
scp -p "$ENROLLMENT_FILE" $H:.nano-enrollment.env
# Arguments INSIDE the single quotes: an unquoted ~ expands on this workstation.
$SSH $H 'bash -s -- --env "$HOME/nano/.env" --from "$HOME/.nano-enrollment.env"' < scripts/apply-enrollment.sh
```

If the operator has no enrollment yet (the trial is still pending), say that
the install will run unlicensed until the values are added. Ask whether to continue. To add them later, run this
step, then Step 8 again.

## Optional: storage tiering (mutating, secret)

Enterprise edition only (the open edition refuses `NANO_TIERING=on`). Off by
default. Only if the operator wants older data in object storage (intake
question 9). An interactive install asks `Enable cold storage tiering? [y/N]`
itself; for an unattended Step 8, generate the flags with `plan.py ...
--tiering-provider <s3|s3-compatible|gcs|azure> --tiering-bucket ...` (its
`tiering.install_flags` and `tiering.secret_env`) or write them by hand;
[operate.md](operate.md#storage-tiering) lists the keys. If the operator
declines, pass `--tiering off` so the prompt is not shown.
The secrets never pass through the chat or the workstation: the operator types
them into a host-side file, which Step 8 sources like the admin credentials.

```bash
# Operator, in their own terminal (values are typed, not echoed into chat):
ssh $H 'umask 077 && cat > ~/.nano-tiering.env'
#   NANO_TIERING_ACCESS_KEY_ID=...
#   NANO_TIERING_SECRET_ACCESS_KEY=...      (azure: NANO_TIERING_AZURE_ACCOUNT_KEY=...)
#   then Ctrl-D
```

Add `set -a && . ~/.nano-tiering.env && set +a &&` before the Step 8 command
and append the flags (`./install.sh --tiering s3 --tiering-bucket ...
--tiering-region ...`). The installer validates them, writes them to `.env`, checks the
store from the host (a warning, not a stop) and renders the ClickHouse policy.
Delete `~/.nano-tiering.env` after Step 8. Check with
`$SSH $H 'cd ~/nano && scripts/nano tiering status && scripts/nano tiering test'`.

## Step 8: install and start (mutating)

```bash
$SSH $H 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_BASE_URL=BASE_URL ./install.sh'
```

The admin variables are needed again: the prepared `.env` makes this a re-run,
and the admin is created only when setup is still uninitialized. The
installer logs in to the registry with the license (2.0.30+), pulls the images
listed in `images.enterprise.customer.lock`, verifies every digest against `images.enterprise.lock`
(it refuses to start on a mismatch), runs migrations, waits for health and
creates the admin. A re-run is safe: it keeps `.env`, secrets and data.

The final output includes an ingest-token hint and sample sender commands. Do
not paste tokens from it into the chat.

## Step 9: public TLS

Pick the method from the intake.

- **Load balancer or reverse proxy in front** (recommended): terminate TLS
  there and forward to the host's port 80. Keep `https://` as the base URL.
  Restrict port 80 on the host to the proxy's address.
- **Bundled nginx (TLS overlay)**: copy the certificate chain and key to
  `~/nano/config/nginx/ssl/fullchain.pem` and `privkey.pem` (key mode
  `0600`). Then re-run the installer with the overlay:

  ```bash
  $SSH $H 'cd ~/nano && grep -q "^NANO_COMPOSE_OVERLAYS=" .env || echo "NANO_COMPOSE_OVERLAYS=docker-compose.tls.yml" >> .env
    set -a && . ~/.nano-admin-credentials && set +a &&
    NANO_COMPOSE_OVERLAYS=docker-compose.tls.yml NANO_BASE_URL=BASE_URL ./install.sh'
  ```

  From 2.0.30 the installer checks the certificate before any prompt
  (present, readable, unencrypted, key matching, not expired; a warning inside
  14 days). A fresh install refuses a bad one; a re-run of an existing install
  only warns, so read the output. It records the overlay in `.env` itself, and
  a re-run detects an overlay the running stack uses that `.env` lacks, so
  HTTPS stays on across re-runs and `scripts/nano upgrade`. The `grep ... ||
  echo` above does the same for 2.0.29 and earlier, which otherwise drop to
  plain HTTP on any run without the overlay. With 2.0.30+ you may stage the
  certificate before Step 8 and pass the overlay on the first install; with
  2.0.29 and earlier keep this order. Never set `NANO_SKIP_TLS_PREFLIGHT=1` to
  get past a certificate error: fix the files. See
  [known-issues.md](known-issues.md).

## Step 10: firewall (operator-owned)

The installer never changes the firewall. Propose rules and apply them only if
the operator asks you to. Allow 443 (and 80 for redirects) from users, and
only the ingest ports in use from the log sources. HTTP ingest goes through
nginx on 80/443 at `/ingest`; Vector's 8080 and the HEC port 8088 are
token-gated. Vector native 6000 is mutual TLS only and, from 2.0.30, listens
on every interface (`NANO_VECTOR_NATIVE_BIND_ADDRESS` in `.env` narrows it);
allow it only from the senders that use it. Keep 4317, 4318 and 24224 on
loopback (the default).
Docker-published ports bypass UFW's `INPUT` rules: enforce source limits in
the `DOCKER-USER` chain, as described in [multi-node-ha.md](multi-node-ha.md#firewall).

## Step 11: Vector-native senders (only if the operator uses them)

Each sender of Vector's own protocol (a Vector `vector` sink) needs its own
client certificate; a sender without one is refused. On the host:

```bash
$SSH $H 'cd ~/nano && scripts/nano vector-client-cert edge-dc1 --address nano.example.com:6000'
```

It writes `edge-dc1.key` (`0600`, never printed), `edge-dc1.crt` and `ca.crt`
to `~/nano/nano-vector-edge-dc1/`, restarts Vector once and prints the sink's
`tls.*` settings. Move the three files to the sender with `scp` (the key stays
`0600`; never print it). `--csr FILE` signs the sender's own request so the
key never leaves the sender. Day 2: `--list` (`expiring` marks the next 30
days), `--renew <name>` (copy the new `.crt`; no restart) and `--revoke <name>`
(restarts Vector; no other sender is affected). A NAT or public address the
host cannot see goes in `NANO_VECTOR_NATIVE_SANS` in `.env`, then re-run the
installer. Upgrading from 2.0.29 or earlier turns mutual TLS on, so plaintext
senders stop: issue their certificates right after the upgrade.

Then go to [verify.md](verify.md).

## Re-runs and recovery

- A step failed: fix the cause and re-run the same step. Re-running
  `./install.sh` is the normal recovery.
- Never run `docker compose down -v` to retry; it deletes all data.
- Install stopped before the admin was created (the UI shows the setup page):
  re-run Step 8, which creates it. Or the operator finishes in the browser:
  the setup page asks for the setup token, `NANO_SETUP_TOKEN` in `~/nano/.env`.
  The operator reads it on the host; never print it yourself. Once an admin
  exists the token is not needed.
- Leftover secret files: `~/.nano-admin-credentials` stays until the operator
  has signed in and stored the password in their password manager. Then offer
  to delete it (`shred -u`).
