# Single node (Docker Compose)

One Linux host runs the whole stack from the **enterprise compose bundle**.
Never use the open-source one-line installer (`get.nano.rs`) for a Self-run
deployment. It installs the open edition, and an install never switches
edition later.

Conventions below: `H` is `user@host`, `SSH="ssh -o BatchMode=yes"`, the
install directory is `~/nano` for the SSH user, and `V` is the release (for
example `2.0.4`). Before each step, show the operator the commands and ask.

## Step 0: check the bundle locally (read-only)

```bash
shasum -a 256 nano-compose-enterprise-$V.tar.gz    # or sha256sum
tar -tzf nano-compose-enterprise-$V.tar.gz | head -3   # top directory: nano-$V/
```

Compare the digest with the value published by nano. On a mismatch, stop.

## Step 1: host prerequisites (only if preflight failed on them)

Propose the minimum fix for each `FAIL` and run it only after approval. On
Debian or Ubuntu, install Docker Engine and the Compose plugin from Docker's
official apt repository (docs.docker.com/engine/install). Do not use the
distribution's `docker.io` package when it is older than 24. Then:

```bash
sudo apt-get install -y git curl openssl python3 tar iproute2
sudo usermod -aG docker "$USER"     # then open a NEW SSH session
```

Re-run preflight until it shows zero `FAIL`.

## Step 2: stage the bundle (mutating)

```bash
scp -p nano-compose-enterprise-$V.tar.gz $H:~/
$SSH $H 'set -e; test ! -e ~/nano || { echo "~/nano exists: this is an upgrade, see operate.md"; exit 3; }
  tar -xzf ~/nano-compose-enterprise-'$V'.tar.gz -C ~ && mv ~/nano-'$V' ~/nano
  cat ~/nano/.nano-edition; grep "^# Release:" ~/nano/images.enterprise.lock'
```

Expect `enterprise` and `# Release: v$V`. Keep the whole extracted directory:
the compose files, scripts and image lock are one release artifact.

## Step 3: registry login (mutating, secret)

The registry host is the prefix of the image lines in `images.enterprise.customer.lock`
(for example `us-central1-docker.pkg.dev`). Copy the operator's credential file
and log in from stdin:

```bash
scp -p "$REGISTRY_CRED_FILE" $H:~/.nano-registry-cred
$SSH $H 'chmod 600 ~/.nano-registry-cred && docker login REGISTRY_HOST -u "REGISTRY_USER" --password-stdin < ~/.nano-registry-cred; rm -f ~/.nano-registry-cred'
```

If the operator has already logged in on the host, skip this step. Confirm
with `docker pull` of one image from the lock, or let the install step report
it.

## Step 4: admin credential file (mutating, secret stays on host)

```bash
$SSH $H "bash -s -- --email ADMIN_EMAIL --name 'ADMIN NAME'" < scripts/admin-credentials.sh
```

## Step 5: check-only (read-only)

```bash
$SSH $H 'cd ~/nano && NANO_CHECK_ONLY=1 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh'
```

It prints the edition, release and image source and writes nothing. It must
say `enterprise` and the release you expect.

## Step 6: prepare without starting (mutating)

`BASE_URL` is the public URL users will open. Use `https://` for anything
beyond a lab. With `http://` the installer turns on dev mode (cookies without
`Secure`).

```bash
$SSH $H 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_BASE_URL=BASE_URL NANO_SCHEMA_PROFILE=ocsf NANO_PREPARE_ONLY=1 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh'
```

This writes `~/nano/.env` (mode `0600`) with generated secrets. It does not
pull or start the application. The schema profile is fixed at first install.
`ocsf` is the default for new installs; ask before choosing anything else.

## Step 7: enrollment (mutating, secret)

```bash
scp -p "$ENROLLMENT_FILE" $H:~/.nano-enrollment.env
$SSH $H 'bash -s' -- --env ~/nano/.env --from ~/.nano-enrollment.env < scripts/apply-enrollment.sh
```

If the operator has no enrollment yet (the trial is still pending), say that
the install will run unlicensed until the values are added. Ask whether to continue. To add them later, run this
step, then Step 8 again.

## Step 8: install and start (mutating)

```bash
$SSH $H 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_BASE_URL=BASE_URL NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh'
```

The admin variables are needed again: the prepared `.env` makes this a re-run,
and the admin is created only when setup is still uninitialized. The
installer pulls the images listed in `images.enterprise.customer.lock`, verifies every digest against `images.enterprise.lock`
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
  `0600`). Then re-run the installer with the overlay. The guide says to pass
  it on **every** installer run, including upgrades, or nginx returns to plain
  HTTP:

  ```bash
  $SSH $H 'cd ~/nano && grep -q "^NANO_COMPOSE_OVERLAYS=" .env || echo "NANO_COMPOSE_OVERLAYS=docker-compose.tls.yml" >> .env
    set -a && . ~/.nano-admin-credentials && set +a &&
    NANO_COMPOSE_OVERLAYS=docker-compose.tls.yml NANO_BASE_URL=BASE_URL NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh'
  ```

  Recording the overlay in `.env` makes `scripts/nano` backup and upgrade keep
  it too. Do the **first** install (Step 8) without the overlay, then enable
  it as shown here once the admin exists. See
  [known-issues.md](known-issues.md).

## Step 10: firewall (operator-owned)

The installer never changes the firewall. Propose rules and apply them only if
the operator asks you to. Allow 443 (and 80 for redirects) from users, and
only the ingest ports in use from the log sources. HTTP ingest goes through
nginx on 80/443 at `/ingest`; Vector's 8080 and the HEC port 8088 are
token-gated. Keep 6000, 4317, 4318 and 24224 on loopback (the default).
Docker-published ports bypass UFW's `INPUT` rules: enforce source limits in
the `DOCKER-USER` chain, as described in [multi-node-ha.md](multi-node-ha.md#firewall).

Then go to [verify.md](verify.md).

## Re-runs and recovery

- A step failed: fix the cause and re-run the same step. Re-running
  `./install.sh` is the normal recovery.
- Never run `docker compose down -v` to retry; it deletes all data.
- Leftover secret files: `~/.nano-admin-credentials` stays until the operator
  has signed in and stored the password in their password manager. Then offer
  to delete it (`shred -u`).
