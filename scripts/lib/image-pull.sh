#!/usr/bin/env bash
# Bounded image pull for install.sh (NAN-5197).
#
# `docker compose pull` re-resolves every manifest on its registry even when
# the pinned image is already local, and on a slow or rate-limited Docker Hub
# that hung the installer for 11-20 minutes with no output. Every image the
# installer starts is pinned: third-party refs carry @sha256 in the Compose
# files and first-party tags have a digest in the images lock. An image counts
# as present only when that pinned digest is local; a local tag that points at
# any other digest is stale and is pulled again. Only those images reach a
# registry, one `docker pull` each, under a timeout with retries.
#
# Usage: nano_pull_images "<newline-separated image refs>"
# Env:   NANO_PULL_LOCK         images lock giving digests for refs without
#                               one (`repo sha256:..` or `repo:tag sha256:..`)
#        NANO_PULL_TIMEOUT      seconds per pull attempt (default 600)
#        NANO_PULL_RETRIES      extra attempts after the first (default 2)
#        NANO_PULL_RETRY_DELAY  seconds between attempts (default 10)
#        NANO_PULL_TRUST_TAGS   1 = presence by plain inspect, no digest readback
#                               (install.sh sets it under NANO_SKIP_IMAGE_VERIFY=1)
# Returns 0 when every image is present afterwards, 1 (after naming the
# missing images and their registries on stderr) otherwise.

_nano_pull_say() {
    local level="$1"; shift
    if declare -F "$level" >/dev/null; then "$level" "$*"; else printf '%s\n' "$*" >&2; fi
}

_nano_pull_uint() {
    local value="$1" default="$2" name="$3"
    if [[ "$value" =~ ^[0-9]+$ ]]; then printf '%s\n' "$value"; return; fi
    [[ -n "$value" ]] && _nano_pull_say warn "$name='$value' is not a whole number of seconds/attempts; using $default."
    printf '%s\n' "$default"
}

# The registry host an image ref resolves against (Docker Hub when the first
# path component is not a host name).
nano_image_registry() {
    local ref="$1" first
    [[ "$ref" == */* ]] || { echo "docker.io"; return; }
    first="${ref%%/*}"
    if [[ "$first" == *"."* || "$first" == *":"* || "$first" == "localhost" ]]; then
        echo "$first"
    else
        echo "docker.io"
    fi
}

# The ref without its @digest and without its tag.
nano_image_repo() {
    local repo="${1%@*}"
    [[ "${repo##*/}" == *":"* ]] && repo="${repo%:*}"
    printf '%s\n' "$repo"
}

# The digest a ref is pinned to: its own @sha256, else its NANO_PULL_LOCK line
# (first-party lines are a bare repo, third-party lines repo:tag). Empty when
# nothing pins it.
nano_pinned_digest() {
    local ref="$1" repo lock_ref lock_digest
    if [[ "$ref" == *"@sha256:"* ]]; then
        printf '%s\n' "${ref##*@}"
        return
    fi
    [[ -n "${NANO_PULL_LOCK:-}" && -r "${NANO_PULL_LOCK:-}" ]] || return 0
    repo=$(nano_image_repo "$ref")
    while read -r lock_ref lock_digest _; do
        [[ -z "$lock_ref" || "$lock_ref" == "#"* ]] && continue
        if [[ "$lock_ref" == "$ref" || "$lock_ref" == "$repo" ]]; then
            printf '%s\n' "$lock_digest"
            return
        fi
    done < "$NANO_PULL_LOCK"
}

# True only when the pinned digest is in the local store: an inspected image
# whose RepoDigests holds exactly repo@<pin>, or whose image ID is the pin.
# Compose v5 stores a repo:tag@sha256 ref under repo@sha256 only, so that form
# is probed too. An unpinned ref falls back to plain presence.
nano_image_present() {
    local ref="$1" pinned repo probe line first
    pinned=$(nano_pinned_digest "$ref")
    if [[ -z "$pinned" || "${NANO_PULL_TRUST_TAGS:-0}" == "1" ]]; then
        docker image inspect "$ref" </dev/null >/dev/null 2>&1
        return
    fi
    repo=$(nano_image_repo "$ref")
    for probe in "$ref" "${repo}@${pinned}"; do
        # Line 1 is the image ID, then one RepoDigests entry per line (the
        # same readback install.sh's verify_image_digests uses).
        first=1
        while IFS= read -r line; do
            if [[ "$line" == "${repo}@${pinned}" ]] || { (( first )) && [[ "$line" == "$pinned" ]]; }; then
                return 0
            fi
            first=0
        done < <(docker image inspect "$probe" \
            --format '{{.Id}}{{println}}{{range .RepoDigests}}{{println .}}{{end}}' </dev/null 2>/dev/null || true)
    done
    return 1
}

nano_missing_images() {
    local ref
    while IFS= read -r ref; do
        [[ -z "$ref" ]] && continue
        nano_image_present "$ref" || printf '%s\n' "$ref"
    done <<< "$1"
}

# Run a command, killing it after $1 seconds. Portable to macOS, which has no
# coreutils `timeout`. Returns 124 on timeout, the command's status otherwise.
nano_run_with_timeout() {
    local seconds="$1"; shift
    local start=$SECONDS pid watcher rc=0
    "$@" </dev/null &
    pid=$!
    # The watcher polls instead of sleeping the whole timeout, so it exits on
    # its own within a second of the command finishing and leaves no orphan.
    (
        deadline=$((SECONDS + seconds))
        while kill -0 "$pid" 2>/dev/null; do
            if (( SECONDS >= deadline )); then
                kill -TERM "$pid" 2>/dev/null
                for _ in 1 2 3 4 5; do
                    kill -0 "$pid" 2>/dev/null || exit 0
                    sleep 1
                done
                kill -KILL "$pid" 2>/dev/null
                exit 0
            fi
            sleep 1
        done
    ) </dev/null >/dev/null 2>&1 &
    watcher=$!
    wait "$pid" 2>/dev/null || rc=$?
    wait "$watcher" 2>/dev/null || true
    if (( rc != 0 && SECONDS - start >= seconds )); then
        return 124
    fi
    return "$rc"
}

# Pull one ref (by its pin when it has one, so a tag is never re-resolved)
# with the timeout and retries. Returns 0 once the pinned digest is local.
_nano_pull_one() {
    local ref="$1" timeout="$2" max="$3" delay="$4" pinned target attempt=0 rc
    pinned=$(nano_pinned_digest "$ref")
    target="$ref"
    # A lock-pinned tag is pulled by digest and then tagged, so the tag the
    # Compose file names points at exactly the locked image.
    [[ -n "$pinned" && "$ref" != *"@"* ]] && target="$(nano_image_repo "$ref")@${pinned}"
    while (( attempt < max )); do
        attempt=$((attempt + 1))
        # NAN-5505: lets nano_pull_pre_hook (below) replace a pull credential this run
        # fetched before it expires (it lasts one hour).
        if declare -F nano_pull_pre_hook >/dev/null; then nano_pull_pre_hook "$ref" || true; fi
        _nano_pull_say log "Pulling $ref (attempt $attempt/$max, timeout ${timeout}s)"
        rc=0
        # NAN-5524: a private image pulls with the credential this run fetched,
        # from the private docker config it lives in (never the user's).
        if [[ -n "${NANO_REGISTRY_LOGGED_IN_AT:-}" && -n "${NANO_REGISTRY_DOCKER_CONFIG:-}" \
              && -n "$(nano_private_images "$ref")" ]]; then
            nano_run_with_timeout "$timeout" env DOCKER_CONFIG="$NANO_REGISTRY_DOCKER_CONFIG" docker pull "$target" || rc=$?
        else
            nano_run_with_timeout "$timeout" docker pull "$target" || rc=$?
        fi
        if (( rc == 0 )); then
            if [[ "$target" != "$ref" ]]; then
                docker tag "$target" "$ref" </dev/null >/dev/null 2>&1 || rc=1
            fi
            if (( rc == 0 )) && nano_image_present "$ref"; then
                return 0
            fi
            _nano_pull_say warn "Pulled $ref but its pinned digest ${pinned:-?} is still not local."
        elif (( rc == 124 )); then
            _nano_pull_say warn "Pull of $ref timed out after ${timeout}s."
        else
            _nano_pull_say warn "Pull of $ref failed (exit $rc)."
        fi
        if (( attempt < max && delay > 0 )); then sleep "$delay"; fi
    done
    return 1
}

nano_pull_images() {
    local images="$1"
    local timeout retries delay missing count failed="" ref
    timeout=$(_nano_pull_uint "${NANO_PULL_TIMEOUT:-}" 600 NANO_PULL_TIMEOUT)
    retries=$(_nano_pull_uint "${NANO_PULL_RETRIES:-}" 2 NANO_PULL_RETRIES)
    delay=$(_nano_pull_uint "${NANO_PULL_RETRY_DELAY:-}" 10 NANO_PULL_RETRY_DELAY)
    (( timeout > 0 )) || timeout=600

    missing=$(nano_missing_images "$images")
    if [[ -z "$missing" ]]; then
        _nano_pull_say ok "All pinned images are already present locally; skipping the registry pull"
        return 0
    fi
    count=$(printf '%s\n' "$missing" | grep -c .)
    _nano_pull_say log "$count image(s) are not present at their pinned digest; pulling only those"

    while IFS= read -r ref; do
        [[ -z "$ref" ]] && continue
        _nano_pull_one "$ref" "$timeout" "$((retries + 1))" "$delay" || failed+="$ref"$'\n'
    done <<< "$missing"
    [[ -z "$failed" ]] && return 0

    {
        printf 'Could not pull these images after %s attempt(s) of up to %ss each:\n' "$((retries + 1))" "$timeout"
        while IFS= read -r ref; do
            [[ -n "$ref" ]] && printf '  - %s (registry: %s)\n' "$ref" "$(nano_image_registry "$ref")"
        done <<< "$failed"
        printf 'Check that this host can reach those registries. Then either:\n'
        printf '  - enterprise: pull from the customer registry (NANO_IMAGES_LOCK=images.enterprise.customer.lock, the default when the bundle ships it) with the license pull credential, or load the offline image bundle (scripts/nano bundle load <images bundle>)\n'
        printf '  - configure a registry mirror ("registry-mirrors" in /etc/docker/daemon.json) or pre-load the images\n'
        printf '  - for Docker Hub rate limits (429 / toomanyrequests), run `docker login` and re-run\n'
        printf 'Raise the per-attempt limit with NANO_PULL_TIMEOUT=<seconds>.\n'
    } >&2
    return 1
}

# ---------------------------------------------------------------------------
# Registry login for enterprise image pulls (NAN-5505), in this file because
# every installer path (and its tests) already sources it.
#
# nano's enterprise application images (nanosiem-*) live in a private Artifact
# Registry repository. The license API issues a one-hour, pull-only credential
# for it: GET <license API>/license/self-run/registry-token?deploymentId=<id>
# with Authorization: Bearer <LICENSE_TOKEN> and X-Nano-Deployment-Id: <id>.
# The reply is JSON {registry, repository, username, password, expiresAt}.
# Same endpoint as skills/nano-deploy/scripts/fetch-bundle.sh and the Helm
# chart's registry-cred-refresh.sh.
#
# nano_registry_login_if_needed decides, right before the pull:
#   1. no private image is missing at its pinned digest -> nothing to do, no
#      API call (an air-gapped host that ran `nano bundle load`, or a re-run);
#   2. the registry already accepts this host's docker login (a manifest check
#      of one missing image) -> keep it, no API call;
#   3. license mode is online with a token and deployment ID -> fetch the
#      credential and `docker login --password-stdin`;
#   4. otherwise (offline, air-gapped, no token) -> no API call; say so and let
#      the pull report what is missing.
# A credential fetch or login that fails stops the install (returns 1 after
# naming the cause). The license token and the registry password never reach
# argv, the terminal or any file: the token goes to curl as a -K config on
# stdin, the password to `docker login --password-stdin`.
#
# NAN-5524: that login, and every pull of a private image while it is in use,
# runs under a PRIVATE docker config: a mktemp directory (0700) in
# NANO_REGISTRY_DOCKER_CONFIG, never the user's own ~/.docker. So an interrupt
# cannot leave the one-hour credential behind in the user's config, a
# customer's own entry for the registry is never overwritten or logged out,
# and a credential helper (credHelpers/credsStore) configured for the registry
# is never in the way. The caller removes it with nano_registry_cleanup (in an
# EXIT trap). The private config.json keeps the user's CLI plugins
# (cliPluginsExtraDirs: compose, buildx) and current docker context. A
# caller may hand in its own directory (NANO_REGISTRY_DOCKER_CONFIG set,
# NANO_REGISTRY_DOCKER_CONFIG_OWNED=0) and removes it itself.
#
# Inputs (shell variables, not exported, set by the caller):
#   NANO_REGISTRY_LICENSE_MODE   online | offline | airgap | app-host | pending | ...
#   NANO_REGISTRY_LICENSE_URL    LICENSE_URL (https://.../api/license/status)
#   NANO_REGISTRY_LICENSE_TOKEN  LICENSE_TOKEN (secret)
#   NANO_REGISTRY_DEPLOYMENT_ID  NANO_DEPLOYMENT_ID
#   NANO_REGISTRY_PROXY          optional outbound proxy for the license API
# Env: NANO_PRIVATE_IMAGE_PREFIX  images that need the credential
#      (default us-central1-docker.pkg.dev/nano-rs/)
#      NANO_REGISTRY_RELOGIN_AFTER seconds after which a pull logs in again
#      with a fresh credential (default 2700; the credential lasts 3600)

NANO_REGISTRY_LOGGED_IN_AT=""
NANO_REGISTRY_DOCKER_CONFIG="${NANO_REGISTRY_DOCKER_CONFIG:-}"
NANO_REGISTRY_DOCKER_CONFIG_OWNED="${NANO_REGISTRY_DOCKER_CONFIG_OWNED:-0}"

# A JSON string literal (paths only: backslash and quote escaped, controls
# refused by the caller).
_nano_reg_json_string() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    printf '"%s"' "$v"
}

# Write the private config.json: no credentials, only what keeps the docker
# CLI working under it. A private DOCKER_CONFIG hides the user's
# <config>/cli-plugins (docker compose and buildx are plugins there on Docker
# Desktop and on some Linux installs) and the user's current context (Docker
# Desktop, rootless docker): both are carried over. The user's config is only
# looked at for its plugin and context directories, never read for
# credentials and never written.
_nano_registry_write_private_config() {
    local dir="$1" user_conf ctx="" sep="" d dirs=() seen=" " json
    user_conf="${DOCKER_CONFIG:-${HOME:-}/.docker}"
    for d in "$user_conf/cli-plugins" "${HOME:-}/.docker/cli-plugins" \
             /usr/local/lib/docker/cli-plugins /usr/local/libexec/docker/cli-plugins \
             /usr/lib/docker/cli-plugins /usr/libexec/docker/cli-plugins \
             /Applications/Docker.app/Contents/Resources/cli-plugins; do
        [[ -d "$d" && "$d" != *[[:cntrl:]]* && "$seen" != *" $d "* ]] || continue
        seen+="$d "
        dirs+=("$d")
    done
    if [[ -z "${DOCKER_HOST:-}" && -z "${DOCKER_CONTEXT:-}" && -d "$user_conf/contexts" ]]; then
        ctx=$(docker context show </dev/null 2>/dev/null | awk 'NR == 1') || ctx=""
        if [[ "$ctx" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ && "$ctx" != default ]]; then
            ln -s "$user_conf/contexts" "$dir/contexts" 2>/dev/null || ctx=""
        else
            ctx=""
        fi
    fi
    # The placeholder auths entry matters: a config with no auth at all lets
    # the docker CLI pick the platform's default credential helper (macOS
    # keychain, pass, secretservice) for `docker login`, which would put the
    # credential back into the user's store. With it, the login stays in this
    # file, which nano_registry_cleanup deletes.
    json='{"auths":{"nano-private-docker-config.invalid":{}},"cliPluginsExtraDirs":['
    for d in ${dirs[@]+"${dirs[@]}"}; do
        json+="$sep$(_nano_reg_json_string "$d")"; sep=","
    done
    json+=']'
    [[ -z "$ctx" ]] || json+=",\"currentContext\":\"$ctx\""
    json+='}'
    ( umask 077; printf '%s\n' "$json" > "$dir/config.json" )
}

# The private docker config directory, created on first use. Returns 1 when
# it cannot be created (nothing is logged in then).
nano_registry_private_config() {
    local dir="${NANO_REGISTRY_DOCKER_CONFIG:-}"
    if [[ -z "$dir" ]]; then
        dir=$(umask 077; mktemp -d "${TMPDIR:-/tmp}/nano-docker-config.XXXXXX" 2>/dev/null) || return 1
        [[ -n "$dir" && -d "$dir" ]] || return 1
        NANO_REGISTRY_DOCKER_CONFIG="$dir"
        NANO_REGISTRY_DOCKER_CONFIG_OWNED=1
    fi
    [[ -d "$dir" && ! -L "$dir" && -O "$dir" ]] || return 1
    chmod 700 "$dir" 2>/dev/null || return 1
    [[ -f "$dir/config.json" ]] || _nano_registry_write_private_config "$dir" || return 1
    return 0
}

# Drop the credential this run fetched: remove the private config (only one
# this library created) and forget the login. Safe to call any number of
# times, from an EXIT trap included. The user's docker config is untouched.
nano_registry_cleanup() {
    NANO_REGISTRY_LICENSE_TOKEN=""
    NANO_REGISTRY_LOGGED_IN_AT=""
    if [[ "${NANO_REGISTRY_DOCKER_CONFIG_OWNED:-0}" == 1 && -n "${NANO_REGISTRY_DOCKER_CONFIG:-}" ]]; then
        rm -rf -- "$NANO_REGISTRY_DOCKER_CONFIG" 2>/dev/null || true
        NANO_REGISTRY_DOCKER_CONFIG=""
        NANO_REGISTRY_DOCKER_CONFIG_OWNED=0
    fi
    return 0
}

_nano_reg_say() {
    local level="$1"; shift
    if declare -F "$level" >/dev/null; then "$level" "$*"; else printf '%s\n' "$*" >&2; fi
}

# The private (credential-gated) images among a newline-separated list.
nano_private_images() {
    local ref prefix="${NANO_PRIVATE_IMAGE_PREFIX:-us-central1-docker.pkg.dev/nano-rs/}"
    while IFS= read -r ref; do
        [[ -n "$ref" && "$ref" == "$prefix"* ]] && printf '%s\n' "$ref"
    done <<< "$1"
    return 0
}

# One JSON string field from a flat object (the reply has no nesting).
_nano_reg_field() {
    printf '%s' "$2" | tr -d '\n' \
        | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | awk 'NR == 1'
}

# The registry-token URL derived from LICENSE_URL (…/api/license/status ->
# …/api/license/self-run/registry-token). Only https, or loopback for tests.
nano_registry_token_url() {
    local license_url="$1" base
    if [[ ! "$license_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/ && ! "$license_url" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?/ ]]; then
        return 1
    fi
    base="${license_url%%\?*}"
    base="${base%/}"
    base="${base%/status}"
    [[ "$base" == */license ]] || return 1
    printf '%s/self-run/registry-token\n' "$base"
}

# True when docker can already read the image (an existing login works).
nano_registry_probe() {
    local ref="$1" pinned target
    pinned=$(nano_pinned_digest "$ref")
    target="$ref"
    [[ -n "$pinned" && "$ref" != *"@"* ]] && target="$(nano_image_repo "$ref")@${pinned}"
    nano_run_with_timeout 60 docker manifest inspect "$target" >/dev/null 2>&1
}

# NAN-5509: curl's own last error line, so a TLS-inspecting proxy, a bad CA
# bundle, DNS or a refused connection each read as what they are. Only curl's
# message is kept (it never echoes the -K config, so never the token), cut to
# one bounded line of printable characters.
_nano_reg_curl_error() {
    [[ -s "$1" ]] || return 0
    grep -E '^curl: \([0-9]+\)' "$1" 2>/dev/null | tail -n 1 | tr -cd '[:print:]' | cut -c1-240
}

# Epoch seconds of an HTTP Date header value (RFC 7231), GNU or BSD date.
_nano_reg_http_date_epoch() {
    date -u -d "$1" +%s 2>/dev/null \
        || date -u -j -f '%a, %d %b %Y %H:%M:%S GMT' "$1" +%s 2>/dev/null
}

# NAN-5509: a host clock far from the license API's (a VM restored from a
# snapshot, no NTP) breaks TLS ("certificate is not yet valid") and token
# checks. Compares against the API's Date header; prints a plain sentence
# when they differ by more than five minutes, nothing otherwise. The probe
# sends no credential, so certificate checks are skipped for it alone.
nano_registry_clock_skew() {
    local host="$1" header remote now skew
    header=$(
        { [[ -n "${NANO_REGISTRY_PROXY:-}" ]] && printf 'proxy = "%s"\n' "$NANO_REGISTRY_PROXY"; true; } \
            | curl -sS -k -I --proto '=https,http' --connect-timeout 10 -m 15 -K - "https://$host/" 2>/dev/null \
            | tr -d '\r' | sed -n 's/^[Dd]ate:[[:space:]]*//p' | awk 'NR == 1'
    ) || true
    [[ -n "$header" ]] || return 0
    remote=$(_nano_reg_http_date_epoch "$header") || return 0
    [[ "$remote" =~ ^[0-9]+$ ]] || return 0
    now=$(date -u +%s)
    skew=$(( now - remote ))
    (( skew < 0 )) && skew=$(( -skew ))
    (( skew > 300 )) || return 0
    printf "This host's clock is off by about %s minutes (this host: %s; %s: %s). TLS and the license check fail on a wrong clock. Fix the time (sudo timedatectl set-ntp true, or sudo chronyc makestep), then re-run.\n" \
        "$(( skew / 60 ))" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" "$host" "$header"
}

# Fetch the credential and log docker in. Returns 1 after naming the cause.
# $1: one private image ref this install pulls (to check the credential covers it).
nano_registry_fetch_and_login() {
    local sample="$1" url host reply code body registry repository username password expires err
    local image_registry curl_err_file curl_err="" skew=""
    url=$(nano_registry_token_url "${NANO_REGISTRY_LICENSE_URL:-}") || {
        _nano_reg_say warn "LICENSE_URL in .env is not an https://…/api/license/status URL, so the installer cannot ask the license API for a registry pull credential."
        return 1
    }
    [[ "${NANO_REGISTRY_DEPLOYMENT_ID:-}" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || {
        _nano_reg_say warn "NANO_DEPLOYMENT_ID is malformed; cannot ask the license API for a registry pull credential."
        return 1
    }
    [[ "${NANO_REGISTRY_LICENSE_TOKEN:-}" =~ ^[A-Za-z0-9_-]+$ ]] || {
        _nano_reg_say warn "LICENSE_TOKEN is not an enrollment token (value not shown); cannot ask the license API for a registry pull credential."
        return 1
    }
    host="${url#*://}"; host="${host%%/*}"
    # The proxy URL goes into a curl config line: no quote, backslash or space.
    if [[ -n "${NANO_REGISTRY_PROXY:-}" && ! "$NANO_REGISTRY_PROXY" =~ ^https?://[^[:space:]\"\\]+$ ]]; then
        _nano_reg_say warn "HTTPS_PROXY in .env is not a plain http(s)://host:port URL (value not shown); fix it, then re-run."
        return 1
    fi
    _nano_reg_say log "Requesting a one-hour registry pull credential from the license API ($host)"
    curl_err_file=$(mktemp "${TMPDIR:-/tmp}/nano-license-curl.XXXXXX" 2>/dev/null) || curl_err_file=""
    # The token reaches curl as a config on stdin, never in argv.
    reply=$(
        {
            printf 'header = "Authorization: Bearer %s"\n' "$NANO_REGISTRY_LICENSE_TOKEN"
            printf 'header = "X-Nano-Deployment-Id: %s"\n' "$NANO_REGISTRY_DEPLOYMENT_ID"
            [[ -n "${NANO_REGISTRY_PROXY:-}" ]] && printf 'proxy = "%s"\n' "$NANO_REGISTRY_PROXY"
        } | curl -sS --proto '=https,http' --connect-timeout 15 -m 60 -K - \
            -w '\n%{http_code}' "$url?deploymentId=$NANO_REGISTRY_DEPLOYMENT_ID" 2>"${curl_err_file:-/dev/null}"
    ) || true
    if [[ -n "$curl_err_file" ]]; then
        curl_err=$(_nano_reg_curl_error "$curl_err_file")
        rm -f -- "$curl_err_file"
    fi
    code="${reply##*$'\n'}"
    body="${reply%$'\n'*}"
    [[ "$reply" == *$'\n'* ]] || body=""
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    reply=""
    if [[ "$code" != 200 ]]; then
        # Error bodies carry {error, code} only; the code is safe to show.
        err=$(_nano_reg_field code "$body")
        [[ "$err" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || err=""
        body=""
        case "$code" in
            000)
                skew=$(nano_registry_clock_skew "$host")
                if [[ -n "$skew" ]]; then
                    _nano_reg_say warn "Could not reach the license API at $host for a registry pull credential${curl_err:+ ($curl_err)}. $skew"
                else
                    case "$curl_err" in
                        *"curl: (6)"*) _nano_reg_say warn "Could not resolve $host ($curl_err): this host's DNS cannot find the license API. Check /etc/resolv.conf or your DNS server, or set HTTPS_PROXY=http://host:port in .env if outbound traffic must go through a proxy, then re-run." ;;
                        *"curl: (60)"* | *"curl: (35)"* | *"curl: (77)"* | *"curl: (51)"* | *"curl: (58)"*) _nano_reg_say warn "The TLS connection to the license API at $host failed ($curl_err). This is usually a proxy or firewall that inspects TLS with its own certificate authority: add that CA to this host's trust store (Debian/Ubuntu: copy it to /usr/local/share/ca-certificates/ and run sudo update-ca-certificates; RHEL: /etc/pki/ca-trust/source/anchors/ and sudo update-ca-trust), or exempt $host from inspection, then re-run." ;;
                        *) _nano_reg_say warn "Could not reach the license API at $host for a registry pull credential${curl_err:+ ($curl_err)} (network, DNS, firewall or proxy). Check that this host reaches https://$host. If it needs a proxy, add HTTPS_PROXY=http://host:port to .env (the installer reads it from there; NANO_HTTPS_PROXY is only asked once), then re-run." ;;
                    esac
                fi ;;
            401)
                skew=$(nano_registry_clock_skew "$host")
                _nano_reg_say warn "The license API rejected LICENSE_TOKEN (HTTP 401${err:+, $err}).${skew:+ $skew} Regenerate the license token on app.nano.rs (Deployments → your Self-run deployment → License), then re-run with only the new token: LICENSE_TOKEN=<new token> ./install.sh (the deployment ID recorded in .env is kept)." ;;
            403) _nano_reg_say warn "The license API refused a registry pull credential for deployment $NANO_REGISTRY_DEPLOYMENT_ID (HTTP 403${err:+, $err}): the token belongs to a different deployment, or the deployment is not paid or in trial. Check NANO_DEPLOYMENT_ID and LICENSE_TOKEN against app.nano.rs." ;;
            404) _nano_reg_say warn "The license API does not know deployment $NANO_REGISTRY_DEPLOYMENT_ID or has no registry credential for it (HTTP 404${err:+, $err}). Check NANO_DEPLOYMENT_ID against app.nano.rs." ;;
            *) _nano_reg_say warn "The license API did not issue a registry pull credential (HTTP $code${err:+, $err}). Try again in a few minutes." ;;
        esac
        return 1
    fi
    registry=$(_nano_reg_field registry "$body")
    repository=$(_nano_reg_field repository "$body")
    username=$(_nano_reg_field username "$body")
    password=$(_nano_reg_field password "$body")
    expires=$(_nano_reg_field expiresAt "$body")
    body=""
    if [[ ! "$registry" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?$ || ! "$username" =~ ^[A-Za-z0-9._@-]+$ \
          || ! "$password" =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
        password=""
        _nano_reg_say warn "The license API's registry credential reply was malformed (no registry, username or password)."
        return 1
    fi
    image_registry=$(nano_image_registry "$sample")
    if [[ "$registry" != "$image_registry" ]] || { [[ -n "$repository" ]] && [[ "$sample" != "$repository/"* ]]; }; then
        password=""
        _nano_reg_say warn "The license credential reads only ${repository:-$registry}, but this install pulls $(nano_image_repo "$sample") (nano's internal repository, from images.enterprise.lock). Use the customer lock this bundle ships: unset NANO_IMAGES_LOCK, or set NANO_IMAGES_LOCK=images.enterprise.customer.lock. An install that already runs these internal images keeps them: log in with a credential that reads $(nano_image_repo "$sample"), or load the offline image bundle (scripts/nano bundle load), then re-run."
        return 1
    fi
    # NAN-5524: into the private docker config only (see the header).
    if ! nano_registry_private_config; then
        password=""
        _nano_reg_say warn "Could not create a private docker config directory under ${TMPDIR:-/tmp} for the registry login; check that it is writable, then re-run."
        return 1
    fi
    # printf is a builtin: the password goes down the pipe, never into argv.
    if ! err=$(printf '%s\n' "$password" | DOCKER_CONFIG="$NANO_REGISTRY_DOCKER_CONFIG" \
            docker login "$registry" -u "$username" --password-stdin 2>&1 >/dev/null); then
        password=""
        err=$(printf '%s' "$err" | tr '\n' ' ' | cut -c1-300)
        _nano_reg_say warn "docker login to $registry with the license-issued credential failed: ${err:-no detail}"
        return 1
    fi
    password=""
    NANO_REGISTRY_LOGGED_IN_AT=$SECONDS
    _nano_reg_say ok "Logged in to $registry with a pull credential from the license API${expires:+ (expires $expires)}"
    return 0
}

# See the header. $1: newline-separated image refs this run starts.
nano_registry_login_if_needed() {
    local images="$1" private missing first
    private=$(nano_private_images "$images")
    [[ -n "$private" ]] || return 0
    missing=$(nano_missing_images "$private")
    if [[ -z "$missing" ]]; then
        return 0
    fi
    first=$(printf '%s\n' "$missing" | awk 'NR == 1')
    if nano_registry_probe "$first"; then
        _nano_reg_say ok "This host's docker login already reads $(nano_image_registry "$first"); using it"
        return 0
    fi
    if [[ "${NANO_REGISTRY_LICENSE_MODE:-}" == offline || "${NANO_REGISTRY_LICENSE_MODE:-}" == airgap \
          || -z "${NANO_REGISTRY_LICENSE_TOKEN:-}" || -z "${NANO_REGISTRY_DEPLOYMENT_ID:-}" ]]; then
        _nano_reg_say warn "This host is not logged in to $(nano_image_registry "$first") and the license is not online (mode ${NANO_REGISTRY_LICENSE_MODE:-unknown}), so no pull credential is requested from the license API."
        return 0
    fi
    nano_registry_fetch_and_login "$first"
}

# Called by nano_pull_images before each pull: a credential this run fetched
# is replaced before it can expire mid-pull (it lasts one hour).
nano_pull_pre_hook() {
    local ref="$1" after
    [[ -n "$NANO_REGISTRY_LOGGED_IN_AT" ]] || return 0
    [[ -n "$(nano_private_images "$ref")" ]] || return 0
    after="${NANO_REGISTRY_RELOGIN_AFTER:-2700}"
    [[ "$after" =~ ^[0-9]+$ ]] || after=2700
    (( SECONDS - NANO_REGISTRY_LOGGED_IN_AT >= after )) || return 0
    _nano_reg_say log "The registry pull credential is close to expiry; requesting a fresh one"
    nano_registry_fetch_and_login "$ref"
}
