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
        _nano_pull_say log "Pulling $ref (attempt $attempt/$max, timeout ${timeout}s)"
        rc=0
        nano_run_with_timeout "$timeout" docker pull "$target" || rc=$?
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
        printf '  - enterprise: use the customer registry, NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh\n'
        printf '  - configure a registry mirror ("registry-mirrors" in /etc/docker/daemon.json) or pre-load the images\n'
        printf '  - for Docker Hub rate limits (429 / toomanyrequests), run `docker login` and re-run\n'
        printf 'Raise the per-attempt limit with NANO_PULL_TIMEOUT=<seconds>.\n'
    } >&2
    return 1
}
