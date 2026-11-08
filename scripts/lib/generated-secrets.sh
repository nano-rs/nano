#!/usr/bin/env bash
# Shared inventory and backfill helper for generated compose secrets.
#
# Inventory contract:
# - nano_cluster_shared_secret_keys lists credentials that must be identical on
#   every host in a role-split deployment. Only the canonical app/prepare host
#   may create missing values.
# - nano_host_local_secret_keys lists credentials that may differ per host. The
#   list is intentionally empty today; ClickHouse memory is host-local config,
#   not a secret. Keep the scope explicit when a real host-local secret arrives.
# - nano_generated_secret_keys is the union used by single-node generators.
#
# Backfill contract:
#   nano_backfill_generated_secrets ENV_FILE generate [LOCK_IDENTITY]
#     Single-node installs and the canonical app/prepare host atomically append
#     generated values for effectively empty keys. LOCK_IDENTITY lets a
#     provisional first-install file serialize on its eventual .env path.
#   nano_backfill_generated_secrets ENV_FILE validate-only [LOCK_IDENTITY]
#     Other role hosts never generate. A missing cluster-shared value fails
#     with the instruction to copy the canonical host's updated shared .env.
#
# The helper resolves a symlinked ENV_FILE to its final target and atomically
# replaces that target in its own directory, leaving the link intact. Existing
# uid, gid, and mode are preserved. A metadata-preservation failure is reported
# before file contents are read. A lock spans recheck, generation, and rename.
# Inherited xtrace is disabled before any value is read/generated/written and is
# restored on every return path. Secret values are never written to stdout.

nano_cluster_shared_secret_keys() {
    printf '%s\n' \
        POSTGRES_PASSWORD \
        CLICKHOUSE_PASSWORD \
        CLICKHOUSE_ADMIN_PASSWORD \
        CLICKHOUSE_INGEST_PASSWORD \
        CLICKHOUSE_VECTOR_PASSWORD \
        CLICKHOUSE_RAWSQL_PASSWORD \
        CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD \
        JWT_SECRET \
        NANOSIEM_ENCRYPTION_KEY \
        VECTOR_AUTH_TOKEN \
        NANO_PLATFORM_INGEST_TOKEN \
        NANO_OTLP_EDGE_KEY \
        NANO_VECTOR_TAP_TOKEN \
        NANO_KEEPER_PASSWORD \
        NANO_KEEPER_SUPER_DIGEST
}

nano_host_local_secret_keys() {
    # No host-local random credentials exist yet. Keep this function so the
    # multi-node contract cannot accidentally collapse back into one list.
    return 0
}

nano_generated_secret_keys() {
    nano_cluster_shared_secret_keys
    nano_host_local_secret_keys
}

nano_secret_resolve_target() {
    local current="$1" link directory hops=0
    [[ "$current" = /* ]] || current="$PWD/$current"
    while [[ -L "$current" ]]; do
        hops=$((hops + 1))
        (( hops <= 40 )) || return 1
        link="$(readlink "$current")" || return 1
        if [[ "$link" = /* ]]; then
            current="$link"
        else
            current="$(dirname "$current")/$link"
        fi
    done
    directory="$(cd "$(dirname "$current")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s\n' "$directory" "$(basename "$current")"
}

nano_file_metadata() {
    local metadata
    if metadata="$(stat -f '%u %g %Lp %z' "$1" 2>/dev/null)"; then
        printf '%s\n' "$metadata"
        return 0
    fi
    stat -c '%u %g %a %s' "$1" 2>/dev/null
}

nano_secret_metadata() {
    local metadata uid gid mode size extra
    metadata="$(nano_file_metadata "$1")" || return 1
    read -r uid gid mode size extra <<< "$metadata"
    [[ -z "$extra" && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ \
        && "$mode" =~ ^[0-7]+$ && "$size" =~ ^[0-9]+$ ]] || return 1
    printf '%s %s %s\n' "$uid" "$gid" "$mode"
}

nano_file_size() {
    local metadata uid gid mode size extra
    metadata="$(nano_file_metadata "$1")" || return 1
    read -r uid gid mode size extra <<< "$metadata"
    [[ -z "$extra" && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ \
        && "$mode" =~ ^[0-7]+$ && "$size" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$size"
}

nano_secret_apply_metadata() {
    local path="$1" uid="$2" gid="$3" mode="$4" current_uid actual
    current_uid="$(id -u)" || return 1
    if [[ "$current_uid" == 0 ]]; then
        chown "$uid:$gid" "$path" 2>/dev/null || return 1
    else
        [[ "$current_uid" == "$uid" ]] || return 1
        chgrp "$gid" "$path" 2>/dev/null || return 1
    fi
    chmod "$mode" "$path" 2>/dev/null || return 1
    actual="$(nano_secret_metadata "$path")" || return 1
    [[ "$actual" == "$uid $gid $mode" ]]
}

nano_secret_effective_nonempty() {
    local file="$1" key="$2"
    awk -v wanted="$key" '
        function ltrim(s) { sub(/^[ \t]+/, "", s); return s }
        function rtrim(s) { sub(/[ \t]+$/, "", s); return s }
        function quote_close(value, quote, start, i, char, escaped) {
            escaped = 0
            for (i = start; i <= length(value); i++) {
                char = substr(value, i, 1)
                if (char == "\\" && !escaped) {
                    escaped = 1
                    continue
                }
                if (char == quote && !escaped) return i
                escaped = 0
            }
            return 0
        }
        function value_nonempty(value, quote, closing, i, char, leading_space) {
            leading_space = value ~ /^[ \t]+/
            value = ltrim(value)
            if (value == "") return 0
            if (substr(value, 1, 1) == "#") return leading_space ? 0 : 1
            quote = substr(value, 1, 1)
            if (quote == "\"" || quote == single_quote) {
                closing = quote_close(value, quote, 2)
                if (closing) return closing > 2
                return length(value) > 1
            }
            for (i = 1; i <= length(value); i++) {
                char = substr(value, i, 1)
                if (char == "#" && i > 1 && substr(value, i - 1, 1) ~ /[ \t]/) {
                    value = substr(value, 1, i - 1)
                    break
                }
            }
            return length(rtrim(value)) > 0
        }
        BEGIN {
            single_quote = sprintf("%c", 39)
            seen = 0
            nonempty = 0
            in_single_quote = 0
            wanted_single_quote = 0
        }
        {
            line = $0
            sub(/\r$/, "", line)
            if (in_single_quote) {
                if (wanted_single_quote) nonempty = 1
                if (quote_close(line, single_quote, 1)) {
                    in_single_quote = 0
                    wanted_single_quote = 0
                }
                next
            }
            sub(/^[ \t]*export[ \t]+/, "", line)
            if (match(line, "^[ \t]*" wanted "[ \t]*=")) {
                seen = 1
                value = substr(line, RLENGTH + 1)
                nonempty = value_nonempty(value)
                value = ltrim(value)
                if (substr(value, 1, 1) == single_quote \
                    && !quote_close(value, single_quote, 2)) {
                    in_single_quote = 1
                    wanted_single_quote = 1
                }
            } else if (line ~ ("^[ \t]*" wanted "[ \t]*$")) {
                seen = 1
                nonempty = 0
            } else if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/)) {
                value = ltrim(substr(line, RLENGTH + 1))
                if (substr(value, 1, 1) == single_quote \
                    && !quote_close(value, single_quote, 2)) {
                    in_single_quote = 1
                    wanted_single_quote = 0
                }
            }
        }
        END { exit(seen && nonempty ? 0 : 1) }
    ' "$file"
}

nano_secret_lock_acquire() {
    local lock_file="$1" target_uid="$2" target_gid="$3" tries=0
    local current_uid lock_metadata lock_uid
    NANO_SECRET_LOCK_KIND=""
    NANO_SECRET_LOCK_DIR=""
    if command -v flock >/dev/null 2>&1; then
        [[ ! -L "$lock_file" ]] || return 1
        (umask 077; : >> "$lock_file") || return 1
        current_uid="$(id -u)" || return 1
        if [[ "$current_uid" == 0 ]]; then
            chown "$target_uid:$target_gid" "$lock_file" 2>/dev/null || return 1
        else
            lock_metadata="$(nano_secret_metadata "$lock_file")" || return 1
            lock_uid="${lock_metadata%% *}"
            [[ "$lock_uid" == "$current_uid" ]] || return 1
        fi
        chmod 600 "$lock_file" 2>/dev/null || return 1
        exec 9<> "$lock_file" || return 1
        flock -x 9 || { exec 9>&-; return 1; }
        NANO_SECRET_LOCK_KIND="flock"
        return 0
    fi

    NANO_SECRET_LOCK_DIR="${lock_file}.d"
    while ! mkdir "$NANO_SECRET_LOCK_DIR" 2>/dev/null; do
        tries=$((tries + 1))
        (( tries < 300 )) || return 1
        sleep 0.1
    done
    NANO_SECRET_LOCK_KIND="mkdir"
}

nano_secret_lock_release() {
    case "${NANO_SECRET_LOCK_KIND:-}" in
        flock) flock -u 9 2>/dev/null || true; exec 9>&- ;;
        mkdir) rmdir "$NANO_SECRET_LOCK_DIR" 2>/dev/null || true ;;
    esac
    NANO_SECRET_LOCK_KIND=""
    NANO_SECRET_LOCK_DIR=""
}

nano_secret_atomic_replace() {
    local tmp="$1" target="$2" uid="$3" gid="$4" perms="$5"
    nano_secret_apply_metadata "$tmp" "$uid" "$gid" "$perms" || return 1
    mv -f "$tmp" "$target"
}

# Run a content writer while holding the same stable lock used by generated
# secret backfill. The writer receives TARGET TMP followed by its own arguments
# and must write the complete replacement to TMP. Resolution, metadata, temp
# placement, final metadata verification, and rename stay centralized here.
nano_env_atomic_rewrite_locked() {
    local env_file="${1:-}" lock_identity="${2:-}" writer="${3:-}"
    local had_xtrace=0 status=0 target="" rechecked_target="" lock_basis=""
    local lock_file="" locked=0 tmp="" directory="" metadata="" uid="" gid="" perms=""
    shift 3 2>/dev/null || true

    case "$-" in *x*) had_xtrace=1; set +x ;; esac
    while :; do
        if [[ -z "$env_file" || -z "$writer" ]] || ! declare -F "$writer" >/dev/null 2>&1; then
            printf 'generated-secrets: nano_env_atomic_rewrite_locked requires ENV_FILE LOCK_IDENTITY WRITER.\n' >&2
            status=2
            break
        fi
        target="$(nano_secret_resolve_target "$env_file")" || status=1
        if (( status != 0 )) || [[ ! -f "$target" ]]; then
            printf 'generated-secrets: env target cannot be resolved as a regular file; no rewrite was attempted.\n' >&2
            status=1
            break
        fi
        metadata="$(nano_secret_metadata "$target")" || status=1
        if (( status != 0 )); then
            printf 'generated-secrets: cannot inspect env metadata; no rewrite was attempted.\n' >&2
            break
        fi
        read -r uid gid perms <<< "$metadata"
        if [[ -n "$lock_identity" ]]; then
            lock_basis="$(nano_secret_resolve_target "$lock_identity")" || {
                directory="$(cd "$(dirname "$lock_identity")" 2>/dev/null && pwd -P)" || status=1
                lock_basis="$directory/$(basename "$lock_identity")"
            }
        else
            lock_basis="$target"
        fi
        (( status == 0 )) || break
        lock_file="${lock_basis}.nano-generated-secrets.lock"
        if ! nano_secret_lock_acquire "$lock_file" "$uid" "$gid"; then
            printf 'generated-secrets: cannot acquire env lock %s; no rewrite was attempted.\n' "$lock_file" >&2
            status=1
            break
        fi
        locked=1
        rechecked_target="$(nano_secret_resolve_target "$env_file")" || status=1
        if (( status != 0 )) || [[ "$rechecked_target" != "$target" || ! -f "$target" ]]; then
            printf 'generated-secrets: env target changed while acquiring its lock; no rewrite was attempted. Retry.\n' >&2
            status=1
            break
        fi
        metadata="$(nano_secret_metadata "$target")" || status=1
        (( status == 0 )) || break
        read -r uid gid perms <<< "$metadata"
        directory="$(dirname "$target")"
        tmp="$(mktemp "$directory/.env.tmp.XXXXXX")" || status=1
        (( status == 0 )) || break
        if ! nano_secret_apply_metadata "$tmp" "$uid" "$gid" "$perms" \
            || ! chmod u+rw "$tmp" 2>/dev/null; then
            printf 'generated-secrets: cannot prepare a metadata-preserving atomic replacement; no rewrite was attempted.\n' >&2
            status=1
            break
        fi
        if ! "$writer" "$target" "$tmp" "$@"; then
            status=1
            break
        fi
        if ! nano_secret_atomic_replace "$tmp" "$target" "$uid" "$gid" "$perms"; then
            status=1
            break
        fi
        tmp=""
        break
    done
    [[ -z "$tmp" ]] || rm -f "$tmp"
    (( locked == 0 )) || nano_secret_lock_release
    if (( had_xtrace )); then set -x; fi
    return "$status"
}

nano_env_managed_block_writer() {
    local target="$1" tmp="$2" content="$3" begin_marker="$4" end_marker="$5"
    local line state=0 seen=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == "$begin_marker" ]]; then
            (( state == 0 && seen == 0 )) || {
                printf 'generated-secrets: malformed managed block; refusing to rewrite the env file.\n' >&2
                return 1
            }
            state=1
            seen=1
        elif [[ "$line" == "$end_marker" ]]; then
            (( state == 1 )) || {
                printf 'generated-secrets: malformed managed block; refusing to rewrite the env file.\n' >&2
                return 1
            }
            state=0
        fi
    done < "$target"
    (( state == 0 )) || {
        printf 'generated-secrets: malformed managed block; refusing to rewrite the env file.\n' >&2
        return 1
    }

    printf '%s\n' "$begin_marker" > "$tmp" || return 1
    cat "$content" >> "$tmp" || return 1
    printf '%s\n' "$end_marker" >> "$tmp" || return 1
    state=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == "$begin_marker" ]]; then state=1; continue; fi
        if [[ "$line" == "$end_marker" && "$state" == 1 ]]; then state=0; continue; fi
        (( state == 1 )) || printf '%s\n' "$line" >> "$tmp" || return 1
    done < "$target"
}

nano_replace_managed_env_block() {
    local env_file="$1" content="$2" begin_marker="$3" end_marker="$4"
    nano_env_atomic_rewrite_locked "$env_file" "$env_file" nano_env_managed_block_writer \
        "$content" "$begin_marker" "$end_marker"
}

nano_secret_add_missing() {
    local list="$1" key="$2"
    if [[ -n "$list" ]]; then
        printf '%s:%s' "$list" "$key"
    else
        printf '%s' "$key"
    fi
}

nano_backfill_generated_secrets() {
    local env_file="${1:-}" mode="${2:-}" lock_identity="${3:-}"
    local had_xtrace=0 status=0 target="" rechecked_target="" directory=""
    local lock_basis="" lock_file="" locked=0 tmp="" uid="" gid="" perms=""
    local actual_metadata="" key="" secret="" shared_missing="" local_missing="" missing=""
    local old_ifs="" last_is_newline="" keeper_password=""

    case "$-" in *x*) had_xtrace=1; set +x ;; esac
    NANO_BACKFILLED_SECRET_KEYS=""

    while :; do
        if [[ -z "$env_file" || ! "$mode" =~ ^(generate|validate-only)$ ]]; then
            printf 'generated-secrets: usage: nano_backfill_generated_secrets ENV_FILE generate|validate-only [LOCK_IDENTITY]\n' >&2
            status=2
            break
        fi
        target="$(nano_secret_resolve_target "$env_file")" || {
            printf 'generated-secrets: cannot resolve env target %s; no secrets were read.\n' "$env_file" >&2
            status=1
            break
        }
        if [[ ! -f "$target" ]]; then
            printf 'generated-secrets: env target %s is not a regular file; no secrets were read.\n' "$target" >&2
            status=1
            break
        fi

        actual_metadata="$(nano_secret_metadata "$target")" || {
            printf 'generated-secrets: cannot inspect uid, gid, and mode for %s; no secrets were read.\n' "$target" >&2
            status=1
            break
        }
        read -r uid gid perms <<< "$actual_metadata"

        if [[ "$mode" == validate-only ]]; then
            while IFS= read -r key; do
                nano_secret_effective_nonempty "$target" "$key" \
                    || shared_missing="$(nano_secret_add_missing "$shared_missing" "$key")"
            done < <(nano_cluster_shared_secret_keys)
            while IFS= read -r key; do
                nano_secret_effective_nonempty "$target" "$key" \
                    || local_missing="$(nano_secret_add_missing "$local_missing" "$key")"
            done < <(nano_host_local_secret_keys)
            if [[ -n "$shared_missing" ]]; then
                printf 'generated-secrets: missing cluster-shared generated secret(s): %s. Copy the updated shared .env from the canonical app/prepare host to this host, then retry.\n' \
                    "${shared_missing//:/, }" >&2
                status=1
            elif [[ -n "$local_missing" ]]; then
                printf 'generated-secrets: missing host-local generated secret(s): %s. Run the canonical host preparation for this host, then retry.\n' \
                    "${local_missing//:/, }" >&2
                status=1
            fi
            break
        fi

        if [[ -n "$lock_identity" ]]; then
            lock_basis="$(nano_secret_resolve_target "$lock_identity")" || {
                directory="$(cd "$(dirname "$lock_identity")" 2>/dev/null && pwd -P)" || status=1
                lock_basis="$directory/$(basename "$lock_identity")"
            }
        else
            lock_basis="$target"
        fi
        (( status == 0 )) || {
            printf 'generated-secrets: cannot resolve lock identity %s; no secrets were read.\n' "$lock_identity" >&2
            break
        }
        lock_file="${lock_basis}.nano-generated-secrets.lock"
        if ! nano_secret_lock_acquire "$lock_file" "$uid" "$gid"; then
            printf 'generated-secrets: cannot acquire env lock %s; no secrets were read.\n' "$lock_file" >&2
            status=1
            break
        fi
        locked=1

        rechecked_target="$(nano_secret_resolve_target "$env_file")" || status=1
        if (( status != 0 )) || [[ "$rechecked_target" != "$target" || ! -f "$target" ]]; then
            printf 'generated-secrets: env target changed while acquiring its lock; no secrets were read. Retry.\n' >&2
            status=1
            break
        fi

        actual_metadata="$(nano_secret_metadata "$target")" || {
            printf 'generated-secrets: cannot inspect uid, gid, and mode for %s; no secrets were read.\n' "$target" >&2
            status=1
            break
        }
        read -r uid gid perms <<< "$actual_metadata"
        directory="$(dirname "$target")"
        tmp="$(mktemp "$directory/.env.tmp.XXXXXX")" || {
            printf 'generated-secrets: cannot create an atomic temp file beside %s; no secrets were read.\n' "$target" >&2
            status=1
            break
        }
        if ! nano_secret_apply_metadata "$tmp" "$uid" "$gid" "$perms"; then
            printf 'generated-secrets: cannot preserve uid=%s gid=%s mode=%s for %s; fix ownership/directory permissions and retry. No secrets were read.\n' \
                "$uid" "$gid" "$perms" "$target" >&2
            status=1
            break
        fi
        chmod u+rw "$tmp" 2>/dev/null || {
            printf 'generated-secrets: cannot prepare a writable atomic temp file for %s; no secrets were read.\n' "$target" >&2
            status=1
            break
        }

        while IFS= read -r key; do
            nano_secret_effective_nonempty "$target" "$key" \
                || shared_missing="$(nano_secret_add_missing "$shared_missing" "$key")"
        done < <(nano_cluster_shared_secret_keys)
        while IFS= read -r key; do
            nano_secret_effective_nonempty "$target" "$key" \
                || local_missing="$(nano_secret_add_missing "$local_missing" "$key")"
        done < <(nano_host_local_secret_keys)

        missing="$shared_missing"
        [[ -z "$local_missing" ]] || missing="${missing}${missing:+:}${local_missing}"
        [[ -n "$missing" ]] || break
        if [[ ":$missing:" == *:NANO_KEEPER_PASSWORD:* \
            && ":$missing:" != *:NANO_KEEPER_SUPER_DIGEST:* ]] \
            || [[ ":$missing:" != *:NANO_KEEPER_PASSWORD:* \
            && ":$missing:" == *:NANO_KEEPER_SUPER_DIGEST:* ]]; then
            printf 'generated-secrets: NANO_KEEPER_PASSWORD and NANO_KEEPER_SUPER_DIGEST are a coupled pair; both must be present or both absent. Copy the updated shared .env from the canonical app/prepare host to this host, then retry.\n' >&2
            status=1
            break
        fi

        if ! cat "$target" > "$tmp"; then
            status=1
            break
        fi
        if [[ -s "$target" ]]; then
            last_is_newline="$(tail -c 1 "$target" | wc -l | tr -d '[:space:]')"
            [[ "$last_is_newline" == 1 ]] || printf '\n' >> "$tmp" || { status=1; break; }
        fi
        old_ifs="$IFS"
        IFS=:
        for key in $missing; do
            if [[ "$key" == NANO_KEEPER_SUPER_DIGEST ]]; then
                if [[ -z "$keeper_password" ]] \
                    || ! secret="nano:$(printf '%s' "$keeper_password" | openssl dgst -sha1 -binary | openssl base64 -A)"; then
                    status=1
                    break
                fi
            elif ! secret="$(openssl rand -hex 32)" || [[ -z "$secret" ]]; then
                status=1
                break
            fi
            [[ "$key" != NANO_KEEPER_PASSWORD ]] || keeper_password="$secret"
            if ! printf '%s=%s\n' "$key" "$secret" >> "$tmp"; then
                status=1
                break
            fi
        done
        IFS="$old_ifs"
        (( status == 0 )) || break
        if ! nano_secret_atomic_replace "$tmp" "$target" "$uid" "$gid" "$perms"; then
            status=1
            break
        fi
        tmp=""
        # Referenced by scripts that source this library; standalone shellcheck
        # cannot see those consumers.
        # shellcheck disable=SC2034
        NANO_BACKFILLED_SECRET_KEYS="${missing//:/, }"
        break
    done

    secret=""
    keeper_password=""
    [[ -z "$tmp" ]] || rm -f "$tmp"
    (( locked == 0 )) || nano_secret_lock_release
    if (( had_xtrace )); then set -x; fi
    return "$status"
}
