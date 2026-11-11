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
# Known public values (security review 2026-11-08):
#   A value nano itself shipped as a default or example
#   (config/known-public-secrets.txt, kept identical to
#   nanosiem-core/src/known_public_secrets.rs by a unit test) protects nothing.
#   In generate mode it is replaced before any service starts:
#     JWT_SECRET, NANO_VECTOR_CONFIG_DELIVERY_TOKEN  regenerated (logins sign in
#                                                    again; consumers get the
#                                                    new token from this .env)
#     NANOSIEM_ENCRYPTION_KEY                        migrated to a key ring: a
#                                                    generated active key plus
#                                                    the old value as decrypt-only
#                                                    legacy-0, so every stored
#                                                    credential still decrypts
#                                                    and is re-encrypted in the
#                                                    background
#     VECTOR_AUTH_TOKEN                              regenerated (NAN-5013, v2.0.6:
#                                                    nano-api refuses a public
#                                                    install token on every lane,
#                                                    so keeping it protects
#                                                    nothing and accepts nothing;
#                                                    named per-source tokens are
#                                                    unaffected)
#   CHANGE_ME* placeholders are always regenerated (nothing real holds one),
#   except database passwords. Known database passwords are reported only
#   (NANO_PUBLIC_DB_PASSWORD_KEYS): the databases keep the password their data
#   was initialised with, and ClickHouse dictionaries embed it.
#   NANO_ROTATED_SECRET_KEYS names what was replaced. NANO_PUBLIC_SECRET_KEYS
#   names a public VECTOR_AUTH_TOKEN a validate-only data host kept (warned:
#   nothing there reads it); generate mode never keeps one since v2.0.6. In
#   validate-only mode any other public cluster-shared value fails like a
#   missing one (copy the canonical host's .env).
#
# Transitional keys (nano_transitional_secret_keys) are generated like the
# others, but a role host whose copied .env predates them only gets a warning:
# the services fall back to their v2.0.x behaviour until the updated shared
# .env is copied over.
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
        NANO_KEEPER_SUPER_DIGEST \
        NANO_VECTOR_CONFIG_DELIVERY_TOKEN \
        NANO_PG_REPLICATION_PASSWORD \
        NANO_PATRONI_API_PASSWORD \
        NANO_SETUP_TOKEN \
        NANO_SERVICE_TOKEN \
        NANO_GRAFANA_ADMIN_PASSWORD
}

# Cluster-shared keys added after v2.0.0. A role host missing one warns
# instead of failing; see the contract above.
# NANO_SETUP_TOKEN (NAN-5237) gates first-admin setup on nano-api; only app
# hosts read it, and an initialized install never needs it.
nano_transitional_secret_keys() {
    # NAN-5214: the PostgreSQL HA credentials are generated once by the
    # canonical app host. Only HA services read them (and refuse to start
    # without them), so an older copied .env warns instead of failing.
    # NAN-5250: NANO_SERVICE_TOKEN (the /metrics bearer credential for
    # Prometheus) and NANO_GRAFANA_ADMIN_PASSWORD (the monitoring role's
    # Grafana admin; never a default). Without them metrics stay closed and
    # the monitoring profile refuses to start, so an older copied .env warns.
    printf '%s\n' NANO_VECTOR_CONFIG_DELIVERY_TOKEN NANO_PG_REPLICATION_PASSWORD NANO_PATRONI_API_PASSWORD NANO_SETUP_TOKEN \
        NANO_SERVICE_TOKEN NANO_GRAFANA_ADMIN_PASSWORD
}

nano_secret_is_transitional() {
    local wanted="$1" key
    while IFS= read -r key; do
        [[ "$key" == "$wanted" ]] && return 0
    done < <(nano_transitional_secret_keys)
    return 1
}

# The known-public kind tag for an env key, or failure if none applies.
nano_secret_public_kind() {
    case "$1" in
        JWT_SECRET) printf 'jwt' ;;
        NANOSIEM_ENCRYPTION_KEY) printf 'encryption_key' ;;
        VECTOR_AUTH_TOKEN) printf 'vector_install_token' ;;
        NANO_VECTOR_CONFIG_DELIVERY_TOKEN) printf 'vector_config_delivery_token' ;;
        POSTGRES_PASSWORD|CLICKHOUSE_PASSWORD|CLICKHOUSE_ADMIN_PASSWORD|CLICKHOUSE_VECTOR_PASSWORD \
            | CLICKHOUSE_INGEST_PASSWORD|CLICKHOUSE_RAWSQL_PASSWORD|CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD)
            printf 'db_password' ;;
        *) return 1 ;;
    esac
}

nano_known_public_secrets_file() {
    if [[ -n "${NANO_KNOWN_PUBLIC_SECRETS_FILE:-}" ]]; then
        printf '%s\n' "$NANO_KNOWN_PUBLIC_SECRETS_FILE"
        return 0
    fi
    local lib_dir
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)" || return 1
    printf '%s\n' "$lib_dir/../../config/known-public-secrets.txt"
}

# The effective (last) single-line value of KEY in FILE, surrounding quotes
# removed. Only used to compare against known public values, which are all
# simple single-line strings; never printed by callers.
nano_secret_effective_value() {
    local file="$1" key="$2"
    awk -v wanted="$key" '
        {
            line = $0
            sub(/\r$/, "", line)
            sub(/^[ \t]*export[ \t]+/, "", line)
            if (match(line, "^[ \t]*" wanted "[ \t]*=")) {
                value = substr(line, RLENGTH + 1)
                sub(/^[ \t]+/, "", value)
                sub(/[ \t]+$/, "", value)
                if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
                    value = substr(value, 2, length(value) - 2)
                }
                found = 1
            }
        }
        END { if (found) print value }
    ' "$file"
}

# Success when KEY's effective value in FILE is a known public value.
# The comparison runs in this shell: the value is never passed to another
# process's command line (where /proc/<pid>/cmdline would show it).
nano_secret_is_known_public() {
    local file="$1" key="$2" kind list value line
    kind="$(nano_secret_public_kind "$key")" || return 1
    list="$(nano_known_public_secrets_file)" || return 1
    [[ -r "$list" ]] || return 1
    value="$(nano_secret_effective_value "$file" "$key")"
    [[ -n "$value" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == "$kind $value" ]] && { value=""; return 0; }
    done < "$list"
    value=""
    return 1
}

# Success when KEY's effective value in FILE is a CHANGE_ME* placeholder.
# Nothing real can hold one, so it is regenerated outright.
nano_secret_is_placeholder() {
    local value
    value="$(nano_secret_effective_value "$1" "$2")"
    case "$value" in
        CHANGE_ME|CHANGE_ME_GENERATED|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32) return 0 ;;
    esac
    return 1
}

# Print a key-ring JSON whose active key is freshly generated and which keeps
# OLD as the explicit decrypt-only `legacy-0` entry (the shape the credential
# key ring accepts for public legacy material).
nano_secret_encryption_ring_json() {
    local old="$1" new_key id
    [[ "$old" =~ ^[A-Za-z0-9_.!-]+$ ]] || return 1
    new_key="$(openssl rand -base64 32 | tr -d '\n')" || return 1
    [[ -n "$new_key" ]] || return 1
    id="k-$(date -u +%Y%m%d)"
    printf '{"version":1,"active":"%s","keys":[{"id":"%s","key":"%s"},{"id":"legacy-0","legacy":"%s"}],"legacy_decrypt_ids":["legacy-0"]}' \
        "$id" "$id" "$new_key" "$old"
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
    # A marker line may end in CR (an .env edited on Windows): match it all the
    # same, or the old block would survive below the new one and keep winning.
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
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
        if [[ "${line%$'\r'}" == "$begin_marker" ]]; then state=1; continue; fi
        if [[ "${line%$'\r'}" == "$end_marker" && "$state" == 1 ]]; then state=0; continue; fi
        (( state == 1 )) || printf '%s\n' "$line" >> "$tmp" || return 1
    done < "$target"
}

nano_replace_managed_env_block() {
    local env_file="$1" content="$2" begin_marker="$3" end_marker="$4"
    nano_env_atomic_rewrite_locked "$env_file" "$env_file" nano_env_managed_block_writer \
        "$content" "$begin_marker" "$end_marker"
}

# Set KEY=VALUE pairs in an env file IN PLACE: the first line for each key is
# replaced where it stands, any later duplicate of it is dropped, and a key
# that has no line yet is appended at the end. Line order is preserved, so a
# re-run that sets the same values leaves the file byte-identical and hosts
# that copy .env stay identical (NAN-5251: the earlier drop-and-append moved
# keys to the end and reordered copied files; appends duplicated keys).
# Atomic, locked, metadata-preserving, symlink-safe.
nano_env_set_keys_writer() {
    local target="$1" tmp="$2" line bare i matched
    shift 2
    local -a kvs=("$@") keys=() written=()
    for i in "${!kvs[@]}"; do
        keys[i]="${kvs[i]%%=*}"
        written[i]=0
    done
    while IFS= read -r line || [[ -n "$line" ]]; do
        matched=-1
        # Match `KEY=`, `  KEY=` and `export KEY=` alike (Compose and the
        # shell both read those), so no form survives as a second assignment.
        bare="${line#"${line%%[![:space:]]*}"}"
        if [[ "$bare" == export[[:space:]]* ]]; then
            bare="${bare#export}"
            bare="${bare#"${bare%%[![:space:]]*}"}"
        fi
        for i in "${!keys[@]}"; do
            [[ "$bare" == "${keys[i]}="* ]] && { matched=$i; break; }
        done
        if (( matched < 0 )); then
            printf '%s\n' "$line" >> "$tmp" || return 1
        elif (( written[matched] == 0 )); then
            printf '%s\n' "${kvs[matched]}" >> "$tmp" || return 1
            written[matched]=1
        fi
    done < "$target"
    for i in "${!kvs[@]}"; do
        (( written[i] )) || printf '%s\n' "${kvs[i]}" >> "$tmp" || return 1
    done
}

# Collapse duplicate assignments in an env file (NAN-5263). An earlier
# installer (v2.0.8) could append a second NANO_LICENSE_MODE line; Compose and
# env readers use the LAST assignment, so that value is kept, at the FIRST
# line's position (the same place nano_env_set_keys writes). Every host
# collapses the same way, so copied .env files stay byte-identical. Prints the
# collapsed key names (never values), comma-separated; nothing when clean.
#
# Lines inside an installer-managed block (`# BEGIN NANO ...` / `# END NANO
# ...`, e.g. the auto-sizing block) are neither counted nor rewritten: a key
# assigned there AND again below is the documented operator override, not a
# duplicate. Collapsing it into the block line used to let the next block
# rewrite silently drop the operator's value (NAN-5282).
nano_env_collapse_scan() {
    # Prints each key (never a value) assigned more than once outside the
    # installer-managed blocks of $1, in first-seen order.
    awk '
        /^# BEGIN NANO / { block = 1; next }
        /^# END NANO / { block = 0; next }
        block { next }
        {
            bare = $0
            sub(/^[ \t]*/, "", bare)
            sub(/^export[ \t]+/, "", bare)
            if (match(bare, /^[A-Za-z_][A-Za-z0-9_]*=/)) {
                key = substr(bare, 1, RLENGTH - 1)
                count[key]++
                if (!(key in order)) { order[key] = ++n; keys[n] = key }
            }
        }
        END {
            for (i = 1; i <= n; i++) if (count[keys[i]] > 1) print keys[i]
        }
    ' "$1"
}

# The kept line goes at the first outside occurrence that follows the key's
# last managed-block assignment, never above it: an operator line above the
# block plus one below must stay below the block, or the block value would take
# effect instead (the block is rewritten only by the installer, not here).
nano_env_collapse_writer() {
    local target="$1" tmp="$2"
    awk '
        NR == FNR {
            if ($0 ~ /^# BEGIN NANO /) { block = 1; next }
            if ($0 ~ /^# END NANO /) { block = 0; next }
            bare = $0
            sub(/^[ \t]*/, "", bare)
            sub(/^export[ \t]+/, "", bare)
            if (match(bare, /^[A-Za-z_][A-Za-z0-9_]*=/)) {
                key = substr(bare, 1, RLENGTH - 1)
                if (block) { managed[key] = FNR; next }
                count[key]++
                last[key] = bare
                if (!(key in anchor) || ((key in managed) && anchor[key] < managed[key]))
                    anchor[key] = FNR
            }
            next
        }
        /^# BEGIN NANO / { block = 1; print; next }
        /^# END NANO / { block = 0; print; next }
        block { print; next }
        {
            bare = $0
            sub(/^[ \t]*/, "", bare)
            sub(/^export[ \t]+/, "", bare)
            if (match(bare, /^[A-Za-z_][A-Za-z0-9_]*=/)) {
                key = substr(bare, 1, RLENGTH - 1)
                if (count[key] > 1) {
                    if (FNR == anchor[key]) print last[key]
                    next
                }
            }
            print
        }
    ' "$target" "$target" > "$tmp"
}

nano_env_collapse_duplicates() {
    local env_file="$1" had_xtrace=0 names
    [[ -f "$env_file" ]] || return 0
    case "$-" in *x*) had_xtrace=1; set +x ;; esac
    names=$(nano_env_collapse_scan "$env_file" | paste -sd, - | sed 's/,/, /g')
    if [[ -n "$names" ]]; then
        nano_env_atomic_rewrite_locked "$env_file" "$env_file" nano_env_collapse_writer \
            || { (( had_xtrace )) && set -x; return 1; }
        printf '%s\n' "$names"
    fi
    if (( had_xtrace )); then set -x; fi
    return 0
}

nano_env_set_keys() {
    local env_file="$1"
    shift
    nano_env_atomic_rewrite_locked "$env_file" "$env_file" nano_env_set_keys_writer "$@"
}

# Names (never values) of the keys whose assignments differ between BEFORE
# (the earlier file content, as a string) and ENV_FILE, comma-separated and
# sorted. "line order" is reported when the bytes differ but no key's
# assignments do (reordered lines, edited comments). Prints nothing when the
# content is identical. Values reach awk on stdin only, never on argv.
nano_env_changed_keys() {
    local before="$1" env_file="$2" had_xtrace=0 status=0
    case "$-" in *x*) had_xtrace=1; set +x ;; esac
    {
        printf '%s' "$before" | awk '{ print "B " $0 }'
        awk '{ print "A " $0 }' "$env_file"
    } | awk '
        {
            side = substr($0, 1, 1)
            line = substr($0, 3)
            all[side] = all[side] "\n" line
            name = line
            sub(/^[ \t]*export[ \t]+/, "", name)
            if (match(name, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/)) {
                name = substr(name, 1, RLENGTH)
                sub(/[ \t]*=$/, "", name)
                gsub(/[ \t]/, "", name)
                seen[name] = 1
                val[side, name] = val[side, name] "\n" line
            }
        }
        END {
            n = 0
            for (k in seen) if (val["B", k] != val["A", k]) { print k; n++ }
            if (n == 0 && all["B"] != all["A"]) print "line order"
        }
    ' | LC_ALL=C sort | paste -sd, - | sed 's/,/, /g' || status=1
    if (( had_xtrace )); then set -x; fi
    return "$status"
}

# Every key in a role-split .env is shared: the file must stay byte-identical
# on every host (host-specific values live in .nano-role.env and the host
# identity file). Prints the operator notice when ENV_FILE differs from
# BEFORE, nothing otherwise. Used by install.sh on every host role.
nano_shared_env_change_notice() {
    local before="$1" env_file="$2" changed
    changed="$(nano_env_changed_keys "$before" "$env_file")" || return 1
    [[ -n "$changed" ]] || return 0
    printf "The shared .env changed on this host (%s): copy this host's .env to every other host (app, ingest, ClickHouse, Keeper and postgres) before the next install.sh run anywhere, then check that 'sha256sum .env' matches on every host.\n" "$changed"
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
    local rotate="" public_kept="" public_db="" kind="" old_value="" transitional_missing=""

    case "$-" in *x*) had_xtrace=1; set +x ;; esac
    NANO_BACKFILLED_SECRET_KEYS=""
    NANO_ROTATED_SECRET_KEYS=""
    NANO_PUBLIC_SECRET_KEYS=""
    NANO_PUBLIC_DB_PASSWORD_KEYS=""

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
                if ! nano_secret_effective_nonempty "$target" "$key" \
                    || nano_secret_is_known_public "$target" "$key"; then
                    if nano_secret_effective_nonempty "$target" "$key" \
                        && [[ "$(nano_secret_public_kind "$key")" == db_password ]]; then
                        public_db="$(nano_secret_add_missing "$public_db" "$key")"
                    elif [[ "$key" == VECTOR_AUTH_TOKEN ]] \
                        && [[ "${NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG:-1}" == 0 ]] \
                        && nano_secret_effective_nonempty "$target" "$key"; then
                        # NAN-5013: a data-only host runs nothing that reads
                        # the install token. Warn, so the documented
                        # data-roles-first upgrade order still works.
                        public_kept="$(nano_secret_add_missing "$public_kept" "$key")"
                    elif nano_secret_is_transitional "$key"; then
                        transitional_missing="$(nano_secret_add_missing "$transitional_missing" "$key")"
                    else
                        shared_missing="$(nano_secret_add_missing "$shared_missing" "$key")"
                    fi
                fi
            done < <(nano_cluster_shared_secret_keys)
            # NAN-5148: a present-but-public delivery token is sent as is and
            # nano-api refuses it, so this host's Vector would get no config
            # after the upgrade: refuse here instead of warning. (A public
            # install token is itself a shared_missing failure since NAN-5013.)
            # A host with no Vector config consumer (data roles) sets
            # NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG=0 and only gets the warning.
            if [[ "${NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG:-1}" != 0 ]] \
                && [[ ":$transitional_missing:" == *:NANO_VECTOR_CONFIG_DELIVERY_TOKEN:* ]] \
                && nano_secret_effective_nonempty "$target" NANO_VECTOR_CONFIG_DELIVERY_TOKEN; then
                printf 'generated-secrets: this host'"'"'s .env has no usable NANO_VECTOR_CONFIG_DELIVERY_TOKEN (it is a placeholder, which nano-api refuses for Vector config delivery), so Vector on this host would stop receiving config. Fix: on the canonical app/prepare host run install.sh (or NANO_PREPARE_ONLY=1 install.sh) so it generates NANO_VECTOR_CONFIG_DELIVERY_TOKEN in its .env, securely copy that updated shared .env to this host, then retry.\n' >&2
                status=1
                break
            fi
            if [[ -n "$public_kept" ]]; then
                printf 'generated-secrets: warning: this host'"'"'s .env holds a publicly known VECTOR_AUTH_TOKEN, which nano refuses since v2.0.6. Copy the updated shared .env from the canonical app/prepare host (whose install.sh run replaces it) to this host.\n' >&2
            fi
            if [[ -n "$transitional_missing" ]]; then
                printf 'generated-secrets: warning: this host'"'"'s .env predates %s. Services keep their v2.0.x fallback until you copy the updated shared .env from the canonical app/prepare host to this host.\n' \
                    "${transitional_missing//:/, }" >&2
            fi
            # shellcheck disable=SC2034
            NANO_PUBLIC_SECRET_KEYS="${public_kept//:/, }"
            # shellcheck disable=SC2034
            NANO_PUBLIC_DB_PASSWORD_KEYS="${public_db//:/, }"
            while IFS= read -r key; do
                nano_secret_effective_nonempty "$target" "$key" \
                    || local_missing="$(nano_secret_add_missing "$local_missing" "$key")"
            done < <(nano_host_local_secret_keys)
            if [[ -n "$shared_missing" ]]; then
                printf 'generated-secrets: missing or publicly known cluster-shared generated secret(s): %s. Copy the updated shared .env from the canonical app/prepare host to this host, then retry.\n' \
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
            if ! nano_secret_effective_nonempty "$target" "$key"; then
                shared_missing="$(nano_secret_add_missing "$shared_missing" "$key")"
            elif nano_secret_is_known_public "$target" "$key"; then
                kind="$(nano_secret_public_kind "$key")"
                if [[ "$kind" == db_password ]]; then
                    # The database keeps the password it was initialised with,
                    # so .env cannot change alone: report it.
                    public_db="$(nano_secret_add_missing "$public_db" "$key")"
                else
                    # NAN-5013: a public VECTOR_AUTH_TOKEN is rotated too. nano
                    # refuses it on every lane, so senders holding it are cut
                    # off either way; named per-source tokens keep working.
                    rotate="$(nano_secret_add_missing "$rotate" "$key")"
                fi
            fi
        done < <(nano_cluster_shared_secret_keys)
        while IFS= read -r key; do
            nano_secret_effective_nonempty "$target" "$key" \
                || local_missing="$(nano_secret_add_missing "$local_missing" "$key")"
        done < <(nano_host_local_secret_keys)
        # shellcheck disable=SC2034
        NANO_PUBLIC_SECRET_KEYS="${public_kept//:/, }"
        # shellcheck disable=SC2034
        NANO_PUBLIC_DB_PASSWORD_KEYS="${public_db//:/, }"

        missing="$shared_missing"
        [[ -z "$local_missing" ]] || missing="${missing}${missing:+:}${local_missing}"
        [[ -n "$missing" || -n "$rotate" ]] || break
        if [[ ":$missing:" == *:NANO_KEEPER_PASSWORD:* \
            && ":$missing:" != *:NANO_KEEPER_SUPER_DIGEST:* ]] \
            || [[ ":$missing:" != *:NANO_KEEPER_PASSWORD:* \
            && ":$missing:" == *:NANO_KEEPER_SUPER_DIGEST:* ]]; then
            printf 'generated-secrets: NANO_KEEPER_PASSWORD and NANO_KEEPER_SUPER_DIGEST are a coupled pair; both must be present or both absent. Copy the updated shared .env from the canonical app/prepare host to this host, then retry.\n' >&2
            status=1
            break
        fi

        if [[ -n "$rotate" ]]; then
            # Drop every assignment of a rotated key; the replacement is
            # appended below, so exactly one assignment remains.
            if ! awk -v keys=":$rotate:" '
                {
                    line = $0
                    sub(/^[ \t]*export[ \t]+/, "", line)
                    if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/)) {
                        name = substr(line, 1, RLENGTH)
                        sub(/[ \t]*=$/, "", name)
                        gsub(/[ \t]/, "", name)
                        if (index(keys, ":" name ":")) next
                    }
                    print
                }
            ' "$target" > "$tmp"; then
                status=1
                break
            fi
        elif ! cat "$target" > "$tmp"; then
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
        old_ifs="$IFS"
        IFS=:
        for key in $rotate; do
            if [[ "$key" == NANOSIEM_ENCRYPTION_KEY ]] && ! nano_secret_is_placeholder "$target" "$key"; then
                # A real shipped key may have encrypted credentials: keep it
                # decrypt-only. (A placeholder never encrypted anything and
                # is plain-regenerated below.)
                old_value="$(nano_secret_effective_value "$target" "$key")"
                if ! secret="$(nano_secret_encryption_ring_json "$old_value")" || [[ -z "$secret" ]]; then
                    status=1
                    break
                fi
                # Single quotes: Compose reads the JSON literally.
                if ! printf "%s='%s'\n" "$key" "$secret" >> "$tmp"; then
                    status=1
                    break
                fi
                continue
            fi
            if ! secret="$(openssl rand -hex 32)" || [[ -z "$secret" ]]; then
                status=1
                break
            fi
            if ! printf '%s=%s\n' "$key" "$secret" >> "$tmp"; then
                status=1
                break
            fi
        done
        IFS="$old_ifs"
        old_value=""
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
        # shellcheck disable=SC2034
        NANO_ROTATED_SECRET_KEYS="${rotate//:/, }"
        break
    done

    secret=""
    old_value=""
    keeper_password=""
    [[ -z "$tmp" ]] || rm -f "$tmp"
    (( locked == 0 )) || nano_secret_lock_release
    if (( had_xtrace )); then set -x; fi
    return "$status"
}
