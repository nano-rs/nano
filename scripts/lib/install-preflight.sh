# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installer preflight checks that turn a late, misleading failure into an
# early, plain one (NAN-5509). install.sh sources this file once the sources
# exist; the caller provides log/ok/warn/fail.
#
#   nano_tls_overlay_requested  is docker-compose.tls.yml in the overlay list?
#   nano_tls_cert_check         the certificate files nginx's TLS config loads
#   nano_published_ports        host ports a rendered Compose graph publishes
#   nano_compose_project        the Compose project a rendered graph belongs to
#   nano_port_conflicts         which of them another process already holds
#   nano_firewall_summary       the inbound ports to open, for the summary
#   nano_running_compose_overlays  the overlays the running stack was started with

# The certificate pair docker-compose.tls.yml mounts at /etc/nginx/ssl
# (config/nginx/nginx.opensource-tls.conf: ssl_certificate / _key).
NANO_TLS_CERT_DIR_REL=config/nginx/ssl
NANO_TLS_EXPIRY_WARN_DAYS=14

# True when the overlay list ($1, space-separated) names the TLS overlay.
nano_tls_overlay_requested() {
    [[ " ${1:-} " == *" docker-compose.tls.yml "* ]]
}

# Checks fullchain.pem / privkey.pem under INSTALL_DIR/config/nginx/ssl.
# Returns 0 when nginx can load them; otherwise prints one plain sentence
# (what is wrong and how to fix it) on stdout and returns 1. Warns (via warn,
# on stderr: callers capture stdout) when the certificate expires within
# NANO_TLS_EXPIRY_WARN_DAYS.
nano_tls_cert_check() {
    local dir="$1" ssl cert key rel cert_pub key_pub enddate
    ssl="$dir/$NANO_TLS_CERT_DIR_REL"
    rel="$NANO_TLS_CERT_DIR_REL"
    cert="$ssl/fullchain.pem"
    key="$ssl/privkey.pem"
    local drop="or install over plain HTTP first: re-run without docker-compose.tls.yml in NANO_COMPOSE_OVERLAYS (NANO_COMPOSE_OVERLAYS= ./install.sh, and remove it from .env if it is recorded there) and add the overlay once the certificate is in place"
    if [[ ! -e "$cert" || ! -e "$key" ]]; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $(
            if [[ ! -e "$cert" && ! -e "$key" ]]; then printf 'the certificate and key are'
            elif [[ ! -e "$cert" ]]; then printf 'the certificate is'
            else printf 'the private key is'; fi
        ) missing. nginx loads them from $ssl: copy your certificate chain (leaf first, then intermediates, PEM) to $rel/fullchain.pem and its private key (PEM, no passphrase) to $rel/privkey.pem in $dir. For a test install, ./config/nginx/generate-ssl.sh makes a self-signed pair (browsers warn), $drop. Nothing was changed."
        return 1
    fi
    # NAN-5521: docker-compose.tls.yml bind-mounts the ssl directory, so a
    # symbolic link to a file outside it (certbot's live/ links) dangles inside
    # the nginx container even though it resolves here.
    local link target ssl_real
    ssl_real=$(cd "$ssl" 2>/dev/null && pwd -P) || ssl_real="$ssl"
    for link in "$cert" "$key"; do
        [[ -L "$link" ]] || continue
        target=$(cd "$(dirname "$link")" 2>/dev/null && cd "$(dirname "$(readlink "$link")")" 2>/dev/null && pwd -P) || target=""
        if [[ "$target" != "$ssl_real" ]]; then
            printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $rel/${link##*/} in $dir is a symbolic link to $(readlink "$link"), outside $rel. nginx sees only $rel (it is mounted into the container), so the link dangles there. Copy the real files instead (for certbot: cp -L /etc/letsencrypt/live/<domain>/fullchain.pem /etc/letsencrypt/live/<domain>/privkey.pem $ssl/, and again after each renewal), then re-run. Nothing was changed."
            return 1
        fi
    done
    if [[ ! -s "$cert" || ! -s "$key" ]]; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $([[ -s "$cert" ]] && printf '%s' "$rel/privkey.pem" || printf '%s' "$rel/fullchain.pem") in $dir is empty. Copy the PEM file there again, or $drop. Nothing was changed."
        return 1
    fi
    if [[ ! -r "$cert" || ! -r "$key" ]]; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but this user ($(id -un)) cannot read $([[ -r "$cert" ]] && printf '%s' "$rel/privkey.pem" || printf '%s' "$rel/fullchain.pem") in $dir, so the installer cannot check it. Make the files readable by the user that runs install.sh (for example: sudo chown $(id -un): $ssl/fullchain.pem $ssl/privkey.pem && chmod 600 $ssl/privkey.pem), then re-run. Nothing was changed."
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout </dev/null >/dev/null 2>&1; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $rel/fullchain.pem in $dir is not a PEM certificate (it should start with -----BEGIN CERTIFICATE-----). Convert it to PEM, or $drop. Nothing was changed."
        return 1
    fi
    # An encrypted key (nginx would stop at a passphrase prompt) fails here too.
    if ! key_pub=$(openssl pkey -in "$key" -pubout -passin pass: </dev/null 2>/dev/null) || [[ -z "$key_pub" ]]; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $rel/privkey.pem in $dir is not an unencrypted PEM private key. nginx cannot use a key with a passphrase: remove it (openssl pkey -in privkey.pem -out privkey.pem.new, then move privkey.pem.new over privkey.pem), or $drop. Nothing was changed."
        return 1
    fi
    cert_pub=$(openssl x509 -in "$cert" -noout -pubkey </dev/null 2>/dev/null || true)
    if [[ -z "$cert_pub" || "$cert_pub" != "$key_pub" ]]; then
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but $rel/privkey.pem in $dir does not belong to the certificate in $rel/fullchain.pem (their public keys differ). Copy the key that was issued with this certificate, and keep the leaf certificate first in fullchain.pem. Nothing was changed."
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout -checkend 0 </dev/null >/dev/null 2>&1; then
        enddate=$(openssl x509 -in "$cert" -noout -enddate </dev/null 2>/dev/null | sed 's/^notAfter=//')
        printf '%s\n' "HTTPS is on (docker-compose.tls.yml) but the certificate in $rel/fullchain.pem expired${enddate:+ on $enddate}. Renew it and copy the new fullchain.pem and privkey.pem there (if the date looks wrong, check this host's clock), then re-run. Nothing was changed."
        return 1
    fi
    if ! openssl x509 -in "$cert" -noout -checkend $(( NANO_TLS_EXPIRY_WARN_DAYS * 86400 )) </dev/null >/dev/null 2>&1; then
        enddate=$(openssl x509 -in "$cert" -noout -enddate </dev/null 2>/dev/null | sed 's/^notAfter=//')
        warn "The HTTPS certificate in $rel/fullchain.pem expires${enddate:+ on $enddate}, within $NANO_TLS_EXPIRY_WARN_DAYS days. Renew it, copy it there, and restart nginx (docker compose ... restart nginx)." >&2
    fi
    return 0
}

# Reads `docker compose config --format json` on stdin; prints one
# "<host_ip> <port> <protocol> <service>" line per published host port
# (host_ip "*" means every interface).
nano_published_ports() {
    python3 -I -c '
import json, sys
try:
    services = (json.load(sys.stdin) or {}).get("services") or {}
except ValueError:
    sys.exit(1)
seen = set()
for name in sorted(services):
    for port in services[name].get("ports") or []:
        if not isinstance(port, dict):
            continue
        published = str(port.get("published") or "")
        if not published.isdigit() or published == "0":
            continue
        row = (str(port.get("host_ip") or "*"), published, str(port.get("protocol") or "tcp"))
        if row in seen:
            continue
        seen.add(row)
        print(*row, name)
'
}

# True when a listener on local address LISTEN_ADDR ("0.0.0.0", "[::]", "*",
# "127.0.0.1", ...) blocks publishing on HOST_IP ("*" = every interface).
nano_port_addr_clashes() {
    local listen="$1" host_ip="$2"
    [[ "$host_ip" == "*" ]] && return 0
    case "$listen" in
        "*" | 0.0.0.0 | "[::]" | "::" | "[::ffff:0.0.0.0]") return 0 ;;
    esac
    [[ "$listen" == "$host_ip" || "$listen" == "[$host_ip]" ]]
}

# What listens on TCP PORT (where it clashes with HOST_IP) on this host, as a
# short description; nothing when the port is free. ss lists every listener
# but names the process only with privileges; lsof run as a plain user sees
# only that user's processes, so an empty answer falls through to a connect.
nano_port_listener() {
    local port="$1" host_ip="${2:-*}" local_addr rest process unnamed found=""
    unnamed="another process (see which: sudo ss -ltnp 'sport = :$port')"
    if command -v ss >/dev/null 2>&1; then
        # No -H: RHEL 7's ss lacks it; the header is skipped instead.
        while read -r local_addr rest; do
            nano_port_addr_clashes "${local_addr%:*}" "$host_ip" || continue
            process=$(printf '%s' "$rest" | sed -n 's/.*users:(("\([^"]*\)",pid=\([0-9]*\).*/\1 (pid \2)/p')
            found="${process:-$unnamed}"
            break
        done < <(ss -ltnp "sport = :$port" 2>/dev/null | awk 'NR > 1 { $1 = $2 = $3 = ""; sub(/^ +/, ""); print }')
        [[ -n "$found" ]] && printf '%s\n' "$found"
        return 0
    fi
    if command -v lsof >/dev/null 2>&1; then
        # Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (LISTEN).
        # NAN-5799: only a NAME of <addr>:PORT is a listener. BusyBox lsof
        # (Alpine, the docker:dind image) ignores -i/-s and lists every open
        # file as "PID EXE FD PATH"; reading those rows as listeners made
        # every published port look taken (by "docker-init").
        while read -r local_addr process; do
            nano_port_addr_clashes "${local_addr%:*}" "$host_ip" || continue
            found="$process"
            break
        # Real lsof always starts with its COMMAND header and prints
        # "TCP <addr>:PORT (LISTEN)" in $8..$10; BusyBox output has no header,
        # so it is dropped at line 1 (a spaced path could end in ":PORT").
        done < <(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null \
            | awk -v port="$port" 'NR == 1 { if ($1 != "COMMAND") exit; next }
                NF >= 10 && $2 ~ /^[0-9]+$/ && $8 == "TCP" && $9 ~ (":" port "$") && $10 == "(LISTEN)" { print $9, $1 " (pid " $2 ")" }')
        if [[ -n "$found" ]]; then
            printf '%s\n' "$found"
            return 0
        fi
    fi
    # NAN-5799: Linux without ss (Alpine/BusyBox) or a plain-user lsof that
    # cannot see root's listeners: the kernel's own socket tables list every
    # listener, every user, IPv4 and IPv6, and are readable without root.
    found=$(nano_proc_net_listener "$port" "$host_ip")
    if [[ -n "$found" ]]; then
        printf '%s\n' "$unnamed"
        return 0
    fi
    local probe probes=()
    if [[ "$host_ip" == "*" ]]; then
        probes=(127.0.0.1 ::1)
    else
        probe=${host_ip#[}; probes=("${probe%]}")
    fi
    for probe in "${probes[@]}"; do
        if (exec 3<>"/dev/tcp/$probe/$port") 2>/dev/null; then
            printf '%s\n' "$unnamed"
            return 0
        fi
    done
    return 0
}

# Prints the local address of the first TCP listener on PORT in
# /proc/net/tcp{,6} (NANO_PROC_NET_DIR in tests) that clashes with HOST_IP;
# nothing when there is none or the tables are not there (macOS).
nano_proc_net_listener() {
    local port="$1" host_ip="${2:-*}" dir="${NANO_PROC_NET_DIR:-/proc/net}" addr table tables=()
    for table in "$dir/tcp" "$dir/tcp6"; do
        [[ -r "$table" ]] && tables+=("$table")
    done
    (( ${#tables[@]} )) || return 0
    while read -r addr; do
        nano_port_addr_clashes "$addr" "$host_ip" || continue
        printf '%s\n' "$addr"
        return 0
    done < <(awk -v port="$port" '
        function hex(s,   i, n) { n = 0; s = toupper(s)
            for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789ABCDEF", substr(s, i, 1)) - 1
            return n }
        # st 0A = LISTEN; local_address is HEXADDR:HEXPORT, IPv4 bytes reversed.
        FNR > 1 && $4 == "0A" { split($2, a, ":"); if (hex(a[2]) != port) next
            h = a[1]
            if (length(h) == 8) { print hex(substr(h, 7, 2)) "." hex(substr(h, 5, 2)) "." hex(substr(h, 3, 2)) "." hex(substr(h, 1, 2)); next }
            if (h == "00000000000000000000000000000000") print "[::]"
            else if (h == "00000000000000000000000001000000") print "[::1]"
            else if (substr(h, 1, 24) == "0000000000000000FFFF0000") print hex(substr(h, 31, 2)) "." hex(substr(h, 29, 2)) "." hex(substr(h, 27, 2)) "." hex(substr(h, 25, 2))
            else print "[" h "]"
        }' "${tables[@]}" 2>/dev/null)
    return 0
}

# Reads `docker compose config --format json` on stdin; prints the Compose
# project name it resolved (COMPOSE_PROJECT_NAME, `name:`, or the directory).
nano_compose_project() {
    python3 -I -c '
import json, sys
try:
    doc = json.load(sys.stdin) or {}
except ValueError:
    sys.exit(1)
name = doc.get("name") if isinstance(doc, dict) else ""
print(name if isinstance(name, str) else "")
'
}

# True when FIELD (a `docker ps` .Ports value, entries joined by ", ") binds
# host TCP port PORT. Docker collapses consecutive ports into one range entry,
# so every shape counts (NAN-5513):
#   0.0.0.0:8080->8080/tcp   127.0.0.1:4317-4318->4317-4318/tcp
#   [::]:8080->8080/tcp      :::8080->8080/tcp      8080/tcp (exposed only)
nano_ports_field_binds() {
    local field="$1" port="$2" entry host hp lo hi
    local -a entries=()
    [[ -n "$field" ]] || return 1
    IFS=, read -r -a entries <<< "$field"
    # ${a[@]+...}: an empty array is "unbound" under set -u before bash 4.4.
    for entry in ${entries[@]+"${entries[@]}"}; do
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ "$entry" == *"->"* && "${entry##*/}" == tcp ]] || continue
        host="${entry%%->*}"
        hp="${host##*:}"
        if [[ "$hp" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            lo="${BASH_REMATCH[1]}" hi="${BASH_REMATCH[2]}"
        elif [[ "$hp" =~ ^[0-9]+$ ]]; then
            lo="$hp" hi="$hp"
        else
            continue
        fi
        (( 10#$lo <= port && port <= 10#$hi )) && return 0
    done
    return 1
}

# `docker port <container>` lines ("4317/tcp -> 127.0.0.1:4317",
# "8080/tcp -> [::]:8080") on stdin, as one .Ports-style field.
nano_docker_port_as_field() {
    awk '$2 == "->" && NF >= 3 { n = split($1, p, "/"); if (n == 2) { out = out sep $3 "->" p[1] "/" p[2]; sep = ", " } } END { print out }'
}

# PORTS: lines from nano_published_ports. DIR: this install directory.
# PROJECT: this install's Compose project name. Prints one line per TCP port
# another process (or another Compose project) already holds. A port that
# one of this project's own containers publishes is never a conflict: `up`
# recreates that container. Own containers are found by their Compose labels
# (com.docker.compose.project, or the project working_dir), never by name.
nano_port_conflicts() {
    local ports="$1" dir="$2" project="${3:-}" physical host_ip port proto service holder containers
    local id name label_project workdir published own_field="" other_rows="" checked=" "
    physical=$(cd "$dir" 2>/dev/null && pwd -P) || physical="$dir"
    # Running containers with their published host ports. `docker ps --filter
    # publish=N` matches the CONTAINER port, so the host side is read from
    # .Ports ("0.0.0.0:3030->3000/tcp, ...") instead.
    containers=$(docker ps --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Ports}}' \
        </dev/null 2>/dev/null || true)
    while IFS='|' read -r id name label_project workdir published; do
        [[ -n "$id" ]] || continue
        if [[ -n "$project" && "$label_project" == "$project" ]] \
            || [[ -n "$workdir" && ( "$workdir" == "$dir" || "$workdir" == "$physical" ) ]]; then
            # Docker's own per-binding list, in case .Ports is in a shape not
            # parsed above: this project's ports must never read as taken.
            own_field+="${own_field:+, }$published"
            own_field+="${own_field:+, }$(docker port "$id" </dev/null 2>/dev/null | nano_docker_port_as_field || true)"
        else
            other_rows+="$name|$label_project|$workdir|$published"$'\n'
        fi
    done <<< "$containers"
    while read -r host_ip port proto service; do
        [[ -n "$port" && "$proto" == tcp && "$port" =~ ^[0-9]+$ ]] || continue
        [[ "$checked" == *" $host_ip:$port "* ]] && continue
        checked+="$host_ip:$port "
        nano_ports_field_binds "$own_field" "$port" && continue
        holder=""
        while IFS='|' read -r name label_project workdir published; do
            [[ -n "$name" ]] || continue
            nano_ports_field_binds "$published" "$port" || continue
            holder="Docker container $name${workdir:+ (from $workdir)}"
            break
        done <<< "$other_rows"
        [[ -n "$holder" ]] || holder=$(nano_port_listener "$port" "$host_ip")
        [[ -n "$holder" ]] || continue
        printf 'Port %s (%s, %s) is already in use on this host by %s.\n' "$port" "$service" "$([[ "$host_ip" == "*" ]] && printf 'all interfaces' || printf '%s' "$host_ip")" "$holder"
    done <<< "$ports"
}

# One summary line naming the inbound TCP ports to allow, from PORTS (lines
# from nano_published_ports). Loopback-only ports are left out.
nano_firewall_summary() {
    local ports="$1" host_ip port proto service label list="" seen=" "
    while read -r host_ip port proto service; do
        [[ -n "$port" ]] || continue
        case "$host_ip" in 127.* | "::1" | localhost) continue ;; esac
        [[ "$seen" == *" $port/$proto "* ]] && continue
        seen+="$port/$proto "
        case "$port" in
            80) label="UI" ;;
            443) label="UI, HTTPS" ;;
            8080) label="HTTP ingest" ;;
            8088) label="HEC ingest" ;;
            6000) label="Vector native, mutual TLS" ;;
            *) label="$service" ;;
        esac
        list+="${list:+, }$port/$proto ($label)"
    done <<< "$ports"
    [[ -n "$list" ]] && printf '%s\n' "$list"
    return 0
}

# NAN-5521: the compose overlays (file names in DIR, one per line) the stack
# in install directory DIR runs with, read from the
# com.docker.compose.project.config_files label of its nginx container (else
# any container of the project). Installs made before 2.0.30 were given
# NANO_COMPOSE_OVERLAYS (docker-compose.tls.yml) in the environment only, so
# .env does not list them. Prints nothing when it cannot tell. Leaves out the
# base file and the overlays install.sh manages itself (Agent Lane, metrics).
nano_running_compose_overlays() {
    local dir="$1" project="${2:-}" physical filter files="" path base
    local -a filters=() paths=()
    command -v docker >/dev/null 2>&1 || return 0
    physical=$(cd "$dir" 2>/dev/null && pwd -P) || physical="$dir"
    filters=("label=com.docker.compose.project.working_dir=$dir")
    [[ "$physical" == "$dir" ]] || filters+=("label=com.docker.compose.project.working_dir=$physical")
    [[ -z "$project" ]] || filters+=("label=com.docker.compose.project=$project")
    for filter in "${filters[@]}"; do
        files=$(docker ps -a --filter "$filter" --filter "label=com.docker.compose.service=nginx" \
            --format '{{.Label "com.docker.compose.project.config_files"}}' </dev/null 2>/dev/null) || files=""
        [[ -n "$files" ]] || files=$(docker ps -a --filter "$filter" \
            --format '{{.Label "com.docker.compose.project.config_files"}}' </dev/null 2>/dev/null) || files=""
        files="${files%%$'\n'*}"
        [[ -z "$files" ]] || break
    done
    [[ -n "$files" ]] || return 0
    IFS=, read -r -a paths <<< "$files"
    for path in ${paths[@]+"${paths[@]}"}; do
        base="${path##*/}"
        [[ "${path%/*}" == "$dir" || "${path%/*}" == "$physical" ]] || continue
        [[ "$base" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$ ]] || continue
        case "$base" in
            docker-compose.opensource.yml | docker-compose.agentlane.yml | docker-compose.metrics-expose.yml) continue ;;
        esac
        [[ -f "$dir/$base" && ! -L "$dir/$base" ]] || continue
        printf '%s\n' "$base"
    done
}

# NAN-5521: OVERLAYS ($1, the list recorded in .env) plus every overlay in
# RUNNING ($2, lines from nano_running_compose_overlays) it lacks, in order.
# Prints the merged list; returns 1 when nothing was missing.
nano_merge_running_overlays() {
    local running="$2" overlay merged="$1" added=1
    while IFS= read -r overlay; do
        [[ -n "$overlay" ]] || continue
        [[ " $merged " == *" $overlay "* ]] && continue
        merged="${merged:+$merged }$overlay"
        added=0
    done <<< "$running"
    printf '%s\n' "$merged"
    return "$added"
}
