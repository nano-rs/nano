#!/usr/bin/env bash
# Reusable teardown guard for Docker/browser test harnesses.
#
# A guard snapshots resources that are already dangling before a harness runs
# and fails if new dangling volumes, networks, or Puppeteer Chrome processes
# remain afterward. Cleanup helpers only act on exact PIDs or the exact Compose
# project label supplied by the caller; they never prune or prefix-match shared
# Docker state.
#
# NAN-5884: several lanes can run on one host. Each guard checks only its own
# run: browsers launched with its run token (NANO_LEAK_GUARD_RUN, which the UI
# driver puts in Chrome's --user-data-dir, inherited by every Chrome helper
# process), and, once the run has
# named its Compose projects (leak_guard_own_project, or the capture/cleanup
# helpers), only volumes and networks of those projects. A guard that named no
# project keeps the host-wide volume and network check.

if [[ -n "${NANO_LEAK_GUARD_LOADED:-}" ]]; then
  return 0
fi
NANO_LEAK_GUARD_LOADED=1

LEAK_GUARD_ACTIVE=0
LEAK_GUARD_DIR=""
LEAK_GUARD_NAME=""
declare -ag LEAK_GUARD_TRACKED_PIDS=()
declare -Ag LEAK_GUARD_PID_STARTS=()
declare -Ag LEAK_GUARD_PROJECT_VOLUMES=()
# NAN-5884: this run's Compose projects, and every volume captured for them
# (anonymous volumes carry no project label once their container is gone).
declare -Ag LEAK_GUARD_PROJECTS=()
LEAK_GUARD_OWNED_VOLUMES=" "
LEAK_GUARD_RUN_TOKEN=""

_leak_guard_process_start() {
  LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//'
}

_leak_guard_browser_pids() {
  # With a run token, only this run's browsers; without one, every Puppeteer
  # Chrome on the host. The UI driver puts the token in the browser's
  # --user-data-dir (puppeteer_dev_chrome_profile-nano-<token>-...), which
  # Chrome passes to every renderer, GPU and utility process, so an orphaned
  # helper whose browser died still counts as this run's leak (review P2-2).
  #
  # Self-match-proof (review r2): neither the marker nor the token appears
  # in awk's own command line (the marker is built from two pieces, the
  # token comes through the environment), so the filter never lists itself.
  # -ww: never cut a command line to $COLUMNS or the terminal width (review
  # r3); Chrome's --user-data-dir sits near the end of a long argv.
  ps -axww -o pid=,args= 2>/dev/null \
    | LEAK_GUARD_AWK_TOKEN="$LEAK_GUARD_RUN_TOKEN" awk '
        BEGIN { p = "puppeteer_dev_" "chrome_profile-"; tag = ENVIRON["LEAK_GUARD_AWK_TOKEN"] }
        index($0, p) && (tag == "" || index($0, p "nano-" tag "-")) { print $1 }' \
    | LC_ALL=C sort -u
}

# NAN-5884: name a Compose project this run owns.
leak_guard_own_project() {
  [[ -n "${1:-}" ]] || return 2
  LEAK_GUARD_PROJECTS["$1"]=1
}

# Whether a new dangling resource belongs to this run (always, when the run
# named no project).
_leak_guard_owned() {
  local kind="$1" id="$2" label
  (( ${#LEAK_GUARD_PROJECTS[@]} )) || return 0
  [[ "$kind" == volumes && "$LEAK_GUARD_OWNED_VOLUMES" == *" $id "* ]] && return 0
  case "$kind" in
    volumes) label="$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)" ;;
    networks) label="$(docker network inspect --format '{{index .Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)" ;;
    *) return 0 ;;
  esac
  [[ -n "$label" && -n "${LEAK_GUARD_PROJECTS[$label]:-}" ]]
}

_leak_guard_snapshot() {
  local destination="$1"
  mkdir -p "$destination"
  if docker info >/dev/null 2>&1; then
    printf '1\n' > "$destination/docker-available"
    docker volume ls -q --filter dangling=true 2>/dev/null | LC_ALL=C sort -u \
      > "$destination/volumes"
    docker network ls -q --filter dangling=true 2>/dev/null | LC_ALL=C sort -u \
      > "$destination/networks"
  else
    printf '0\n' > "$destination/docker-available"
    : > "$destination/volumes"
    : > "$destination/networks"
  fi
  _leak_guard_browser_pids > "$destination/browsers"
}

leak_guard_begin() {
  local name="${1:-harness}"
  if (( LEAK_GUARD_ACTIVE )); then
    printf 'leak guard already active for %s\n' "$LEAK_GUARD_NAME" >&2
    return 2
  fi
  LEAK_GUARD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nano-leak-guard.XXXXXX")"
  LEAK_GUARD_NAME="$name"
  LEAK_GUARD_PROJECTS=()
  LEAK_GUARD_OWNED_VOLUMES=" "
  # NAN-5884: a token the run's browsers carry (inherited by the scenario
  # processes and the UI driver).
  LEAK_GUARD_RUN_TOKEN="$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
  [[ -n "$LEAK_GUARD_RUN_TOKEN" ]] || LEAK_GUARD_RUN_TOKEN="$$$(date +%s)"
  export NANO_LEAK_GUARD_RUN="$LEAK_GUARD_RUN_TOKEN"
  _leak_guard_snapshot "$LEAK_GUARD_DIR/before"
  LEAK_GUARD_ACTIVE=1
}

leak_guard_track_pid() {
  local pid="$1" start
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 2
  start="$(_leak_guard_process_start "$pid")"
  [[ -n "$start" ]] || return 1
  LEAK_GUARD_TRACKED_PIDS+=("$pid")
  LEAK_GUARD_PID_STARTS["$pid"]="$start"
}

leak_guard_untrack_pid() {
  local target="$1" pid
  local kept=()
  for pid in "${LEAK_GUARD_TRACKED_PIDS[@]}"; do
    [[ "$pid" == "$target" ]] || kept+=("$pid")
  done
  LEAK_GUARD_TRACKED_PIDS=("${kept[@]}")
  unset 'LEAK_GUARD_PID_STARTS[$target]'
}

leak_guard_stop_tracked_pids() {
  local pid expected current
  for pid in "${LEAK_GUARD_TRACKED_PIDS[@]}"; do
    expected="${LEAK_GUARD_PID_STARTS[$pid]:-}"
    current="$(_leak_guard_process_start "$pid")"
    [[ -n "$expected" && "$current" == "$expected" ]] || continue
    kill -TERM "$pid" >/dev/null 2>&1 || true
  done
  for _ in $(seq 1 30); do
    local live=0
    for pid in "${LEAK_GUARD_TRACKED_PIDS[@]}"; do
      expected="${LEAK_GUARD_PID_STARTS[$pid]:-}"
      current="$(_leak_guard_process_start "$pid")"
      [[ -n "$expected" && "$current" == "$expected" ]] && live=1
    done
    (( live == 0 )) && break
    sleep 0.1
  done
  for pid in "${LEAK_GUARD_TRACKED_PIDS[@]}"; do
    expected="${LEAK_GUARD_PID_STARTS[$pid]:-}"
    current="$(_leak_guard_process_start "$pid")"
    if [[ -n "$expected" && "$current" == "$expected" ]]; then
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
    wait "$pid" >/dev/null 2>&1 || true
  done
  LEAK_GUARD_TRACKED_PIDS=()
  LEAK_GUARD_PID_STARTS=()
}

leak_guard_capture_compose_project() {
  local project="$1" container volume label recorded
  [[ -n "$project" ]] || return 2
  leak_guard_own_project "$project"
  recorded="${LEAK_GUARD_PROJECT_VOLUMES[$project]:-}"
  while IFS= read -r container; do
    [[ -n "$container" ]] || continue
    label="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null || true)"
    [[ "$label" == "$project" ]] || continue
    while IFS= read -r volume; do
      [[ -n "$volume" ]] || continue
      label="$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$volume" 2>/dev/null || true)"
      # Compose-owned named volumes carry the project label. Image-declared
      # anonymous volumes do not, but Docker names those with a 64-hex ID.
      # Never capture an unlabeled human-named/external volume.
      [[ "$label" == "$project" || "$volume" =~ ^[0-9a-f]{64}$ ]] || continue
      [[ " $recorded " == *" $volume "* ]] || recorded+=" $volume"
    done < <(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$container" 2>/dev/null)
  done < <(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null)
  LEAK_GUARD_PROJECT_VOLUMES["$project"]="$recorded"
  for volume in $recorded; do
    [[ "$LEAK_GUARD_OWNED_VOLUMES" == *" $volume "* ]] || LEAK_GUARD_OWNED_VOLUMES+="$volume "
  done
}

leak_guard_cleanup_compose_project() {
  local project="$1" id label captured
  local ids=()
  [[ -n "$project" ]] || return 2
  leak_guard_capture_compose_project "$project"

  while IFS= read -r id; do [[ -z "$id" ]] || ids+=("$id"); done \
    < <(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null)
  for id in "${ids[@]}"; do
    label="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)"
    [[ "$label" == "$project" ]] || continue
    docker rm -fv "$id" >/dev/null 2>&1 || true
  done

  captured="${LEAK_GUARD_PROJECT_VOLUMES[$project]:-}"
  ids=()
  read -r -a ids <<< "$captured"
  for id in "${ids[@]}"; do
    docker volume rm "$id" >/dev/null 2>&1 || true
  done
  unset 'LEAK_GUARD_PROJECT_VOLUMES[$project]'

  ids=()
  while IFS= read -r id; do [[ -z "$id" ]] || ids+=("$id"); done \
    < <(docker volume ls -q --filter "label=com.docker.compose.project=$project" 2>/dev/null)
  for id in "${ids[@]}"; do
    label="$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)"
    [[ "$label" == "$project" ]] || continue
    docker volume rm "$id" >/dev/null 2>&1 || true
  done

  ids=()
  while IFS= read -r id; do [[ -z "$id" ]] || ids+=("$id"); done \
    < <(docker network ls -q --filter "label=com.docker.compose.project=$project" 2>/dev/null)
  for id in "${ids[@]}"; do
    label="$(docker network inspect --format '{{index .Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)"
    [[ "$label" == "$project" ]] || continue
    docker network rm "$id" >/dev/null 2>&1 || true
  done
}

leak_guard_assert() {
  (( LEAK_GUARD_ACTIVE )) || return 0
  local after="$LEAK_GUARD_DIR/after" kind id failed=0
  _leak_guard_snapshot "$after"
  if [[ "$(<"$LEAK_GUARD_DIR/before/docker-available")" == 1 \
      && "$(<"$after/docker-available")" != 1 ]]; then
    printf 'LEAK-GUARD[%s]: Docker became unavailable before teardown could be verified\n' \
      "$LEAK_GUARD_NAME" >&2
    failed=1
  fi
  for kind in volumes networks browsers; do
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      # NAN-5884: another lane's resources are that lane's guard's business.
      _leak_guard_owned "$kind" "$id" || continue
      printf 'LEAK-GUARD[%s]: new dangling %s resource: %s\n' \
        "$LEAK_GUARD_NAME" "$kind" "$id" >&2
      failed=1
    done < <(comm -13 "$LEAK_GUARD_DIR/before/$kind" "$after/$kind")
  done
  rm -rf "$LEAK_GUARD_DIR"
  LEAK_GUARD_ACTIVE=0
  LEAK_GUARD_DIR=""
  LEAK_GUARD_RUN_TOKEN=""
  unset NANO_LEAK_GUARD_RUN
  (( failed == 0 ))
}

leak_guard_finish() {
  local status="$1" guard_status=0
  leak_guard_assert || guard_status=$?
  if (( status == 0 && guard_status != 0 )); then
    return "$guard_status"
  fi
  return "$status"
}
