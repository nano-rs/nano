#!/usr/bin/env bash
# shellcheck disable=SC2016
# This script GENERATES shell for an emitted Dockerfile; the single-quoted $f and $got belong to that shell, not this one.
#
# Prove every compile-time asset survives .dockerignore.
#
# The Rust crates pull non-source files in at COMPILE time four ways:
#   1. include_str!/include_bytes!("relative/path")
#   2. the same macros wrapped in concat!(env!("CARGO_MANIFEST_DIR"), "/path")
#   3. sqlx::migrate!("../migrations/postgres") — embeds a whole DIRECTORY, so a
#      partially-excluded directory compiles into an image with missing migrations
#   4. build scripts that READ a file (nanosiem-core/build.rs generates the UDM
#      field code from docs/udmfields.csv)
#
# Those assets live under directories .dockerignore excludes wholesale (config/,
# docs/, scripts/, nanosiem-web/, nano-desktop/) and are re-admitted one by one.
# Get a negation wrong and the image build fails — or the public mirror builds a
# stale artifact (NAN-2169). Nothing checked this: .dockerignore's own comment
# claims the list is machine-checked, and no such check existed.
#
# How it works: BuildKit transfers build context LAZILY, so a Dockerfile that
# only COPYs the assets under test costs a few hundred kB, not the whole repo. A
# path excluded by .dockerignore makes COPY fail with `"<path>": not found`, and
# a partially-excluded directory trips a file-count assertion. Docker's own
# matcher decides, rather than a reimplementation of its glob semantics.
#
# Scope: only what the image targets actually compile — <crate>/src/** and
# <crate>/build.rs. tests/ and benches/ are excluded on purpose: `cargo build`
# for a bin never compiles them, and some of their fixtures legitimately live
# under directories .dockerignore excludes.
#
# Usage: scripts/check-build-context-includes.sh [--list] [--quiet]
#   --list   print the resolved assets and exit (no daemon needed)
#
# Run from the repo root. Needs docker (BuildKit). Read-only: builds a throwaway
# image from busybox and removes it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

LIST_ONLY=0
QUIET=0
for arg in "$@"; do
    case "$arg" in
        --list)  LIST_ONLY=1 ;;
        --quiet) QUIET=1 ;;
        -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

ok()   { (( QUIET )) || printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

[[ -f .dockerignore ]] || fail ".dockerignore not found — run from the repo root."
command -v python3 >/dev/null 2>&1 || fail "python3 is required."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/nano-buildctx.XXXXXX")"
trap 'rm -rf "$WORK"; docker image rm -f nano-buildctx-probe:tmp >/dev/null 2>&1 || true' EXIT

# ----------------------------------------------------------------------------
# Resolve the assets. Emits "F <path>" for files and "D <path> <tracked count>"
# for directories embedded wholesale.
# ----------------------------------------------------------------------------
cat > "$WORK/resolve.py" <<'RESOLVER'
import os, re, subprocess

root = os.getcwd()
tracked = [f for f in subprocess.run(
    ["git", "ls-files", "-z"], capture_output=True, text=True, check=True
).stdout.split("\0") if f]
tracked_set = set(tracked)

def compiled_into_image(rel):
    parts = rel.split("/")
    if rel.endswith("build.rs") and len(parts) == 2:
        return True
    return "src" in parts[:2] and rel.endswith(".rs")

lit_pat = re.compile(r'include_(?:str|bytes)!\s*\(\s*"((?:[^"\\]|\\.)*)"')
cat_pat = re.compile(
    r'include_(?:str|bytes)!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,'
    r'\s*((?:\s*"(?:[^"\\]|\\.)*"\s*,?)+)',
    re.S,
)
mig_pat   = re.compile(r'sqlx::migrate!\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)')
rerun_pat = re.compile(r'cargo:rerun-if-changed=([^"\'\\\s)]+)')

files, dirs = set(), set()
for rel in tracked:
    if not compiled_into_image(rel):
        continue
    try:
        src = open(rel, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    here = os.path.dirname(os.path.join(root, rel))
    manifest_dir = os.path.join(root, rel.split("/")[0])

    cands = [(here, m.group(1)) for m in lit_pat.finditer(src)]
    for m in cat_pat.finditer(src):
        joined = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))
        cands.append((manifest_dir, joined.lstrip("/")))
    if rel.endswith("build.rs"):
        cands += [(manifest_dir, m.group(1)) for m in rerun_pat.finditer(src)]

    def resolve(base, lit):
        try:
            lit = lit.encode().decode("unicode_escape")
        except Exception:
            return None
        t = os.path.normpath(os.path.join(base, lit))
        return t if t.startswith(root + os.sep) else None

    for base, lit in cands:
        t = resolve(base, lit)
        if t and os.path.isfile(t):
            files.add(os.path.relpath(t, root))
    # sqlx::migrate! is crate-manifest-relative, like the concat! form.
    for m in mig_pat.finditer(src):
        t = resolve(manifest_dir, m.group(1))
        if t and os.path.isdir(t):
            dirs.add(os.path.relpath(t, root))

for f in sorted(files):
    print("F", f)
for d in sorted(dirs):
    members = sorted(t[len(d) + 1:] for t in tracked_set if t.startswith(d + "/"))
    print("D", d, " ".join(members))
RESOLVER

ASSETS=$(python3 "$WORK/resolve.py")
[[ -n "$ASSETS" ]] || fail "no compile-time assets resolved — the resolver is broken."

FILES=$(awk '$1 == "F" { print $2 }' <<< "$ASSETS")
DIRS=$(awk '$1 == "D" { sub(/^D /, ""); print }' <<< "$ASSETS")
NF=$(grep -c . <<< "$FILES" || true)
ND=$(grep -c . <<< "$DIRS" || true)

if (( LIST_ONLY )); then
    printf '%s\n' "$ASSETS"
    printf '\n%s files + %s embedded directories\n' "$NF" "$ND"
    exit 0
fi

command -v docker >/dev/null 2>&1 || fail "docker is required (or use --list)."

emit_dockerfile() {
    printf 'FROM busybox\n'
    while IFS= read -r a; do
        [[ -z "$a" ]] && continue
        printf 'COPY ["%s", "/probe/%s"]\n' "$a" "$a"
    done <<< "$1"
    # A directory can also be *partially* excluded, which COPY reports as
    # success while silently dropping files. Assert every TRACKED member is
    # present — a count comparison would be skewed by untracked files sitting
    # in the same directory.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local d="${line%% *}" members="${line#* }"
        printf 'COPY ["%s", "/probe/%s"]\n' "$d" "$d"
        printf 'RUN for f in %s; do [ -f "/probe/%s/$f" ] || { echo "DIRDROP %s/$f"; exit 1; }; done\n' \
            "$members" "$d" "$d"
    done <<< "$2"
}

emit_dockerfile "$FILES" "$DIRS" > "$WORK/probe.Dockerfile"
if docker build -f "$WORK/probe.Dockerfile" -t nano-buildctx-probe:tmp . >"$WORK/build.log" 2>&1; then
    ok "$NF compile-time files + $ND embedded directories are all intact in the Docker build context"
    exit 0
fi

if grep -q 'DIRDROP' "$WORK/build.log"; then
    printf '\033[31mFAIL\033[0m .dockerignore drops files from a directory embedded by sqlx::migrate!:\n' >&2
    grep -o 'DIRDROP .*' "$WORK/build.log" | sed 's/^DIRDROP /  /' >&2
    printf '\n  sqlx verifies migrations at COMPILE time, so a partially-excluded\n  directory produces an image with silently missing migrations.\n' >&2
    exit 1
fi

printf '\033[31mFAIL\033[0m .dockerignore excludes compile-time asset(s) the crates need:\n' >&2
MISSING=0
while IFS= read -r a; do
    [[ -z "$a" ]] && continue
    printf 'FROM busybox\nCOPY ["%s", "/probe/x"]\n' "$a" > "$WORK/one.Dockerfile"
    docker build -f "$WORK/one.Dockerfile" -t nano-buildctx-probe:tmp . >/dev/null 2>&1 \
        || { printf '  %s\n' "$a" >&2; MISSING=$((MISSING + 1)); }
done <<< "$FILES
$(awk '{print $1}' <<< "$DIRS")"

cat >&2 <<MSG

  $MISSING asset(s) are excluded. Each is pulled in at compile time, so the
  image build fails without them.

  Fix .dockerignore by re-including the file AND every parent directory:

      !config/vector/
      config/vector/*
      !config/vector/00-base.toml

  (a negation cannot resurrect a file whose parent directory is still excluded).
MSG
[[ "$MISSING" == "0" ]] && sed -n '$p' "$WORK/build.log" >&2
exit 1
