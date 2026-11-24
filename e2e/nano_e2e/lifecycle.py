"""Lifecycle scenarios (NAN-5765): delete X, then assert it is gone from every
page that summarizes X, not only from its own list.

NAN-5760 (SIEM health kept reporting deleted log sources) shipped because the
delete tests only checked the primary list. These helpers make the "every
summary" check cheap to write:

- `mentions(body, needles)`: every JSON path in an API response whose string
  value contains one of the needles (an id in any spelling, a name). A
  summary that still lists the deleted object mentions it somewhere.
- `id_spellings(value)`: the forms one id takes across the API (the public
  TypeID `lsrc_01h…`, the stored UUID, with and without dashes).
- `present(...)`: the positive control before a delete: the summary lists
  EVERY object (one of several is not enough), so `absent` cannot pass
  vacuously for an object that never got there.
- `absent(...)`: poll one summary endpoint until it mentions NONE of the
  deleted objects (caches and the stored health report may catch up), and
  fail with the paths that still mention one.
- `page_loaded(...)`: before a "not shown" assertion on a page, wait for its
  data (the API response, then control rows or a settled page), never a
  text length.
- `SIG_*`: the strict `known_bug` signatures the scenarios pin, proven by
  selftest/test_lifecycle_helpers.py to match only their bug's value.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from nano_e2e.soar_ui import typeid, uuid_of
from nano_e2e.waits import eventually


def id_spellings(value: str, prefix: str | None = None) -> set[str]:
    """Every spelling of one id: as given, its UUID (dashed and bare), and the
    TypeID with `prefix` when given. Lower-cased; matching is lower-cased."""
    out = {value.lower()}
    try:
        u = uuid_of(value)
    except ValueError:
        u = ""
    if u:
        out |= {u, u.replace("-", "")}
        if prefix:
            out.add(typeid(prefix, u))
    return {s for s in out if s}


def mentions(body: Any, needles: Iterable[str], path: str = "$") -> list[str]:
    """JSON paths (`$.sources[3].name=...`) whose string value contains one of
    `needles` (case-insensitive). Keys are checked too: a map keyed by the
    deleted object's id or name still summarizes it."""
    wanted = [n.lower() for n in needles if n]
    hits: list[str] = []

    def walk(node: Any, at: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                ks = str(k)
                if any(n in ks.lower() for n in wanted):
                    hits.append(f"{at}.{{{ks}}}")
                walk(v, f"{at}.{ks}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{at}[{i}]")
        elif isinstance(node, str):
            low = node.lower()
            if any(n in low for n in wanted):
                hits.append(f"{at}={node[:120]}")

    walk(body, path)
    return hits


def absent(
    fetch: Callable[[], Any],
    needles: Iterable[str],
    *,
    what: str,
    timeout: float = 60,
    interval: float = 3,
    ignore: Callable[[str], bool] | None = None,
) -> Any:
    """Poll `fetch()` until its body no longer mentions any of `needles`
    (paths for which `ignore(path)` holds are allowed: a quiet historical
    record). Returns the last body. On timeout the failure names the summary
    (`what`) and the paths still mentioning the deleted object, which is the
    symptom a `known_bug` signature matches."""
    needles = list(needles)
    last: dict[str, Any] = {"body": None, "hits": []}

    def probe() -> list[str]:
        body = fetch()
        hits = [h for h in mentions(body, needles) if not (ignore and ignore(h))]
        last.update(body=body, hits=hits)
        return hits

    try:
        eventually(probe, timeout=timeout, interval=interval, desc=f"{what} to drop the deleted object",
                   ok=lambda hits: not hits)
    except AssertionError:
        hits = last["hits"]
        raise AssertionError(
            f"{what} still lists the deleted object ({len(hits)} mentions): {hits[:6]}"
        ) from None
    return last["body"]


def present(fetch: Callable[[], Any], needles: Iterable[str], *, what: str, timeout: float = 120,
            interval: float = 3) -> Any:
    """Poll `fetch()` until its body mentions EVERY one of `needles` (one
    spelling per object): the positive control before a delete. Any object
    that never reached the summary would make its later `absent` vacuous, so
    one match among several is not enough."""
    needles = [n for n in needles if n]
    assert needles, f"{what}: present() needs at least one object to look for"
    last: dict[str, Any] = {"missing": needles}

    def missing() -> list[str]:
        body = fetch()
        last["missing"] = [n for n in needles if not mentions(body, [n])]
        return last["missing"]

    try:
        eventually(missing, timeout=timeout, interval=interval, desc=f"{what} to list every object",
                   ok=lambda m: not m)
    except AssertionError:
        raise AssertionError(f"{what} never listed {last['missing']} (before the delete)") from None
    return fetch()


def page_loaded(page: Any, api_path: str, since_ms: int, *, controls: Iterable[str] = (),
                timeout: float = 30) -> str:
    """Wait until the page has its data, before any "not shown" assertion:
    a 200 for `api_path` fetched since `since_ms` (take `page.now_ms()` before
    `goto`), then every control text (things the API says the page lists),
    or, with no controls, the page text stable across two reads. Returns the
    page text."""
    eventually(
        lambda: [r for r in page.api_responses_since(since_ms) if api_path in r["url"] and r["status"] == 200],
        timeout=timeout, interval=0.5, desc=f"the page to fetch {api_path}", ok=bool,
    )
    controls = [c for c in controls if c]
    if controls:
        return eventually(page.main_text, timeout=timeout, interval=0.5,
                          desc=f"the page to render {controls[:3]}", ok=lambda t: all(c in t for c in controls))
    prev = {"t": None}

    def stable() -> bool:
        cur = page.main_text()
        same, prev["t"] = cur == prev["t"], cur
        return same

    eventually(stable, timeout=timeout, interval=1, desc="the page text to settle", ok=bool)
    return prev["t"] or ""


# ---------------------------------------------------------------- pinned symptoms
# The `known_bug` signatures of the lifecycle scenarios, kept here so
# selftest/test_lifecycle_helpers.py proves each one matches ONLY its bug's
# value (a stale over-count, a raw id, a named row) and never an empty list,
# a zero or an under-count: those must stay red. Each scenario asserts the
# healthy bound (for example "never fewer than exist") outside the pin.
# None pinned now (NAN-5785 was the last).
