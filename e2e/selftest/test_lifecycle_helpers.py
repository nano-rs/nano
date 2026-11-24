"""The lifecycle helpers and pins (NAN-5765) cannot pass vacuously.

- `present` needs EVERY object, not one of several, before a delete;
- `absent` fails while ANY spelling of any deleted object is still listed,
  naming the JSON paths;
- each lifecycle `known_bug` signature matches only its bug's value (a stale
  over-count, a raw id, a named row): an empty list, a zero or an under-count
  must stay red.
"""

from __future__ import annotations

import re

import pytest

from nano_e2e import lifecycle
from nano_e2e.known_bugs import known_bug

XFAIL = pytest.xfail.Exception

UUID = "0189c0a2-7b3d-7c1e-9f00-1234567890ab"
TYPEID = lifecycle.typeid("lsrc", UUID)


def test_mentions_finds_every_spelling_in_values_and_keys() -> None:
    body = {"sources": [{"id": TYPEID}, {"name": "e2e_abc"}], "by_id": {UUID.replace("-", ""): 1}}
    hits = lifecycle.mentions(body, lifecycle.id_spellings(TYPEID, "lsrc"))
    assert any("sources[0].id" in h for h in hits), hits
    assert any(h.startswith("$.by_id.{") for h in hits), hits
    assert lifecycle.mentions(body, {"E2E_ABC"}) == ["$.sources[1].name=e2e_abc"]
    assert lifecycle.mentions(body, {"nope"}) == []


def test_present_needs_every_object() -> None:
    body = {"rows": [{"name": "rule_a"}]}
    assert lifecycle.present(lambda: body, ["rule_a"], what="t", timeout=0) == body
    with pytest.raises(AssertionError, match=r"never listed \['rule_b'\]"):
        lifecycle.present(lambda: body, ["rule_a", "rule_b"], what="t", timeout=0)
    with pytest.raises(AssertionError, match="at least one object"):
        lifecycle.present(lambda: body, [], what="t", timeout=0)


def test_absent_fails_on_any_remaining_object() -> None:
    body = {"rows": [{"name": "rule_a"}, {"name": "kept"}]}
    with pytest.raises(AssertionError, match=r"still lists the deleted object \(1 mentions\).*rule_a"):
        lifecycle.absent(lambda: body, {"rule_a", "rule_b"}, what="t", timeout=0)
    assert lifecycle.absent(lambda: body, {"rule_c"}, what="t", timeout=0) == body
    ok = lifecycle.absent(lambda: body, {"rule_a"}, what="t", timeout=0, ignore=lambda h: "rows[0]" in h)
    assert ok == body


# (signature, buggy messages that XFAIL, messages that must stay red)
# Empty while no lifecycle bug is pinned (NAN-5785 was the last); add a row
# with each new `known_bug` signature.
PINS: list[tuple[str, list[str], list[str]]] = []


@pytest.mark.parametrize(("sig", "bug", "red"), PINS, ids=[re.sub(r"\W+", "_", p[0][:40]) for p in PINS])
def test_each_pin_matches_only_its_bug(sig: str, bug: list[str], red: list[str]) -> None:
    for msg in bug:
        with pytest.raises(XFAIL):
            with known_bug("NAN-5765", sig):
                raise AssertionError(msg)
    for msg in red:
        with pytest.raises(AssertionError, match=re.escape(msg[:20])):
            with known_bug("NAN-5765", sig):
                raise AssertionError(msg)
