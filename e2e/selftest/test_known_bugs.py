"""`known_bug` pins exactly one bug (NAN-5684): its own symptom XFAILs, any
other failure in the wrapped step stays red, a fixed bug fails the test, and
catch-all signatures are refused where they are written."""

from __future__ import annotations

import pytest

from nano_e2e.known_bugs import known_bug
from nano_e2e.ui import UiError

XFAIL = pytest.xfail.Exception
FAILED = pytest.fail.Exception
SIG = r"^(?:[4-9]|[1-9]\d+) rows for `head 3`"


def test_the_pinned_symptom_xfails() -> None:
    with pytest.raises(XFAIL, match="NAN-5693"):
        with known_bug("NAN-5693", SIG):
            raise AssertionError("9 rows for `head 3` (per chunk)")


def test_anchors_hold_on_a_pytest_rewritten_message() -> None:
    # pytest appends its rewrite after the message: `^…$` match the first line.
    with pytest.raises(XFAIL):
        with known_bug("NAN-5701", r"^50 buckets shown of \d+$"):
            raise AssertionError("50 buckets shown of 73\nassert 50 == 73")
    with pytest.raises(AssertionError, match="^0 buckets"):
        with known_bug("NAN-5701", r"^50 buckets shown of \d+$"):
            raise AssertionError("0 buckets shown of 73\nassert 0 == 73")


def test_an_unrelated_assertion_in_the_step_still_fails() -> None:
    # Same step, different symptom (rows dropped instead of multiplied).
    with pytest.raises(AssertionError, match="^1 rows"):
        with known_bug("NAN-5693", SIG):
            raise AssertionError("1 rows for `head 3`")


def test_an_unrelated_exception_type_still_fails() -> None:
    with pytest.raises(RuntimeError):
        with known_bug("NAN-5693", SIG):
            raise RuntimeError("9 rows for `head 3`")  # right text, wrong type


def test_a_driver_failure_in_the_step_still_fails() -> None:
    with pytest.raises(UiError):
        with known_bug("NAN-5693", SIG):
            raise UiError("UI click: Error: timed out after 20000ms waiting for element {'testid': 'x'}")


def test_the_predicate_must_accept_the_failure() -> None:
    def all_none(exc: BaseException) -> bool:
        return "{'team-red': None" in str(exc)

    with pytest.raises(XFAIL):
        with known_bug("NAN-5694", r"^OUTPUT enriched nothing:", when=all_none):
            raise AssertionError("OUTPUT enriched nothing: {'team-red': None, 'team-blue': None}")
    with pytest.raises(AssertionError, match="999"):
        with known_bug("NAN-5694", r"^OUTPUT enriched nothing:", when=all_none):
            raise AssertionError("OUTPUT enriched nothing: {'team-red': 1, 'team-blue': 999}")


def test_a_fixed_bug_fails_the_test() -> None:
    with pytest.raises(FAILED, match="NAN-5693 looks fixed"):
        with known_bug("NAN-5693", SIG):
            pass


def test_a_specific_exception_type_can_be_named() -> None:
    with pytest.raises(XFAIL):
        with known_bug("NAN-5699", r"waiting for a download to be produced", raises=UiError):
            raise UiError("UI download: Error: timed out after 10000ms waiting for a download to be produced")


@pytest.mark.parametrize(
    "signature",
    [r".*", r".+", r"", r"\w+", r"Error", r"timed out after", r"BUG \S+", r"(?s).{0,}", r"assert"],
)
def test_catch_all_signatures_are_refused(signature: str) -> None:
    with pytest.raises(ValueError):
        with known_bug("NAN-1", signature):
            pass


@pytest.mark.parametrize("raises", [Exception, BaseException, (AssertionError, Exception), "AssertionError"])
def test_catch_all_exception_types_are_refused(raises) -> None:
    with pytest.raises(ValueError):
        with known_bug("NAN-1", SIG, raises=raises):
            pass


def test_the_bug_id_must_be_a_linear_id() -> None:
    with pytest.raises(ValueError):
        with known_bug("BUG-1", SIG):
            pass
