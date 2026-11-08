"""Entra ID directory feed (`entra_directory`, kind identity) against the real
Azure e2e tenant (app registration `nano-e2e-entra-connector`, Graph
application permissions User.Read.All, GroupMember.Read.All,
RoleManagement.Read.Directory).

Created in the browser (Pull feeds > New pull feed, secret entered inline),
then checked against Microsoft Graph read with the same app:

- the first run (full) writes exactly Graph's users into the user directory
  under the feed's provider (`cfeed_...`), with the mapped fields;
- group and activated directory-role memberships land on the users
  (`groups`), transitive members included;
- a second run (delta from the stored deltaLink) succeeds, advances the users
  checkpoint and duplicates nobody;
- a credential rotate is live on the next run: rotated to a wrong secret the
  run fails (and retires nobody), rotated to the app's second real secret it
  succeeds again;
- a feed with a wrong secret fails visibly (API last_error + the Pull feeds
  row) while the good feed keeps succeeding and Vector stays healthy;
- deleting the feed retires its users (tombstones), the tenant is untouched.
"""

from __future__ import annotations

from collections import Counter

import pytest

from nano_e2e import creds, feeds_live, ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.stack import Stack
from nano_e2e.vendors_live import EntraDirectory
from nano_e2e.waits import eventually

LABEL = "Microsoft Entra ID directory"
# A full directory run walks users, then fans out over groups and roles.
FIRST_RUN = 300.0


@pytest.fixture
def entra(live_runner) -> tuple[creds.EntraCreds, EntraDirectory]:
    c, why = creds.entra()
    if c is None:
        pytest.skip(why)
    return c, EntraDirectory(c)


def _config(c: creds.EntraCreds, privileged: str) -> dict[str, str]:
    return {"DIRECTORY_ID": c.tenant_id, "CLIENT_ID": c.client_id, "PRIVILEGED_GROUPS": privileged}


def test_entra_directory_feed(
    stack: Stack,
    nano: Nano,
    page: uilib.UiPage,
    entra: tuple[creds.EntraCreds, EntraDirectory],
    mark: str,
    feed_cleanup: list[str],
    timeline,
) -> None:
    c, graph = entra
    users = graph.users()
    groups = graph.groups()
    members = {gid: graph.group_user_members(gid) for gid in groups}
    roles = graph.role_user_members()
    assert users, "the Entra e2e tenant has no users"
    # A group with members, marked privileged by the feed's PRIVILEGED_GROUPS.
    priv_gid = next((gid for gid, m in sorted(members.items()) if m), "")
    timeline.step(
        "graph truth",
        users=len(users),
        groups=len(groups),
        groups_with_members=sum(1 for m in members.values() if m),
        roles={k: len(v) for k, v in roles.items()},
    )

    # ---------------------------------------------------------------- browser: create
    name = f"{mark}-entra"
    page.driver.register_secret(c.client_secret)
    feeds_live.ui_create_feed(
        page,
        LABEL,
        name,
        _config(c, groups[priv_gid]["displayName"] if priv_gid else ""),
        {"CLIENT_SECRET": c.client_secret},
    )
    feed = eventually(lambda: feeds_live.feed_by_name(nano, name), timeout=30, desc="feed in the API")
    assert feed is not None
    feed_cleanup.append(feed["id"])
    timeline.step("ui: feed created", id=feed["id"], kind=feed.get("kind"), credential=feed.get("credential_id"))
    assert feed["kind"] == "identity", feed
    assert feed.get("credential_id"), "the inline secret was not stored as a credential"
    assert not page.contains(c.client_secret), "the client secret is shown in the page"

    # ---------------------------------------------------------------- run 1: full sync
    d1 = feeds_live.wait_run(nano, feed["id"], after=0, timeout=FIRST_RUN)
    run1 = feeds_live.finished_runs(d1)[0]
    cp1 = feeds_live.checkpoints(d1)
    timeline.step("run 1", run=run1, checkpoints=cp1)
    provider = feed["id"]  # the directory provider id of an identity feed is its cfeed_ id
    synced = feeds_live.directory_users(nano, provider)
    by_ext = {u["external_id"]: u for u in synced}
    timeline.step("directory after run 1", users=len(synced))
    assert set(by_ext) == set(users), (
        f"directory != Graph: missing {sorted(set(users) - set(by_ext))[:5]}, "
        f"extra {sorted(set(by_ext) - set(users))[:5]}"
    )
    for uid, g in users.items():
        u = by_ext[uid]
        assert u.get("upn") == g.get("userPrincipalName"), (uid, u.get("upn"))
        assert (u.get("display_name") or None) == (g.get("displayName") or None), uid
        assert u.get("account_enabled") == g.get("accountEnabled"), uid
        assert u.get("account_status") == ("active" if g.get("accountEnabled") else "disabled"), uid
    # Memberships: every Graph group with user members, and activated roles.
    expected: dict[str, set[str]] = {}
    for gid, m in members.items():
        for uid in m:
            expected.setdefault(uid, set()).add(groups[gid]["displayName"])
    for role, m in roles.items():
        for uid in m:
            expected.setdefault(uid, set()).add(role)
    wrong = {
        uid: (sorted(want), sorted(by_ext[uid].get("groups") or []))
        for uid, want in expected.items()
        if not want <= set(by_ext[uid].get("groups") or [])
    }
    assert not wrong, f"group / role memberships missing from the directory: {dict(list(wrong.items())[:3])}"

    # ---------------------------------------------------------------- run 2: delta, checkpoint
    feeds_live.run_now(nano, feed["id"])
    d2 = feeds_live.wait_run(nano, feed["id"], after=len(feeds_live.finished_runs(d1)))
    cp2 = feeds_live.checkpoints(d2)
    synced2 = feeds_live.directory_users(nano, provider)
    dupes = {k: n for k, n in Counter(u["external_id"] for u in synced2).items() if n > 1}
    timeline.step("run 2", run=feeds_live.finished_runs(d2)[0], checkpoints=cp2, users=len(synced2))
    assert not dupes, f"duplicated directory users after the delta run: {dupes}"
    assert {u["external_id"] for u in synced2} == set(users)
    assert cp2.get("users", 0) > cp1.get("users", 0), f"users checkpoint did not advance: {cp1} -> {cp2}"

    # ---------------------------------------------------------------- rotate
    if not c.rotate_client_secret:
        pytest.fail("NANO_E2E_ENTRA_ROTATE_CLIENT_SECRET missing: the rotate step needs the app's second secret")
    page.driver.register_secret(c.rotate_client_secret)
    feeds_live.rotate_and_prove(
        nano,
        feed["id"],
        feed["credential_id"],
        {"CLIENT_SECRET": "nano-e2e-wrong-secret-" + "y" * 16},
        {"CLIENT_SECRET": c.rotate_client_secret},
        timeline.step,
    )
    assert len(feeds_live.directory_users(nano, provider)) == len(users), "the failed run changed the directory"

    # ---------------------------------------------------------------- bad credential, isolated
    bad = feeds_live.create_feed(
        nano,
        {
            "name": f"{mark}-entra-badcred",
            "connector": "entra_directory",
            "config": _config(c, ""),
            "credentials": {"CLIENT_SECRET": "nano-e2e-wrong-secret-" + "x" * 16},
        },
    )
    feed_cleanup.append(bad["id"])
    failed = feeds_live.wait_failed(nano, bad["id"])["feed"]
    timeline.step("bad credential", error=failed.get("last_error"))
    err = (failed.get("last_error") or "").lower()
    assert any(s in err for s in ("401", "invalid_client", "unauthorized", "aadsts")), (
        f"the error does not say the credential was refused: {failed.get('last_error')!r}"
    )
    assert not feeds_live.directory_users(nano, bad["id"]), "a refused credential synced users"
    row = feeds_live.ui_feed_row(page, f"{mark}-entra-badcred")
    timeline.step("ui: bad credential row", row=row)
    assert row["status"].lower() == "failed", row
    assert failed["last_error"][:40] in row["name"], "the Pull feeds row does not show the error"
    # ... and nothing else is wedged: the good feed runs, Vector ingests.
    before = len(feeds_live.finished_runs(feeds_live.detail(nano, feed["id"])))
    feeds_live.run_now(nano, feed["id"])
    feeds_live.wait_run(nano, feed["id"], after=before)
    assert ingest.hec_health(stack.hec_url) == 200, "Vector HEC unhealthy after the failing feed"
    good = feeds_live.ui_feed_row(page, name)
    assert good["status"].lower() == "healthy", good

    # ---------------------------------------------------------------- delete retires users
    feeds_live.delete_feed(nano, bad["id"])
    feeds_live.delete_feed(nano, feed["id"])
    left = eventually(
        lambda: [u for u in feeds_live.directory_users(nano, provider) if u.get("account_status") != "deleted"],
        timeout=60,
        desc="users of the deleted feed retired (tombstoned)",
        ok=lambda us: not us,
    )
    timeline.step("deleted: users retired", still_live=len(left))
