"""Selftests for the OCSF field-name invariant checker and the persona
exploration helpers (NAN-5291). Fixtures only: no stack, no browser."""

from __future__ import annotations

import pytest

from nano_e2e import corpus, explore, field_invariants, stackenv
from nano_e2e.field_invariants import OcsfContract, Seen, Universe, check, check_name, suggestions_in

CONTRACT = {
    "version": "1.9.0",
    "classes": {
        "authentication": {
            "attributes": {
                "actor": {"type": "object_t", "object_type": "actor"},
                "src_endpoint": {"type": "object_t", "object_type": "network_endpoint"},
                "duration": {"type": "long_t"},
                "unmapped": {"type": "object_t", "object_type": "object"},
            }
        }
    },
    "objects": {
        "actor": {"attributes": {"user": {"type": "object_t", "object_type": "user"}}},
        "user": {"attributes": {"name": {"type": "string_t"}, "uid": {"type": "string_t"}}},
        "network_endpoint": {"attributes": {"ip": {"type": "ip_t"}, "port": {"type": "port_t"}}},
        "object": {"attributes": {}},
    },
}


@pytest.fixture
def universe() -> Universe:
    return Universe(
        schema="ocsf",
        schema_api={"src_endpoint.ip", "actor.user.name", "metadata.log_source"},
        columns={"src_endpoint.ip", "actor.user.name", "source_type", "id", "event", "unmapped", "timestamp"},
        event_paths={"metadata.log_source", "http_request.url.path"},
        unmapped_keys={"okta.debug_context", "vendor_field"},
        udm_names={"src_ip", "dest_ip", "user", "duration", "source_type", "timestamp"},
        contract=OcsfContract(CONTRACT),
    )


def kinds(name: str, u: Universe) -> list[str]:
    return [k for k, _ in check_name(name, u)]


def test_unmapped_unmapped_is_a_doubled_segment(universe: Universe) -> None:
    assert kinds("unmapped.unmapped", universe) == ["doubled-segment"]
    assert kinds("unmapped.unmapped.vendor_field", universe) == ["doubled-segment"]


def test_doubled_segment_anywhere_in_a_path(universe: Universe) -> None:
    assert "doubled-segment" in kinds("actor.user.user.name", universe)
    assert field_invariants.doubled_segment("a.b.a") is None
    assert field_invariants.doubled_segment("a.a") == "a.a"


def test_present_unmapped_key_passes_and_absent_one_fails(universe: Universe) -> None:
    assert kinds("unmapped.vendor_field", universe) == []
    assert kinds("unmapped.okta.debug_context", universe) == []
    assert kinds("unmapped.never_seen", universe) == ["unmapped-absent"]
    assert kinds("unmapped", universe) == []  # the spill column itself


def test_udm_alias_flagged_but_ocsf_homonym_is_canonical(universe: Universe) -> None:
    assert kinds("src_ip", universe) == ["udm-alias"]
    assert kinds("user", universe) == ["udm-alias"]
    # `duration` is a UDM name AND an OCSF class attribute: canonical.
    assert kinds("duration", universe) == []
    # `timestamp` is a physical promoted column: fine.
    assert kinds("timestamp", universe) == []


def test_ocsf_paths_from_columns_live_paths_and_contract(universe: Universe) -> None:
    assert kinds("src_endpoint.ip", universe) == []  # promoted column
    assert kinds("http_request.url.path", universe) == []  # present in event
    assert kinds("actor.user.uid", universe) == []  # contract-only (no data yet)
    assert kinds("src_endpoint.port", universe) == []
    assert kinds("actor.usr.name", universe) == ["not-in-schema"]


def test_ext_prefix_and_udm_era_and_internal_columns(universe: Universe) -> None:
    assert kinds("ext.foo", universe) == ["ext-prefix"]
    assert kinds("source_type", universe) == ["udm-era-column"]
    assert kinds("id", universe) == ["internal-column"]


def test_check_dedupes_per_surface_and_grades_severity(universe: Universe) -> None:
    seen = [
        Seen("ui:sidebar", "unmapped.unmapped"),
        Seen("ui:sidebar", "unmapped.unmapped"),
        Seen("api:field-stats", "unmapped.unmapped"),
        Seen("ui:sidebar", "source_type"),
        Seen("ui:sidebar", "actor.user.name"),
        Seen("ui:sidebar", "  "),
    ]
    got = check(seen, universe)
    assert [(v.surface, v.name, v.kind) for v in got] == [
        ("ui:sidebar", "unmapped.unmapped", "doubled-segment"),
        ("api:field-stats", "unmapped.unmapped", "doubled-segment"),
        ("ui:sidebar", "source_type", "udm-era-column"),
    ]
    assert [v.severity for v in got] == ["error", "error", "warn"]


def test_allow_list_suppresses(universe: Universe) -> None:
    universe.allow.add("src_ip")
    assert kinds("src_ip", universe) == []


def test_only_suggestions_are_taken_from_validation_messages() -> None:
    msg = "Unknown field 'src_ip' in the OCSF schema. Did you mean 'src_endpoint.ip', 'src_endpoint.port'?"
    assert suggestions_in(msg) == ["src_endpoint.ip", "src_endpoint.port"]
    warn = (
        "Field 'dest_ip' has no OCSF mapping on this tenant and reads an empty value. "
        "Did you mean 'dst_endpoint.ip'?"
    )
    assert suggestions_in(warn) == ["dst_endpoint.ip"]
    avail = "Unknown field 'zzz'. Available fields include 'timestamp', 'message'."
    assert suggestions_in(avail) == ["timestamp", "message"]
    assert (
        suggestions_in("Field 'x' has no OCSF mapping on this tenant. Use an OCSF field path instead.") == []
    )


def test_embedded_contract_resolves_real_paths() -> None:
    real = OcsfContract.load()
    if real is None:
        pytest.skip("embedded OCSF contract not in this tree")
    assert real.has_path("src_endpoint.ip")
    assert real.has_path("actor.user.name")
    assert not real.has_path("src_endpoint.src_endpoint")
    assert not real.has_path("src_ip")


def test_udm_names_parse_from_the_web_bundle() -> None:
    names = field_invariants.udm_names_from_ts()
    if not names:
        pytest.skip("nanosiem-web udm-fields.ts not in this tree")
    assert {"src_ip", "dest_ip", "command_line"} <= names


def test_report_lists_errors_before_warnings(universe: Universe) -> None:
    v = check([Seen("s", "source_type"), Seen("s", "unmapped.unmapped")], universe)
    text = field_invariants.report(v, [Seen("s", "source_type"), Seen("s", "unmapped.unmapped")], universe)
    assert "1 error(s), 1 warning(s)" in text
    assert text.index("doubled-segment") < text.index("udm-era-column")


# ---------------------------------------------------------------- corpus
PARSER_YAML = """
name: okta_ocsf
match_values: [okta, okta_system]
samples:
  - raw: '{"eventType":"user.session.start"}'
    expect: {}
  - raw: '{"eventType":"user.lifecycle.deactivate"}'
"""


def test_corpus_reads_samples_from_the_repo_listing() -> None:
    listing = [
        {"file_path": "parsers-ocsf/okta/parser.yaml", "raw_content": PARSER_YAML},
        {"file_path": "parsers/okta/parser.yaml", "raw_content": PARSER_YAML},  # UDM tree: not the corpus
        {"file_path": "parsers-ocsf/empty/parser.yaml", "raw_content": "name: empty\nmatch_values: [e]\n"},
        {"file_path": "parsers-ocsf/broken/parser.yaml", "raw_content": "name: [unclosed"},
    ]
    got = corpus.corpus_from_listing(listing)
    assert [(c.name, c.lane, len(c.samples)) for c in got] == [("okta_ocsf", "okta", 2)]
    assert got[0].samples[0] == '{"eventType":"user.session.start"}'


def test_corpus_summary_flags_empty_partial_and_class_zero() -> None:
    ok = corpus.CorpusParser("p/a", "a", ["a"], ["x"], sent=1, landed=1, classes={"3002": 1})
    part = corpus.CorpusParser("p/b", "b", ["b"], ["x", "y"], sent=2, landed=1, classes={"0": 1})
    empty = corpus.CorpusParser("p/c", "c", ["c"], ["x"], sent=1)
    text = corpus.summary([ok, part, empty])
    assert "2 parser(s) with nothing" not in text and "1 parser(s) with nothing" in text
    assert "PARTIAL" in text and "Base Event class 0" in text and "EMPTY" in text


# ---------------------------------------------------------------- stackenv + explore CLI
def test_stackenv_parse_ignores_comments_and_keeps_raw_values() -> None:
    env = stackenv.parse("# header\nA_B=1\nURL=http://x:1/?a=b=c\nbad line\n=nokey\n")
    assert env == {"A_B": "1", "URL": "http://x:1/?a=b=c"}


def test_explore_cli_builds_finders_and_requests() -> None:
    ap = explore.build_parser()
    ns = ap.parse_args(["click", "--role", "button", "--name", "^Save", "--regex"])
    assert explore.request_args(ns) == {"find": {"role": "button", "name": {"re": "^Save", "flags": "i"}}}
    ns = ap.parse_args(["type", "src_endpoint.ip=", "--css", ".cm-content", "--clear"])
    assert explore.request_args(ns) == {
        "find": {"css": ".cm-content"},
        "text": "src_endpoint.ip=",
        "clear": True,
    }
    ns = ap.parse_args(["idle", "10", "--reload"])
    assert explore.request_args(ns) == {"minutes": 10.0, "reload": True}
    ns = ap.parse_args(["search", "*", "--start", "2000-01-01T00:00:00Z"])
    assert explore.request_args(ns) == {"query": "*", "start": "2000-01-01T00:00:00Z", "end": None}
    with pytest.raises(SystemExit):
        explore.request_args(ap.parse_args(["click"]))


def test_explore_personas_match_the_scripted_suite() -> None:
    assert set(explore.PERSONAS) == {
        "soc_analyst",
        "siem_engineer",
        "detection_engineer",
        "incident_responder",
        "platform_admin",
    }
    assert all(explore.PERSONAS.values())


def test_stale_explore_socket_is_cleared() -> None:
    import socket
    import tempfile
    from pathlib import Path

    sock = Path(tempfile.mkdtemp(dir="/tmp")) / "s.sock"  # noqa: S108 - AF_UNIX path limit
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    s.close()  # a killed daemon leaves the file behind, nobody listening
    assert sock.exists()
    assert explore._alive(sock) is False
    assert not sock.exists()


def test_corpus_skips_lanes_that_are_not_identifiers() -> None:
    bad = PARSER_YAML.replace("[okta, okta_system]", "['okta\" OR 1=1']")
    assert corpus.corpus_from_listing([{"file_path": "parsers-ocsf/x/parser.yaml", "raw_content": bad}]) == []
