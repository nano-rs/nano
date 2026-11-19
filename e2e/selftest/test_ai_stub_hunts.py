"""NAN-5561: the AI stub's scripted hunt tool calls (stateless, history-driven)."""

from __future__ import annotations

import json

from nano_e2e.ai_stub import HUNT_FILE_CRITICAL_MARKER, hunt_tool_calls

FIN = "fin-ws-r1"
SCCM = "sccm-r1"
E1 = "0195a000-0000-7000-8000-000000000001"
E2 = "0195a000-0000-7000-8000-000000000002"


def tools(*names: str) -> list[dict]:
    return [{"type": "function", "function": {"name": n, "parameters": {}}} for n in names]


def assistant(name: str, args: dict) -> dict:
    return {"role": "assistant", "tool_calls": [
        {"id": "c", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def names(result) -> list[str]:
    kind, calls = result
    assert isinstance(calls, list), (kind, calls)
    return [c["function"]["name"] for c in calls]


def args(result) -> dict:
    return json.loads(result[1][0]["function"]["arguments"])


def test_non_hunt_requests_fall_through() -> None:
    assert hunt_tool_calls({"messages": [{"role": "user", "content": "hi"}]}) is None


def test_the_investigator_files_the_lead_then_the_benign_twin_then_finishes() -> None:
    prompt = (f'{{"id": "{E1}", "device.hostname": "{FIN}", "process.name": "powershell.exe"}}\n'
              f'{{"id": "{E2}", "device.hostname": "{SCCM}", "process.name": "powershell.exe"}}')
    body = {"tools": tools("file_finding", "finish", "search"), "messages": [{"role": "user", "content": prompt}]}
    first = hunt_tool_calls(body)
    assert names(first) == ["file_finding"]
    assert args(first)["class"] == "lead" and args(first)["entity_value"] == FIN
    assert args(first)["evidence_event_ids"] == [E1]
    body["messages"].append(assistant("file_finding", args(first)))
    body["messages"].append({"role": "tool", "content": "filed lead"})
    second = hunt_tool_calls(body)
    assert args(second)["class"] == "benign" and args(second)["entity_value"] == SCCM
    body["messages"].append(assistant("file_finding", args(second)))
    body["messages"].append({"role": "tool", "content": "filed benign sccm"})
    assert names(hunt_tool_calls(body)) == ["finish"]


def test_a_charter_marker_files_the_lead_at_critical() -> None:
    """NAN-5663: the duplicate gate's worse variant (same chain, higher severity)."""
    row = f'{{"id": "{E1}", "device.hostname": "{FIN}", "process.name": "powershell.exe"}}'
    plain = {"tools": tools("file_finding", "finish"), "messages": [{"role": "user", "content": row}]}
    assert args(hunt_tool_calls(plain))["severity"] == "high"
    marked = {"tools": tools("file_finding", "finish"),
              "messages": [{"role": "user", "content": f"CHARTER notes: {HUNT_FILE_CRITICAL_MARKER}\n{row}"}]}
    first = args(hunt_tool_calls(marked))
    assert first["severity"] == "critical" and first["entity_value"] == FIN and first["evidence_event_ids"] == [E1]


def test_the_reviewer_reads_evidence_first_then_records_one_verdict() -> None:
    lead = "lead_01h455vb4pex5vsknk084sn02q"
    body = {"tools": tools("record_verdict", "get_events", "read_investigator_reasoning"),
            "messages": [{"role": "user", "content":
                f"memory: lead_00000000000000000000000000 ruled\nentity_value: {FIN}\nevidence {E1}\nFINDING {lead} from hunt"}]}
    first = hunt_tool_calls(body)
    assert names(first) == ["get_events"] and args(first)["ids"] == [E1]
    body["messages"].append(assistant("get_events", args(first)))
    body["messages"].append({"role": "tool", "content": f'{{"id": "{E1}"}}'})
    verdict = hunt_tool_calls(body)
    assert names(verdict) == ["record_verdict"]
    assert args(verdict)["verdict"] == "escalated" and args(verdict)["cited_event_ids"] == [E1]
    assert args(verdict)["lead_id"] == lead, "the finding under review, never a memory lead id"
    body["messages"].append(assistant("record_verdict", args(verdict)))
    assert hunt_tool_calls(body)[1] == "Review complete."


def test_recheck_and_eval_answer_in_one_call() -> None:
    assert args(hunt_tool_calls({"tools": tools("record_recheck"), "messages": []}))["verdict"] == "quiet"
    benign = hunt_tool_calls({"tools": tools("record_eval_verdict"),
                              "messages": [{"role": "user", "content": f"entity {SCCM} CcmExec.exe"}]})
    assert args(benign)["verdict"] == "benign"
    bad = hunt_tool_calls({"tools": tools("record_eval_verdict"),
                           "messages": [{"role": "user", "content": f"entity {FIN} WINWORD"}]})
    assert args(bad)["verdict"] == "escalated"
