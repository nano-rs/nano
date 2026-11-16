#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build the public benchmark's detection set (rules.json), deterministically.

200 scheduled rules in the shape a SOC actually runs (every 1 or 5 minutes),
written in nPL against the OCSF schema (the default for new installs). The
mix is weighted toward endpoint, like the generated data (about 60% Sysmon).

  python3 benchmarks/public/detections/build_rules.py > benchmarks/public/detections/rules.json

The output is committed, so a run never depends on this script's environment.
Each rule body is the POST /api/rules request (NewDetectionRule); setup_content.py
sets `mode` per run (alerting by default).
"""
import json

LOLBINS = [
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
    "cscript.exe", "wscript.exe", "installutil.exe", "msbuild.exe", "regasm.exe", "regsvcs.exe",
    "odbcconf.exe", "cmstp.exe", "forfiles.exe", "pcalua.exe", "msiexec.exe", "schtasks.exe",
    "at.exe", "sc.exe", "reg.exe", "vssadmin.exe", "wevtutil.exe", "bcdedit.exe", "fsutil.exe",
    "nltest.exe", "dsquery.exe", "adfind.exe", "net1.exe", "whoami.exe", "quser.exe", "qwinsta.exe",
    "psexec.exe", "psexesvc.exe", "procdump.exe", "ntdsutil.exe", "esentutl.exe", "expand.exe",
    "makecab.exe", "hh.exe",
]
LOLBIN_TECH = {"rundll32.exe": "T1218.011", "regsvr32.exe": "T1218.010", "mshta.exe": "T1218.005",
               "certutil.exe": "T1105", "bitsadmin.exe": "T1197", "wmic.exe": "T1047",
               "vssadmin.exe": "T1490", "wevtutil.exe": "T1070.001", "schtasks.exe": "T1053.005",
               "psexec.exe": "T1569.002", "procdump.exe": "T1003.001", "ntdsutil.exe": "T1003.003"}

CMDLINE = [
    ("encoded powershell", r"-enc(odedcommand)?\s", "T1059.001"),
    ("powershell download cradle", r"downloadstring|downloadfile|invoke-webrequest|iwr\s", "T1105"),
    ("powershell hidden window", r"-w(indowstyle)?\s+hidden", "T1564.003"),
    ("powershell bypass policy", r"-ep\s+bypass|-executionpolicy\s+bypass", "T1059.001"),
    ("invoke-expression", r"\biex\b|invoke-expression", "T1059.001"),
    ("mimikatz keywords", r"sekurlsa|kerberos::|lsadump::", "T1003.001"),
    ("shadow copy delete", r"shadowcopy\s+delete|delete\s+shadows", "T1490"),
    ("event log clear", r"cl\s+(security|system|application)|clear-eventlog", "T1070.001"),
    ("user add", r"net(1)?\s+user\s+\S+\s+\S+\s+/add", "T1136.001"),
    ("local admin add", r"net(1)?\s+localgroup\s+administrators\s+\S+\s+/add", "T1098"),
    ("domain admins enum", r"net(1)?\s+group\s+\"?domain admins", "T1069.002"),
    ("scheduled task create", r"schtasks(\.exe)?\s+/create", "T1053.005"),
    ("service create", r"sc(\.exe)?\s+create", "T1543.003"),
    ("run key persistence", r"currentversion\\\\run", "T1547.001"),
    ("certutil decode", r"certutil.*-decode", "T1140"),
    ("certutil urlcache", r"certutil.*-urlcache", "T1105"),
    ("regsvr32 scrobj", r"regsvr32.*scrobj", "T1218.010"),
    ("rundll32 javascript", r"rundll32.*javascript:", "T1218.011"),
    ("mshta http", r"mshta.*https?://", "T1218.005"),
    ("wmic process call create", r"wmic.*process\s+call\s+create", "T1047"),
    ("wmic shadowcopy", r"wmic.*shadowcopy", "T1490"),
    ("bcdedit recovery off", r"bcdedit.*recoveryenabled\s+no", "T1490"),
    ("defender exclusion", r"add-mppreference.*exclusion", "T1562.001"),
    ("defender disable", r"set-mppreference.*disable", "T1562.001"),
    ("firewall disable", r"netsh.*advfirewall.*state\s+off", "T1562.004"),
    ("rdp enable", r"fdenytsconnections.*0", "T1021.001"),
    ("lsass access via comsvcs", r"comsvcs.*minidump", "T1003.001"),
    ("ntds copy", r"ntds\.dit", "T1003.003"),
    ("sam hive save", r"reg(\.exe)?\s+save\s+hklm\\\\sam", "T1003.002"),
    ("whoami all", r"whoami\s+/all", "T1033"),
    ("nltest trusts", r"nltest.*domain_trusts", "T1482"),
    ("ping sweep", r"for\s+/l.*ping", "T1018"),
    ("base64 in cmdline", r"frombase64string", "T1027"),
    ("curl to raw ip", r"curl(\.exe)?\s+.*https?://\d+\.\d+\.\d+\.\d+", "T1105"),
    ("archive staging", r"(7z|rar|zip)(\.exe)?\s+a\s+.*-p", "T1560.001"),
]

PARENT_CHILD = [(p, c) for p in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
                for c in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")]

# Ports a Windows fleet does not normally talk to (no 445/3389/5985: those are
# everyday internal traffic and would bury the SOC in findings).
PORTS = [4444, 5555, 1337, 31337, 6666, 6667, 6697, 8081, 8888, 9001, 9050, 1080, 3128, 2222, 4433,
         50050, 7777, 12345, 54321, 1234, 10000, 20000, 65535, 23, 69]

AUTH = [(n, t) for n in (10, 20, 50, 100, 200) for t in ("user.name", "src_endpoint.ip", "dst_endpoint.hostname", "actor.user.name")]

PROXY = [
    ("pastebin", r"pastebin\.com"), ("raw github", r"raw\.githubusercontent\.com"), ("ngrok", r"ngrok\.(io|app)"),
    ("dynamic dns", r"duckdns\.org|no-ip\.|dyndns"), ("file sharing", r"transfer\.sh|file\.io|mega\.nz"),
    ("tor gateway", r"\.onion\.|tor2web"), ("discord cdn", r"cdn\.discordapp\.com"), ("telegram api", r"api\.telegram\.org"),
    ("ip literal host", r"^\d+\.\d+\.\d+\.\d+$"), ("long subdomain", r"^[a-z0-9]{30,}\."),
    ("punycode", r"xn--"), ("free tld", r"\.(tk|ml|ga|cf|gq)$"), ("crypto mining pool", r"pool\.|mining|xmr"),
    ("anonymizer", r"proxy|anonym|hide"), ("cloud storage exfil", r"dropbox|drive\.google|onedrive"),
]
PROXY_THRESH = [(code, n) for code in (403, 404, 407, 500, 502) for n in (50, 200)]

CLOUD_OPS = ["ConsoleLogin", "CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutBucketPolicy",
             "PutBucketAcl", "DeleteTrail", "StopLogging", "UpdateTrail", "AuthorizeSecurityGroupIngress",
             "CreateLoginProfile", "UpdateAssumeRolePolicy", "DisableKey", "ScheduleKeyDeletion", "GetSecretValue"]

# High-signal tool launches, run every minute. The first five match processes
# the generated fleet runs every few minutes, so event-to-alert latency is
# always measured; the rest are tools a clean fleet never runs.
TOOLS = ["rundll32.exe", "sc.exe", "wmic.exe", "reg.exe", "schtasks.exe",
            "mimikatz.exe", "psexesvc.exe", "procdump.exe", "ntdsutil.exe", "adfind.exe", "rclone.exe",
            "anydesk.exe", "ngrok.exe", "plink.exe", "nc.exe", "socat.exe", "chisel.exe", "sharphound.exe",
            "rubeus.exe", "seatbelt.exe"]


# ATT&CK tactic ID for each technique used above (nano requires both or neither,
# and validates the pair against its ATT&CK catalog).
TACTIC = {
    "T1218.011": "TA0005", "T1218.010": "TA0005", "T1218.005": "TA0005",
    "T1105": "TA0011", "T1197": "TA0005", "T1047": "TA0002", "T1490": "TA0040",
    "T1070.001": "TA0005", "T1053.005": "TA0003", "T1569.002": "TA0002",
    "T1003.001": "TA0006", "T1003.002": "TA0006", "T1003.003": "TA0006",
    "T1059.001": "TA0002", "T1564.003": "TA0005", "T1136.001": "TA0003",
    "T1098": "TA0003", "T1069.002": "TA0007", "T1543.003": "TA0003",
    "T1547.001": "TA0003", "T1140": "TA0005", "T1562.001": "TA0005",
    "T1562.004": "TA0005", "T1021.001": "TA0008", "T1033": "TA0007",
    "T1482": "TA0007", "T1018": "TA0007", "T1027": "TA0005", "T1560.001": "TA0009",
    "T1204.002": "TA0002", "T1571": "TA0011", "T1110": "TA0006",
    "T1071.001": "TA0011", "T1078.004": "TA0001",
}


def npl_regex(rx):
    """nPL regex literals are /.../flags: a `/` inside would end the literal
    and a group followed by `?` trips the parser, so match `/` with `.` and
    write optional single characters without a group."""
    return rx.replace("/", ".").replace("(1)?", "1?")


def rule(i, cat, title, query, severity, tech=None, every_minute=False):
    r = {
        "name": f"bench-{i:03d} {cat}: {title}",
        "description": f"nano public benchmark detection ({cat}).",
        "query": query,
        "severity": severity,
        "tags": ["nano-benchmark", cat],
        "author": "nano benchmark",
        "alert_cooldown_minutes": 30,
    }
    if tech:
        r["mitre_techniques"] = [tech]
        r["mitre_tactics"] = [TACTIC[tech]]
    r.update({"detection_mode": "scheduled",
              "schedule_cron": "* * * * *" if every_minute else "*/5 * * * *",
              "lookback_minutes": 2 if every_minute else 5})
    return r


def build():
    rules, i = [], 0

    def add(*a, **k):
        nonlocal i
        i += 1
        rules.append(rule(i, *a, every_minute=k.pop("every_minute", i % 5 == 0), **k))

    for b in LOLBINS:
        add("endpoint", f"{b} execution", f'class_uid=1007 process.name="{b}"', "medium", LOLBIN_TECH.get(b))
    for title, rx, tech in CMDLINE:
        add("endpoint", title, f"class_uid=1007 process.cmd_line=/{npl_regex(rx)}/i", "high", tech)
    for p, c in PARENT_CHILD:
        add("endpoint", f"{p} spawns {c}",
            f'class_uid=1007 process.parent_process.name="{p}" process.name="{c}"', "high", "T1204.002")
    for port in PORTS:
        add("network", f"outbound to port {port}",
            f"class_uid=4001 dst_endpoint.port={port} | stats count as conns, dc(dst_endpoint.ip) as dsts by src_endpoint.ip",
            "low", "T1571")
    for n, field in AUTH:
        add("identity", f"{n}+ failed logons by {field}",
            f"class_uid=3002 status_id=2 | stats count as failures by {field} | where failures > {n}", "medium", "T1110")
    for title, rx in PROXY:
        add("proxy", f"egress to {title}", f"class_uid=4002 http_request.url.hostname=/{npl_regex(rx)}/i", "medium",
            "T1071.001")
    for code, n in PROXY_THRESH:
        add("proxy", f"{n}+ HTTP {code} by source",
            f"class_uid=4002 http_response.code={code} | stats count as hits by src_endpoint.ip | where hits > {n}",
            "low", "T1071.001")
    for op in CLOUD_OPS:
        add("cloud", f"CloudTrail {op}", f'class_uid=6003 api.operation="{op}"', "medium", "T1078.004")
    for b in TOOLS:
        add("tools", f"{b} launched", f'class_uid=1007 process.name="{b}"', "high", None, every_minute=True)
    assert len(rules) == 200, len(rules)
    return rules


if __name__ == "__main__":
    rs = build()
    print(json.dumps({"version": 1, "count": len(rs),
                      "rules": rs}, indent=1))
