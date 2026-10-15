#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Emit N Sysmon EventID 1 (process create) records as NDJSON for lean/sysmon-http.tql.

Usage: gen_sysmon_sample.py N RUN_MARKER > sysmon.ndjson
Each record carries a unique ProcessGuid and RUN_MARKER-NNNN in its CommandLine,
so a search for RUN_MARKER should return exactly N rows.
"""
import json, sys, uuid, datetime, random
n = int(sys.argv[1]); run = sys.argv[2]
base = datetime.datetime.now(datetime.timezone.utc)
for i in range(n):
    t = base - datetime.timedelta(seconds=n - i)
    pg = "{%s}" % uuid.uuid4()
    rec = {
      "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": random.choice(["WKS-TENZIR01.corp.local", "WKS-TENZIR02.corp.local"]),
      "RecordID": 900000 + i,
      "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
      "ProcessGuid": pg, "ProcessId": 4000 + i,
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "CommandLine": f"cmd.exe /c echo {run}-{i:04d}",
      "CurrentDirectory": "C:\\Users\\jsmith\\",
      "User": "CORP\\jsmith",
      "Hashes": "SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex,
      "ParentProcessGuid": "{%s}" % uuid.uuid4(), "ParentProcessId": 1234,
      "ParentImage": "C:\\Windows\\explorer.exe",
      "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
      "nano_test_run": run, "nano_test_seq": i,
    }
    print(json.dumps(rec))
