#!/usr/bin/env python3
"""Assert zero network syscalls during the real native search fixture.

Pass the already-built stored_enrichment_native test executable. The caller
supplies NANO_CHDB_LIBRARY_PATH, its verified digest, and NANO_LAKE_COMPILER.
Artifact-read/feed-match counters are asserted inside the audit-feature binary.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="nan2469-trace-") as directory:
    trace = pathlib.Path(directory) / "syscalls"
    subprocess.run([
        "strace", "-f", "-qq", "-e", "trace=network,write", "-o", str(trace),
        sys.argv[1], "--nocapture", "--test-threads=1",
    ], check=True)
    lines = trace.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if "NAN2469_NATIVE_SEARCH_BEGIN" in line)
    end = next(i for i, line in enumerate(lines) if "NAN2469_NATIVE_SEARCH_END" in line)
    ipc = [line for line in lines[start:end] if "socketpair(AF_UNIX," in line]
    network = [line for line in lines[start:end] if line not in ipc and re.search(
        r"\b(socket|socketpair|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg|sendmmsg|recvmmsg|getpeername|getsockname|setsockopt|getsockopt|shutdown)\(", line)]
    assert not network, "native search performed network IO:\n" + "\n".join(network)
    print(f"NAN2469 native search: network syscalls=0; local subprocess socketpairs={len(ipc)}; artifact/feed counters asserted by fixture")
