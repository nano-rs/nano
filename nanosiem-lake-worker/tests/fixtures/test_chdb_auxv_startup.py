#!/usr/bin/env python3
"""Run as root in a disposable Linux container with the cell release artifact.

NANO_QUERY_TEST_BIN points to the newly built lake_part_query binary.
After Jailed, verify the child retains libchdb, then send Shutdown.
No bootstrap secrets or control-plane requests are needed.
The test driver needs CAP_SYS_PTRACE to inspect the non-dumpable child.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


class ChdbAuxvStartup(unittest.TestCase):
    def test_query_and_detect_start_with_large_spawn_environment(self):
        binary = os.environ["NANO_QUERY_TEST_BIN"]
        for role, rules in [("query", False), ("detect", True)]:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o755)
                state, tmp = root / "state", root / "tmp"
                for path in [state, tmp]:
                    path.mkdir(mode=0o700)
                    os.chown(path, 12345, 12345)
                parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                parent.settimeout(60)
                environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
                environment.update({f"NAN3100_EXTRA_{i}": "x" * 256 for i in range(512)})
                # fd3 is the production control socket; dup2 runs only in this
                # single-threaded test driver before exec.
                process = subprocess.Popen(
                    [binary, "--cell-control-fd", "3"], env=environment,
                    pass_fds=(parent.fileno(), child.fileno()),
                    preexec_fn=lambda: os.dup2(child.fileno(), 3),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                child.close()
                try:
                    hello = json.loads(parent.recv(65536))
                    self.assertEqual(hello["type"], "hello")
                    assignment = {
                        "tenant": "auxv-fixture", "role": role, "cell_id": "fixture",
                        "tenant_dir": directory, "parts_dir": directory,
                        "state_dir": str(state), "tmp_dir": str(tmp), "feed_dir": None,
                        "memory_cap_bytes": 1073741824, "cpu_millis": 1000, "eps": 1,
                        "detect_runs_rules": rules,
                        "jail": {
                            "uid": 12345, "gid": 12345,
                            "rw_paths": [str(state), str(tmp)], "ro_paths": [],
                            "system_ro_paths": ["/usr", "/lib", "/lib64", "/etc"],
                            "tcp_connect_ports": [], "cgroup_dir": None,
                            "require_landlock": True, "max_processes": None,
                            "max_open_files": 1024,
                        },
                    }
                    parent.send(json.dumps({"type": "assign", "protocol_version": 2,
                                            "assignment": assignment}).encode())
                    jailed = json.loads(parent.recv(65536))
                    self.assertEqual(jailed["type"], "jailed", jailed)
                    self.assertEqual(jailed["uid"], 12345)
                    self.assertTrue(jailed["seccomp"])
                    self.assertNotEqual(jailed["landlock"], "none")
                    maps = Path(f"/proc/{hello['pid']}/maps").read_text()
                    self.assertIn("/usr/local/lib/nano-chdb/libchdb.so", maps,
                                  "native runtime must be initialized and retained before Jailed")
                    parent.send(b'{"type":"shutdown","grace_ms":1000}')
                    _, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, stderr.decode())
                finally:
                    parent.close()
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    process.stderr.close()


if __name__ == "__main__":
    unittest.main()
