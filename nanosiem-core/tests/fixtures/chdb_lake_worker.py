#!/usr/bin/env python3
"""Bounded local lake-worker protocol fixture backed by real native chDB.

This is test-only: it implements only the authenticated broad_npl request used
by the enterprise-shared detection integration test. The returned row is
materialized by the exact digest-pinned libchdb C ABI, not a canned JSON body.
"""

import ctypes
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock


LIBRARY = os.environ["NANOSIEM_FIXTURE_CHDB_LIBRARY"]
TOKEN = os.environ["NANOSIEM_FIXTURE_TOKEN"]
TENANT_ID = os.environ["NANOSIEM_FIXTURE_TENANT_ID"]
WORKER_IDENTITY = os.environ["NANOSIEM_FIXTURE_WORKER_IDENTITY"]
WORKER_REVISION = os.environ.get("NANOSIEM_FIXTURE_WORKER_REVISION", "1")
PORT = int(os.environ.get("NANOSIEM_FIXTURE_PORT", "3015"))


class Chdb:
    def __init__(self, path: str):
        self.lib = ctypes.CDLL(path)
        self.lib.chdb_connect.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
        self.lib.chdb_connect.restype = ctypes.POINTER(ctypes.c_void_p)
        self.lib.chdb_close_conn.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self.lib.chdb_query_with_params.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_size_t,
        ]
        self.lib.chdb_query_with_params.restype = ctypes.c_void_p
        self.lib.chdb_result_buffer.argtypes = [ctypes.c_void_p]
        self.lib.chdb_result_buffer.restype = ctypes.c_void_p
        self.lib.chdb_result_length.argtypes = [ctypes.c_void_p]
        self.lib.chdb_result_length.restype = ctypes.c_size_t
        self.lib.chdb_result_error.argtypes = [ctypes.c_void_p]
        self.lib.chdb_result_error.restype = ctypes.c_char_p
        self.lib.chdb_result_elapsed.argtypes = [ctypes.c_void_p]
        self.lib.chdb_result_elapsed.restype = ctypes.c_double
        self.lib.chdb_destroy_query_result.argtypes = [ctypes.c_void_p]
        argv = (ctypes.c_char_p * 2)(b"nano-detection-fixture", b"--path=:memory:")
        self.connection = self.lib.chdb_connect(2, argv)
        if not self.connection or not self.connection.contents.value:
            raise RuntimeError("native chDB fixture connection failed")
        self.lock = Lock()

    def detection_row(self):
        sql = (
            "SELECT 'tenant-b-runtime-event' AS log_id, "
            "'2026-08-28T12:00:00.000000Z' AS timestamp, "
            "'apache' AS source_type FORMAT JSONEachRow"
        )
        with self.lock:
            result = self.lib.chdb_query_with_params(
                self.connection.contents.value,
                sql.encode(),
                b"JSONEachRow",
                None,
                None,
                0,
            )
            if not result:
                raise RuntimeError("native chDB fixture query returned no result")
            try:
                error = self.lib.chdb_result_error(result)
                if error:
                    raise RuntimeError("native chDB fixture query failed")
                length = self.lib.chdb_result_length(result)
                buffer = self.lib.chdb_result_buffer(result)
                body = ctypes.string_at(buffer, length).decode("utf-8")
                rows = [json.loads(line) for line in body.splitlines() if line]
                if len(rows) != 1:
                    raise RuntimeError("native chDB fixture returned an unexpected row count")
                return rows, self.lib.chdb_result_elapsed(result)
            finally:
                self.lib.chdb_destroy_query_result(result)


CHDB = Chdb(LIBRARY)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        if self.path != "/v1/query" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            if request.get("tenant_id") != TENANT_ID or request.get("route") != "broad_npl":
                self.send_error(403)
                return
            rows, wall_seconds = CHDB.detection_row()
            response = json.dumps(
                {
                    "ok": True,
                    "request_id": request["request_id"],
                    "tenant_id": TENANT_ID,
                    "route": "broad_npl",
                    "generation_id": "local-chdb-fixture",
                    "snapshot_id": "1",
                    "wall_seconds": wall_seconds,
                    "result": {
                        "rows": rows,
                        "result_rows": len(rows),
                        "page_has_more": False,
                    },
                },
                separators=(",", ":"),
            ).encode()
        except Exception:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("x-nano-worker-assignment-id", WORKER_IDENTITY)
        self.send_header("x-nano-worker-assignment-revision", WORKER_REVISION)
        self.end_headers()
        self.wfile.write(response)


server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
print("nan2361-local-chdb-worker=ready", flush=True)
server.serve_forever()
