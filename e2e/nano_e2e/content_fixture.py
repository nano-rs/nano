"""Signed NAN-4955 content publisher plus a deny-all egress proxy.

This process is started by ``scripts/e2e.sh run content_acceptance`` before
the application. It deliberately uses only the public RFC 8032 test vector;
the matching public key is accepted only by the non-shippable acceptance build.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTENT_DOMAIN = b"nano/content-bundle/descriptor/v1\0"
SOAR_INDEX_DOMAIN = b"nanosiem.soar-catalog.index.signature.v1\n"
TEST_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
CONTENT_KEY_ID = "content-acceptance-nan4955"
SOAR_KEY_ID = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
BLOCKED_HOSTS = ("github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com")

CHANNELS = {
    "parsers.main": ("nano-rs/parsers", "main", "open"),
    "rules.main": ("nano-rs/rules", "main", "open"),
    "playbooks.main": ("nano-rs/playbooks", "main", "open"),
    "enrichments.main": ("nano-rs/nano-enrichments", "main", "open"),
    "integrations.main": ("nano-rs/nano-integrations", "main", "open"),
    "models.main": ("nano-rs/models", "main", "open"),
    "mitre-attack.v19-1": ("mitre-attack/attack-stix-data", "v19.1", "open"),
    "soar-catalog": ("", "", "enterprise"),
}


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json(value: object, *, canonical: bool = False) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=canonical,
        separators=(",", ":"),
    ).encode()


def _git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()  # noqa: S324


def _mitre_acceptance_bundle() -> bytes:
    """Small deterministic STIX catalog accepted only by the dev-key build."""
    return _json(
        {
            "type": "bundle",
            "id": "bundle--nan4955-acceptance",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--nan4955",
                    "name": "Execution",
                    "description": "NAN-4955 signed content acceptance tactic",
                    "x_mitre_shortname": "execution",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "TA0002",
                            "url": "https://attack.mitre.org/tactics/TA0002/",
                        }
                    ],
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--nan4955",
                    "name": "Command and Scripting Interpreter",
                    "description": "NAN-4955 signed content acceptance technique",
                    "x_mitre_is_subtechnique": False,
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                    ],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1059",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                        }
                    ],
                },
            ],
        },
        canonical=True,
    )


def _tree_summary(files: dict[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256()
    total = 0
    for path, content in sorted(files.items()):
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(_git_blob_sha1(content).encode())
        digest.update(b"\n")
        total += len(content)
    return {"files": len(files), "bytes": total, "sha256": digest.hexdigest()}


def _tar(files: dict[str, bytes], *, compressed: bool) -> bytes:
    output = io.BytesIO()
    def append(stream: io.BytesIO | gzip.GzipFile) -> None:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for path, content in sorted(files.items()):
                info = tarfile.TarInfo(path)
                info.size = len(content)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(content))
    if compressed:
        with gzip.GzipFile(fileobj=output, mode="wb", compresslevel=9, mtime=0) as stream:
            append(stream)
    else:
        append(output)
    return output.getvalue()


def _soar_catalog(root: Path, key: Ed25519PrivateKey) -> bytes:
    fixture = root / "nanosiem-enterprise/src/soar/catalog/fixtures/publication-okta"
    release = json.loads((fixture / "release.json").read_text())
    artifact = (fixture / "bundle.tar.gz").read_bytes()
    now = datetime.now(UTC)
    index = {
        "schema_version": 1,
        "revision": str(time.time_ns()),
        "issued_at": _timestamp(now),
        "expires_at": _timestamp(now + timedelta(hours=23)),
        "signing_key_id": SOAR_KEY_ID,
        "releases": [release],
        "withdrawals": [],
    }
    signature = key.sign(SOAR_INDEX_DOMAIN + _json(index, canonical=True)).hex()
    signed = _json({"index": index, "signature_hex": signature})
    artifact_sha = hashlib.sha256(artifact).hexdigest()
    return _tar(
        {"index.json": signed, f"releases/{artifact_sha}.tar.gz": artifact},
        compressed=False,
    )


def _files(channel: str, root: Path, key: Ed25519PrivateKey) -> dict[str, bytes]:
    if channel == "parsers.main":
        return {
            "parsers-ocsf/nan4955/parser.yaml": b"""name: nan4955_fixture
display_name: NAN-4955 Signed Content Fixture Parser
version: \"1.0.0\"
description: Parser delivered by the signed content acceptance publisher
category: application
vendor: nano
product: content-acceptance
match_values:
  - nan4955_fixture
parser_vrl: |
  .message = to_string(.message) ?? \"\"
"""
        }
    if channel == "rules.main":
        return {
            "nan4955_fixture.yml": b"""---
title: NAN-4955 Signed Content Fixture Rule
description: Detection delivered by the signed content acceptance publisher
severity: low
tags:
  - nan4955
---
metadata.log_source = \"nan4955_fixture\"
"""
        }
    if channel == "playbooks.main":
        return {
            "identity/nan4955_fixture.md": b"""---
title: NAN-4955 Signed Content Fixture Playbook
category: identity
tags:
  - nan4955
---

# Validate signed content delivery

/query: source_type = 'nan4955_fixture'
"""
        }
    if channel == "enrichments.main":
        return {
            "enrichments/identity/nan4955_fixture/manifest.yaml": b"""name: NAN-4955 Signed Content Fixture
slug: nan4955_fixture
category: identity
description: Marketplace entry delivered by the signed content acceptance publisher
author: nano
version: 1
requires_credential: none
tags:
  - nan4955
""",
            "enrichments/identity/nan4955_fixture/code.ts": b"export default async function() { return []; }\n",
        }
    if channel == "integrations.main":
        return {
            "integrations/nan4955_fixture/manifest.yaml": b"""name: NAN-4955 Signed Integration Fixture
slug: nan4955_integration_fixture
category: identity
description: Integration catalog delivered by the signed content acceptance publisher
author: nano
version: 1
requires_credential: none
"""
        }
    if channel == "models.main":
        return {"models/nan4955/README.md": b"NAN-4955 signed model catalog fixture.\n"}
    if channel == "mitre-attack.v19-1":
        return {"enterprise-attack/enterprise-attack.json": _mitre_acceptance_bundle()}
    if channel == "soar-catalog":
        return {"soar-catalog.tar": _soar_catalog(root, key)}
    raise KeyError(channel)


@dataclass(frozen=True)
class Release:
    descriptor: dict[str, object]
    signed: dict[str, object]
    container: bytes
    route: str
    tampered: bool


class State:
    def __init__(self, root: Path, journal: Path, base_url: str):
        self.root = root
        self.journal_path = journal
        self.base_url = base_url
        self.key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
        self.lock = threading.RLock()
        self.records: list[dict[str, object]] = []
        self.releases: dict[str, Release] = {}
        sequence = time.time_ns() // 1_000_000
        for offset, channel in enumerate(CHANNELS):
            self.releases[channel] = self._release(channel, sequence + offset, tampered=False)
        self.record("fixture_started", channels=sorted(CHANNELS), blocked_hosts=list(BLOCKED_HOSTS))

    def record(self, kind: str, **fields: object) -> None:
        entry = {"at": _timestamp(datetime.now(UTC)), "kind": kind, **fields}
        with self.lock:
            self.records.append(entry)
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            with self.journal_path.open("a") as output:
                output.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def _release(self, channel: str, sequence: int, *, tampered: bool) -> Release:
        repo, branch, route = CHANNELS[channel]
        files = _files(channel, self.root, self.key)
        payload = _tar(files, compressed=True)
        now = datetime.now(UTC)
        descriptor: dict[str, object] = {
            "format": "nano/content-bundle",
            "format_version": 1,
            "channel": channel,
            "repo": repo,
            "branch": branch,
            "route": route,
            "sequence": sequence,
            "produced_at": _timestamp(now),
            "hard_expiry": _timestamp(now + timedelta(days=29)),
            "upstream": {
                "commit": hashlib.sha1(f"{channel}:{sequence}".encode()).hexdigest() if repo else "",  # noqa: S324
                "committed_at": _timestamp(now),
            },
            "payload": {
                "format": "tar+gzip",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            },
            "tree": _tree_summary(files),
            "signer_key_id": CONTENT_KEY_ID,
        }
        signature = self.key.sign(CONTENT_DOMAIN + _json(descriptor)).hex()
        signed = {"descriptor": descriptor, "signature": signature}
        signed_bytes = _json(signed)
        container = b"NANCONT1" + len(signed_bytes).to_bytes(8, "little") + signed_bytes + payload
        if tampered:
            container = container[:-1] + bytes([container[-1] ^ 1])
        return Release(descriptor, signed, container, route, tampered)

    def publish(self, channel: str, *, tampered: bool) -> Release:
        with self.lock:
            current = self.releases[channel]
            sequence = int(current.descriptor["sequence"]) + 1
            release = self._release(channel, sequence, tampered=tampered)
            self.releases[channel] = release
        self.record("published", channel=channel, sequence=sequence, tampered=tampered)
        return release

    def metadata(self, channel: str) -> dict[str, object]:
        release = self.releases[channel]
        sequence = release.descriptor["sequence"]
        return {
            "descriptor": release.signed,
            "bundle_url": f"{self.base_url}/bundles/{channel}/{sequence}.nancontent",
            "bundle_sha256": release.descriptor["payload"]["sha256"],  # type: ignore[index]
        }


class Handler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status: int, value: object) -> None:
        self._send(status, _json(value), "application/json")

    def _block_proxy(self, host: str) -> None:
        probe = self.headers.get("X-Nano-E2E-Probe") == "1"
        self.server.state.record(
            "blocked_egress",
            method=self.command,
            host=host.lower().split(":", 1)[0],
            target=self.path[:500],
            probe=probe,
        )
        self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "NAN-4955 egress sinkhole"})

    def do_CONNECT(self) -> None:  # noqa: N802
        self._block_proxy(self.path)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            self._block_proxy(parsed.hostname)
            return
        path = unquote(parsed.path)
        state = self.server.state
        if path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "signer_key_id": CONTENT_KEY_ID, "blocked_hosts": BLOCKED_HOSTS},
            )
            return
        if path == "/__journal":
            with state.lock:
                self._send_json(HTTPStatus.OK, {"records": list(state.records)})
            return
        match = re.fullmatch(r"/api/content/v1/(open|enterprise)/([a-z0-9.-]+)/current", path)
        if match:
            route, channel = match.groups()
            release = state.releases.get(channel)
            if release is None or release.route != route:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not published"})
                return
            license_present = bool(self.headers.get("X-Nano-License"))
            if route == "enterprise" and not license_present:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "license required"})
                return
            state.record(
                "metadata",
                channel=channel,
                sequence=release.descriptor["sequence"],
                license_present=license_present,
            )
            self._send_json(HTTPStatus.OK, state.metadata(channel))
            return
        match = re.fullmatch(r"/bundles/([a-z0-9.-]+)/(\d+)[.]nancontent", path)
        if match:
            channel, sequence = match.groups()
            release = state.releases.get(channel)
            if release is None or int(release.descriptor["sequence"]) != int(sequence):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "bundle not found"})
                return
            state.record(
                "bundle",
                channel=channel,
                sequence=int(sequence),
                tampered=release.tampered,
                bytes=len(release.container),
            )
            self._send(HTTPStatus.OK, release.container, "application/octet-stream")
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        match = re.fullmatch(r"/__control/([a-z0-9.-]+)/(tampered|good)", parsed.path)
        if not match:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        channel, mode = match.groups()
        if channel not in CHANNELS:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown channel"})
            return
        release = self.server.state.publish(channel, tampered=mode == "tampered")
        self._send_json(
            HTTPStatus.OK,
            {
                **self.server.state.metadata(channel),
                "sequence": release.descriptor["sequence"],
                "tampered": release.tampered,
            },
        )


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], state: State):
        self.state = state
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    args = parser.parse_args()
    if not args.root.is_absolute() or not args.journal.is_absolute():
        parser.error("--root and --journal must be absolute")
    args.journal.unlink(missing_ok=True)
    base_url = f"http://127.0.0.1:{args.port}"
    state = State(args.root, args.journal, base_url)
    FixtureServer(("127.0.0.1", args.port), state).serve_forever()


if __name__ == "__main__":
    main()
