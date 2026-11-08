#!/usr/bin/env python3
"""Verify and safely stage a signed nano v2 compose bootstrap.

This verifier intentionally uses only the Python standard library and supports
Python 3.8+, the Python version shipped by Ubuntu 20.04. Its own SHA-256 is
published independently of the release artifacts it verifies.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import os
import re
import shutil
import stat
import sys
import tarfile
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 25_000
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 512
MAX_PUBLIC_KEY_BYTES = 4 * 1024
MAX_SIGNATURE_BYTES = 64
READ_CHUNK = 1024 * 1024
ARCHIVE_NAME = re.compile(
    r"^nano-compose-(open|enterprise)-"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.tar\.gz$"
)

# Ed25519 constants from RFC 8032. The implementation is verification-only;
# release signing remains in the protected KMS workflow.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class BootstrapError(RuntimeError):
    """A bounded, operator-facing bootstrap verification failure."""


def _point_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _point_multiply(
    scalar: int, point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> bool:
    return (
        left[0] * right[2] % _P == right[0] * left[2] % _P
        and left[1] * right[2] % _P == right[1] * left[2] % _P
    )


def _recover_x(y: int, sign_bit: int) -> int:
    if y >= _P:
        raise BootstrapError("Ed25519 point encoding is not canonical")
    denominator = (_D * y * y + 1) % _P
    if denominator == 0:
        raise BootstrapError("Ed25519 point is invalid")
    x_squared = (y * y - 1) * pow(denominator, _P - 2, _P) % _P
    x = pow(x_squared, (_P + 3) // 8, _P)
    if (x * x - x_squared) % _P:
        x = x * _I % _P
    if (x * x - x_squared) % _P:
        raise BootstrapError("Ed25519 point is not on the curve")
    if (x & 1) != sign_bit:
        x = (-x) % _P
    if x == 0 and sign_bit:
        raise BootstrapError("Ed25519 point has a non-canonical sign bit")
    return x


def _decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise BootstrapError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, value >> 255)
    return x, y, 1, x * y % _P


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
_BASE_POINT = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Strictly verify one Ed25519 signature or raise BootstrapError."""
    if len(public_key) != 32 or len(signature) != 64:
        raise BootstrapError("Ed25519 public key or signature has an invalid size")
    encoded_r, encoded_s = signature[:32], signature[32:]
    point_a = _decode_point(public_key)
    point_r = _decode_point(encoded_r)
    scalar_s = int.from_bytes(encoded_s, "little")
    if scalar_s >= _L:
        raise BootstrapError("Ed25519 signature scalar is not canonical")
    if _point_equal(point_a, _IDENTITY) or not _point_equal(
        _point_multiply(_L, point_a), _IDENTITY
    ):
        raise BootstrapError("Ed25519 public key is not in the prime-order subgroup")
    if not _point_equal(_point_multiply(_L, point_r), _IDENTITY):
        raise BootstrapError("Ed25519 signature point is not in the prime-order subgroup")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % _L
    expected = _point_add(point_r, _point_multiply(challenge, point_a))
    if not _point_equal(_point_multiply(scalar_s, _BASE_POINT), expected):
        raise BootstrapError("compose bootstrap signature verification failed")


@contextlib.contextmanager
def _open_regular(path: Path, label: str, maximum: int) -> Iterator[BinaryIO]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BootstrapError(f"cannot open {label} as a non-symlink file: {path}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise BootstrapError(f"{label} must be a non-empty bounded regular file")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            yield source
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded(path: Path, label: str, maximum: int) -> bytes:
    with _open_regular(path, label, maximum) as source:
        value = source.read(maximum + 1)
        if len(value) > maximum or len(value) != os.fstat(source.fileno()).st_size:
            raise BootstrapError(f"{label} changed or exceeded its size limit while read")
        return value


def _public_key_from_pem(path: Path) -> bytes:
    raw = _read_bounded(path, "release public key", MAX_PUBLIC_KEY_BYTES)
    lines = raw.splitlines()
    if (
        len(lines) != 3
        or lines[0] != b"-----BEGIN PUBLIC KEY-----"
        or lines[2] != b"-----END PUBLIC KEY-----"
    ):
        raise BootstrapError("release public key is not a canonical one-line PEM")
    try:
        der = base64.b64decode(lines[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise BootstrapError("release public key PEM is invalid base64") from error
    if len(der) != len(_SPKI_PREFIX) + 32 or not der.startswith(_SPKI_PREFIX):
        raise BootstrapError("release public key is not an Ed25519 SubjectPublicKeyInfo key")
    return der[len(_SPKI_PREFIX) :]


def public_key_fingerprint(path: Path) -> str:
    """Return SHA-256 over the canonical Ed25519 SubjectPublicKeyInfo DER."""
    public_key = _public_key_from_pem(path)
    return hashlib.sha256(_SPKI_PREFIX + public_key).hexdigest()


def _sha256(source: BinaryIO) -> str:
    source.seek(0)
    digest = hashlib.sha256()
    while True:
        block = source.read(READ_CHUNK)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def _archive_identity(source: BinaryIO) -> tuple[int, int, int, int, int]:
    info = os.fstat(source.fileno())
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _member_name(raw: str, root: str) -> str:
    if not raw or "\\" in raw or "\x00" in raw or any(ord(char) < 0x20 for char in raw):
        raise BootstrapError("compose archive contains an invalid member name")
    name = raw[:-1] if raw.endswith("/") else raw
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BootstrapError(f"compose archive member path is unsafe: {raw!r}")
    if parts[0] != root:
        raise BootstrapError(f"compose archive member escapes required root {root!r}")
    return name


def _is_regular_member(member: tarfile.TarInfo) -> bool:
    return member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}


def _is_sparse_member(member: tarfile.TarInfo) -> bool:
    return (
        member.type == tarfile.GNUTYPE_SPARSE
        or member.sparse is not None
        or any(key.startswith("GNU.sparse.") for key in member.pax_headers)
        or "SCHILY.realsize" in member.pax_headers
    )


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, maximum: int) -> bytes:
    if member.size > maximum:
        raise BootstrapError(f"compose archive metadata file is too large: {member.name}")
    source = archive.extractfile(member)
    if source is None:
        raise BootstrapError(f"compose archive cannot read required file: {member.name}")
    value = source.read(maximum + 1)
    if len(value) != member.size or len(value) > maximum:
        raise BootstrapError(f"compose archive member changed size while read: {member.name}")
    return value


def _validated_members(
    source: BinaryIO, edition: str, version: str
) -> list[tarfile.TarInfo]:
    root = f"nano-{version}"
    source.seek(0)
    try:
        with tarfile.open(fileobj=source, mode="r:gz") as archive:
            members: list[tarfile.TarInfo] = []
            names: set[str] = set()
            expanded = 0
            for member in archive:
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise BootstrapError("compose archive exceeds the member-count limit")
                name = _member_name(member.name, root)
                if name in names:
                    raise BootstrapError(f"compose archive contains duplicate member {name!r}")
                names.add(name)
                if _is_sparse_member(member):
                    raise BootstrapError(f"compose archive contains a sparse member: {name}")
                if member.type != tarfile.DIRTYPE and not _is_regular_member(member):
                    raise BootstrapError(
                        f"compose archive contains a link or special member: {name}"
                    )
                if member.type == tarfile.DIRTYPE and member.size != 0:
                    raise BootstrapError(f"compose archive directory has data: {name}")
                if _is_regular_member(member):
                    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                        raise BootstrapError(f"compose archive member exceeds its size limit: {name}")
                    expanded += member.size
                    if expanded > MAX_EXPANDED_BYTES:
                        raise BootstrapError("compose archive exceeds the expanded-size limit")
                members.append(member)

            required = {
                root,
                f"{root}/.nano-bundle",
                f"{root}/.nano-edition",
                f"{root}/scripts/nano",
                f"{root}/scripts/lib/nano_bundle_embedded_lab_root.json",
            }
            missing = sorted(required - names)
            if missing:
                raise BootstrapError(
                    f"compose archive is missing required members: {', '.join(missing)}"
                )
            if f"{root}/.env" in names or f"{root}/.nano-test-upgrade-root" in names:
                raise BootstrapError("compose release archive contains runtime or TEST-root state")
            by_name = {member.name.rstrip("/"): member for member in members}
            if by_name[root].type != tarfile.DIRTYPE:
                raise BootstrapError("compose archive root must be a directory")
            nano_cli = by_name[f"{root}/scripts/nano"]
            if not _is_regular_member(nano_cli) or not nano_cli.mode & 0o111:
                raise BootstrapError("compose archive scripts/nano must be an executable regular file")
            marker = _read_tar_member(archive, by_name[f"{root}/.nano-bundle"], 128)
            if marker != f"nano compose release v{version}\n".encode("ascii"):
                raise BootstrapError("compose archive release marker does not match its version")
            archive_edition = _read_tar_member(
                archive, by_name[f"{root}/.nano-edition"], 32
            )
            if archive_edition != f"{edition}\n".encode("ascii"):
                raise BootstrapError("compose archive edition marker does not match its name")
            embedded = _read_tar_member(
                archive,
                by_name[f"{root}/scripts/lib/nano_bundle_embedded_lab_root.json"],
                MAX_PUBLIC_KEY_BYTES,
            )
            if embedded.strip() != b"null":
                raise BootstrapError("compose release archive embeds a TEST release root")
            return members
    except (tarfile.TarError, EOFError, OSError) as error:
        raise BootstrapError(f"compose archive is not a valid bounded gzip tar: {error}") from error


def inspect_archive(path: Path, edition: str, version: str) -> tuple[int, int]:
    """Validate an archive before signing and return member/expanded counts."""
    with _open_regular(path, "compose archive", MAX_ARCHIVE_BYTES) as source:
        members = _validated_members(source, edition, version)
        return len(members), sum(
            member.size for member in members if _is_regular_member(member)
        )


def _safe_parent_directories(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            pass
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise BootstrapError(f"staging path is not a directory: {current}")


def _extract_members(
    source: BinaryIO, output: Path, edition: str, version: str
) -> tuple[int, int]:
    members = _validated_members(source, edition, version)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:gz") as archive:
            extracted = 0
            for member in members:
                relative = Path(*member.name.rstrip("/").split("/"))
                target = output / relative
                if member.type == tarfile.DIRTYPE:
                    _safe_parent_directories(output, relative / "placeholder")
                    try:
                        target.mkdir(mode=0o755)
                    except FileExistsError:
                        pass
                    if not stat.S_ISDIR(target.lstat().st_mode):
                        raise BootstrapError(f"staging directory was replaced: {target}")
                    continue
                _safe_parent_directories(output, relative)
                incoming = archive.extractfile(member)
                if incoming is None:
                    raise BootstrapError(f"cannot extract compose archive member: {member.name}")
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(target, flags, 0o600)
                try:
                    written = 0
                    with os.fdopen(descriptor, "wb") as destination:
                        descriptor = -1
                        while True:
                            block = incoming.read(READ_CHUNK)
                            if not block:
                                break
                            written += len(block)
                            if written > member.size:
                                raise BootstrapError(
                                    f"compose archive member expanded past its declared size: {member.name}"
                                )
                            destination.write(block)
                        if written != member.size:
                            raise BootstrapError(
                                f"compose archive member was truncated: {member.name}"
                            )
                        destination.flush()
                        os.fsync(destination.fileno())
                        os.fchmod(destination.fileno(), 0o755 if member.mode & 0o111 else 0o644)
                    extracted += written
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            return len(members), extracted
    except BaseException:
        shutil.rmtree(output)
        raise


def verify_and_extract(args: argparse.Namespace) -> tuple[int, int]:
    archive_path = Path(args.archive)
    match = ARCHIVE_NAME.fullmatch(archive_path.name)
    if match is None or match.group(1) != args.edition or ".".join(match.groups()[1:]) != args.version:
        raise BootstrapError("compose archive name, edition, and version do not match")
    checksum = _read_bounded(Path(args.checksum), "checksum statement", MAX_CHECKSUM_BYTES)
    expected_statement = re.fullmatch(
        rb"([0-9a-f]{64})  (nano-compose-(?:open|enterprise)-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz)\n",
        checksum,
    )
    if expected_statement is None or expected_statement.group(2).decode("ascii") != archive_path.name:
        raise BootstrapError("checksum statement is not canonical for the compose archive")
    signature = _read_bounded(Path(args.signature), "detached signature", MAX_SIGNATURE_BYTES)
    if len(signature) != MAX_SIGNATURE_BYTES:
        raise BootstrapError("detached Ed25519 signature must be exactly 64 bytes")
    verify_ed25519(_public_key_from_pem(Path(args.public_key)), checksum, signature)

    output = Path(args.output)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise BootstrapError("--output must be a fresh absolute staging path")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise BootstrapError("--output parent must already exist") from error
    output = parent / output.name
    with _open_regular(archive_path, "compose archive", MAX_ARCHIVE_BYTES) as source:
        before = _archive_identity(source)
        expected_digest = expected_statement.group(1).decode("ascii")
        if _sha256(source) != expected_digest:
            raise BootstrapError("compose archive SHA-256 does not match its signed statement")
        result = _extract_members(source, output, args.edition, args.version)
        if _archive_identity(source) != before or _sha256(source) != expected_digest:
            shutil.rmtree(output)
            raise BootstrapError("compose archive changed during verified extraction")
        return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="nano_bootstrap_verify_v1.py")
    subparsers = result.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect", help="validate an archive before signing")
    inspect.add_argument("--archive", required=True)
    inspect.add_argument("--edition", required=True, choices=("open", "enterprise"))
    inspect.add_argument("--version", required=True)
    fingerprint = subparsers.add_parser(
        "fingerprint", help="print the release public-key SPKI SHA-256"
    )
    fingerprint.add_argument("--public-key", required=True)
    verify = subparsers.add_parser(
        "verify-extract", help="verify the signed archive and extract it to fresh staging"
    )
    verify.add_argument("--archive", required=True)
    verify.add_argument("--checksum", required=True)
    verify.add_argument("--signature", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--edition", required=True, choices=("open", "enterprise"))
    verify.add_argument("--version", required=True)
    verify.add_argument("--output", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "inspect":
            members, expanded = inspect_archive(Path(args.archive), args.edition, args.version)
            print(f"verified {members} archive members ({expanded} expanded bytes)")
        elif args.command == "fingerprint":
            print(public_key_fingerprint(Path(args.public_key)))
        else:
            members, expanded = verify_and_extract(args)
            print(f"verified {members} archive members ({expanded} expanded bytes)")
        return 0
    except (BootstrapError, OSError, ValueError) as error:
        print(f"nano-bootstrap-verify: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
