#!/usr/bin/env python3
"""Isolated fixture; generated credentials stay in memory and subprocess env."""
import datetime
import hashlib
import hmac
import json
import os
import shlex
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid

FIXTURE = Path(__file__).resolve().parent
REPO = FIXTURE.parents[3]
MINIO_COMMIT = "07c3a429bfed433e49018cb0f78a52145d4bedeb"  # RELEASE.2025-09-07T16-13-09Z
CATALOG_IMAGE = "apache/iceberg-rest-fixture@sha256:db8de90b5b7693d4ac334c336f91d9bbe320d7b19f4f514d26de84cdfbcbfe8d"


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(args, env, log):
    # Never echo commands/env/remote error bodies (they can contain credentials).
    with log.open("ab") as output:
        subprocess.run(args, env=env, stdout=output, stderr=output, check=True)


def healthy(url):
    for _ in range(120):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("fixture readiness deadline exceeded")


def create_bucket(endpoint, access, secret, bucket="export-fixture"):
    # Minimal AWS SigV4 PUT: no dependency on MinIO's discontinued mc image.
    date = datetime.datetime.now(datetime.timezone.utc)
    stamp = date.strftime("%Y%m%dT%H%M%SZ")
    day = date.strftime("%Y%m%d")
    host = endpoint.removeprefix("http://")
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{stamp}\n"
    signed = "host;x-amz-content-sha256;x-amz-date"
    canonical = f"PUT\n/{bucket}\n\n{headers}\n{signed}\n{payload_hash}"
    scope = f"{day}/us-east-1/s3/aws4_request"
    message = f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    key = ("AWS4" + secret).encode()
    for value in [day, "us-east-1", "s3", "aws4_request"]:
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    authorization = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}"
    request = urllib.request.Request(endpoint + "/" + bucket, data=b"", method="PUT", headers={"Authorization": authorization, "x-amz-date": stamp, "x-amz-content-sha256": payload_hash})
    with urllib.request.urlopen(request, timeout=10):
        pass


def main():
    env = os.environ.copy()
    env.update({"CARGO_BUILD_JOBS": env.get("CARGO_BUILD_JOBS", "4"), "CARGO_TARGET_DIR": str(REPO / "target"), "SQLX_OFFLINE": "true", "NANO_FAMILY_TARGET_GUARD": "error", "GOMAXPROCS": "4", "CGO_ENABLED": "0"})
    # Optional build throttles: NANO_CARGO replaces `cargo`, NANO_BUILD_GATE
    # (a command prefix) wraps the MinIO `go build`.
    gate = shlex.split(env.get("NANO_BUILD_GATE", ""))
    cargo = env.get("NANO_CARGO", "cargo")
    name = "nano-export-test-" + uuid.uuid4().hex[:12]
    containers = []
    network_created = False
    auth_file = REPO / "target" / (name + "-auth.json")
    with tempfile.TemporaryDirectory(prefix="nano-export-fixture-") as directory:
        temp = Path(directory)
        log = temp / "fixture.log"
        try:
            binary = os.environ.get("MINIO_BINARY")
            if binary:
                shutil.copyfile(binary, temp / "minio")
            else:
                print("Building pinned upstream MinIO fixture", flush=True)
                run(["git", "clone", "--quiet", "--depth", "1", "--branch", "RELEASE.2025-09-07T16-13-09Z", "https://github.com/minio/minio.git", str(temp / "source")], env, log)
                commit = subprocess.check_output(["git", "-C", str(temp / "source"), "rev-parse", "HEAD"], text=True).strip()
                if commit != MINIO_COMMIT:
                    raise RuntimeError("MinIO fixture source identity mismatch")
                with log.open("ab") as output:
                    subprocess.run([*gate, "go", "build", "-p", "4", "-trimpath", "-o", str(temp / "minio"), "."], cwd=temp / "source", env=env, stdout=output, stderr=output, check=True)
            (temp / "minio").chmod(0o755)
            shutil.copyfile(FIXTURE / "Dockerfile.minio", temp / "Dockerfile")
            run(["docker", "build", "--quiet", "-t", name, str(temp)], env, log)
            run(["docker", "network", "create", name], env, log)
            network_created = True
            s3_port, rest_port, pg_port = port(), port(), port()
            access, secret = uuid.uuid4().hex, uuid.uuid4().hex + uuid.uuid4().hex
            env.update({"MINIO_ROOT_USER": access, "MINIO_ROOT_PASSWORD": secret, "AWS_ACCESS_KEY_ID": access, "AWS_SECRET_ACCESS_KEY": secret, "AWS_REGION": "us-east-1", "CATALOG_WAREHOUSE": "s3://export-fixture/", "CATALOG_IO__IMPL": "org.apache.iceberg.aws.s3.S3FileIO", "CATALOG_S3_ENDPOINT": "http://minio:9000", "CATALOG_S3_PATH__STYLE__ACCESS": "true"})
            containers.append(name + "-minio")
            run(["docker", "run", "-d", "--name", containers[-1], "--network", name, "--network-alias", "minio", "-p", f"127.0.0.1:{s3_port}:9000", "--env", "MINIO_ROOT_USER", "--env", "MINIO_ROOT_PASSWORD", name, "server", "/data", "--address", ":9000"], env, log)
            endpoint = f"http://127.0.0.1:{s3_port}"
            print("Waiting for local MinIO", flush=True)
            healthy(endpoint + "/minio/health/ready")
            print("Local MinIO ready", flush=True)
            create_bucket(endpoint, access, secret)
            create_bucket(endpoint, access, secret, "nano-shared-r2-00000000-0000-4000-8000-000000000001")
            containers.append(name + "-catalog")
            args = ["docker", "run", "-d", "--name", containers[-1], "--network", name, "-p", f"127.0.0.1:{rest_port}:8181"]
            for variable in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "CATALOG_WAREHOUSE", "CATALOG_IO__IMPL", "CATALOG_S3_ENDPOINT", "CATALOG_S3_PATH__STYLE__ACCESS"]:
                args += ["--env", variable]
            run(args + [CATALOG_IMAGE], env, log)
            uri = f"http://127.0.0.1:{rest_port}"
            print("Waiting for local REST catalog", flush=True)
            healthy(uri + "/v1/config")
            pg_password = uuid.uuid4().hex + uuid.uuid4().hex
            env.update({"POSTGRES_USER": "export_fixture", "POSTGRES_PASSWORD": pg_password, "POSTGRES_DB": "export_fixture"})
            containers.append(name + "-postgres")
            run(["docker", "run", "-d", "--name", containers[-1], "--network", name, "--memory", "512m", "--cpus", "2", "-p", f"127.0.0.1:{pg_port}:5432", "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB", "postgres:18"], env, log)
            ready = False
            for _ in range(60):
                result = subprocess.run(["docker", "exec", containers[-1], "pg_isready", "-U", "export_fixture", "-d", "export_fixture"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    ready = True
                    break
                time.sleep(0.5)
            if not ready:
                raise RuntimeError("local PostgreSQL startup failed")
            auth_file.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(os.open(auth_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
                json.dump({"access_key": access, "secret_key": secret, "pg_url": f"postgres://export_fixture:{pg_password}@127.0.0.1:{pg_port}/export_fixture"}, handle)
            env.update({"NANO_EXPORT_TEST_CATALOG_URI": uri, "NANO_EXPORT_TEST_S3_ENDPOINT": endpoint, "NANO_EXPORT_TEST_AUTH_FILE": str(auth_file)})
            print("Local MinIO and REST catalog ready; running read-back integration", flush=True)
            # Error paths in the test suppress remote response bodies/credentials.
            subprocess.run([cargo, "test", "-p", "nanosiem-lake-worker", "--test", "lean_iceberg_export_local", "--", "--ignored", "--nocapture", "--test-threads=1"], cwd=REPO, env=env, check=True)
            env["NANO_ICEBERG_EXPORT_ENABLED"] = "true"
            subprocess.run([cargo, "test", "-p", "nanosiem-lake-worker", "--lib", "part_ingest::iceberg_export::runner::pg_tests", "--", "--ignored", "--nocapture", "--test-threads=1"], cwd=REPO, env=env, check=True)
            print("Local S3/catalog and PostgreSQL integrations passed", flush=True)
        finally:
            auth_file.unlink(missing_ok=True)
            for container in reversed(containers):
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if network_created:
                subprocess.run(["docker", "network", "rm", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "image", "rm", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Exception strings may contain URLs or headers; only report the class.
        print(f"Local fixture failed ({type(error).__name__}); no credentials logged", flush=True)
        raise SystemExit(1)
