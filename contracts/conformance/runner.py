"""Run isolated profile instances. Only containers recorded by this run are cleaned."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import IO, LiteralString, cast

import httpx
import psycopg

from profiles import BASE, PROFILES, environment

ROOT = Path(__file__).resolve().parents[2]
SUITE = Path(__file__).resolve().parent


def command(args: list[str], *, merge_stderr: bool = False) -> str:
    return subprocess.check_output(
        args, text=True, timeout=60, stderr=subprocess.STDOUT if merge_stderr else None
    ).strip()


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, process: subprocess.Popen[str] | None = None) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"sample exited {process.returncode}; see sample log")
        try:
            # An auth endpoint exists on every sample; anonymous 401 is healthy.
            if httpx.get(url, timeout=2, trust_env=False).status_code < 500:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"sample not ready: {url}")


def wait_database(url: str) -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            with psycopg.connect(url, autocommit=True, connect_timeout=2) as db:
                db.execute("SELECT 1")
            return
        except psycopg.OperationalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=[*PROFILES, "all"], default="all")
    parser.add_argument("--sample-command", help="foreground shell command, receives sample env")
    parser.add_argument("--peer-command", help="second foreground command using the same DB")
    parser.add_argument("--cross-backend", action="store_true", help="launch a second Rails oracle")
    parser.add_argument("--reference", action="store_true", help="DTA skips for custom commands")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--setting", action="append", default=[], help="OGIRI_NAME=value override")
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args()

    def shutdown(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGHUP, shutdown)
    profiles = list(PROFILES) if args.profile == "all" else [args.profile]
    overrides: dict[str, str] = {}
    for value in args.setting:
        name, separator, content = str(value).partition("=")
        if not separator or name not in BASE:
            parser.error("--setting must name a documented OGIRI_ setting")
        overrides[name] = content
    prefix = "ogiri-suite-" + uuid.uuid4().hex[:10]
    containers: list[str] = []
    processes: list[subprocess.Popen[str]] = []
    logs: list[IO[str]] = []
    failure = 0

    def container(name: str, arguments: list[str]) -> str:
        full_name = prefix + "-" + name
        # Record before launching, including cases where Docker accepts then errors.
        containers.append(full_name)
        command(["docker", "run", "-d", "--name", full_name, *arguments])
        return full_name

    def published(name: str, internal: str) -> int:
        return int(command(["docker", "port", name, internal]).rsplit(":", 1)[1])

    def sample(env: dict[str, str], name: str, custom: str | None) -> tuple[str, str]:
        sample_port = port()
        env = env | {"PORT": str(sample_port)}
        host_env = os.environ | env
        base_url = f"http://127.0.0.1:{sample_port}"
        if custom:
            log = (SUITE / "results" / f"{name}.log").open("w")
            logs.append(log)
            proc = subprocess.Popen(
                ["/bin/sh", "-c", custom],
                env=host_env,
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            processes.append(proc)
            wait_http(base_url + "/auth/validate_token", proc)
            return base_url, ""
        docker_env = env | {
            "OGIRI_DATABASE_URL": env["OGIRI_DATABASE_URL"].replace(
                "127.0.0.1", "host.docker.internal"
            ),
            "OGIRI_SMTP_HOST": "host.docker.internal",
        }
        # Empty URL defaults must mean unset, rather than a redirect to an empty string.
        docker_args = ["-p", f"127.0.0.1:{sample_port}:{sample_port}"]
        for key, value in docker_env.items():
            if value or key == "OGIRI_REDIRECT_ALLOWLIST":
                docker_args.extend(["-e", f"{key}={value}"])
        full_name = container(name, [*docker_args, "ogiri-suite-rails-reference"])
        try:
            wait_http(base_url + "/auth/validate_token")
        except Exception:
            print(command(["docker", "logs", full_name]), flush=True)
            raise
        return base_url, full_name

    def remove_owned(name: str) -> bool:
        if not name.startswith(prefix + "-"):
            raise ValueError("refusing to remove a container not owned by this run")
        try:
            subprocess.run(["docker", "stop", name], check=False, capture_output=True, timeout=15)
        except subprocess.TimeoutExpired:
            print(f"Cleanup: Docker stop timed out for {name}; trying force removal", flush=True)
        try:
            result = subprocess.run(
                ["docker", "container", "rm", "--force", "--volumes", name],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            print(f"Cleanup pending: Docker removal timed out for {name}", flush=True)
            return False
        if result.returncode:
            print(f"Cleanup pending: {name}: {result.stderr.strip()}", flush=True)
            return False
        return True

    def stop_sample(name: str) -> None:
        if name and remove_owned(name):
            containers.remove(name)

    (SUITE / "results").mkdir(exist_ok=True)
    try:
        if not args.sample_command and not args.no_build:
            subprocess.run(
                [
                    "docker",
                    "build",
                    "-t",
                    "ogiri-suite-rails-reference",
                    str(ROOT / "examples/rails-reference"),
                ],
                check=True,
                timeout=600,
            )
        subprocess.run(
            ["npm", "ci", "--prefix", str(SUITE), "--ignore-scripts", "--no-audit", "--no-fund"],
            check=True,
            timeout=120,
        )
        pg_port = port()
        pg = container(
            "pg",
            [
                "-p",
                f"127.0.0.1:{pg_port}:5432",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "postgres:17-alpine",
            ],
        )
        mail = container(
            "mailpit", ["-p", "127.0.0.1::8025", "-p", "127.0.0.1::1025", "axllent/mailpit:v1.29.2"]
        )
        mail_port = published(mail, "8025/tcp")
        smtp_port = published(mail, "1025/tcp")
        wait_database(f"postgresql://postgres@127.0.0.1:{pg_port}/postgres")
        wait_http(f"http://127.0.0.1:{mail_port}/api/v1/messages")
        for profile in profiles:
            # Profile names are constrained by argparse; identifiers still use psycopg quoting.
            from psycopg import sql

            db_name = "ogiri_suite_" + profile.replace("-", "_")
            with psycopg.connect(
                f"postgresql://postgres@127.0.0.1:{pg_port}/postgres", autocommit=True
            ) as db:
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            database_url = f"postgresql://postgres@127.0.0.1:{pg_port}/{db_name}"
            with psycopg.connect(database_url, autocommit=True) as db:
                for file in [
                    "schema/users-postgresql.sql",
                    "schema/ogiri-postgresql.sql",
                    "fixtures/devise-users.sql",
                ]:
                    db.execute(cast(LiteralString, (ROOT / "contracts" / file).read_text()))
                db.execute("ALTER TABLE users ADD COLUMN tokens text DEFAULT '{}'")
                db.execute("CREATE TABLE admins (LIKE users INCLUDING ALL)")
            env = (
                environment(profile)
                | overrides
                | {
                    "OGIRI_DATABASE_URL": database_url,
                    "OGIRI_SMTP_HOST": "127.0.0.1",
                    "OGIRI_SMTP_PORT": str(smtp_port),
                }
            )
            base, sample_name = sample(env, profile, args.sample_command)
            peer_name = ""
            pytest_args = [
                sys.executable,
                "-m",
                "pytest",
                str(SUITE),
                "-q",
                "--base-url",
                base,
                "--database-url",
                database_url,
                "--mailpit-url",
                f"http://127.0.0.1:{mail_port}",
                "--profile",
                profile,
                "--database-container",
                pg,
                "--junitxml",
                str(SUITE / "results" / f"{profile}.xml"),
            ]
            for name, value in overrides.items():
                pytest_args.extend(["--setting", name + "=" + value])
            if args.reference or not args.sample_command:
                pytest_args.append("--reference")
            if args.peer_command or args.cross_backend:
                peer, peer_name = sample(env, profile + "-peer", args.peer_command)
                pytest_args.extend(["--peer-url", peer])
            print(f"PROFILE {profile}: {base}", flush=True)
            result = subprocess.run([*pytest_args, *args.pytest_args], check=False, timeout=600)
            failure |= result.returncode
            if sample_name:
                (SUITE / "results" / f"{profile}.log").write_text(
                    command(["docker", "logs", sample_name], merge_stderr=True)
                )
            stop_sample(peer_name)
            stop_sample(sample_name)
            # Custom samples also stop between profiles.
            for proc in processes:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=15)
            processes.clear()
    finally:
        for proc in processes:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=15)
        for log in logs:
            log.close()
        for name in reversed(containers):
            try:
                (SUITE / "results" / f"{name}.log").write_text(
                    command(["docker", "logs", name], merge_stderr=True)
                )
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"Could not capture container log for {name}: {exc}", flush=True)
            if not remove_owned(name):
                failure |= 1
    return failure


if __name__ == "__main__":
    raise SystemExit(main())
