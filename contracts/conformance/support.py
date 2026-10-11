"""HTTP and disposable-database fixtures. No authentication is implemented here."""

import base64
import html
import json
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, LiteralString, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg
from psycopg import sql

from profiles import REDIRECT, environment

PASSWORD = "test-password"  # noqa: S105 -- public fixture credential
DEMO = "demo@example.com"
AUTH_KEYS = {"access-token", "token-type", "client", "expiry", "uid"}
FULL_KEYS = {
    "id",
    "provider",
    "uid",
    "email",
    "name",
    "nickname",
    "image",
    "allow_password_change",
    "created_at",
    "updated_at",
}
TOKEN_KEYS = FULL_KEYS - {"created_at", "updated_at"}
BAD_CREDENTIALS = "Invalid login credentials. Please try again."
LOCKED = "Your account has been locked due to an excessive number of unsuccessful sign in attempts."
PARANOID = {
    "password": (
        "If your email address exists in our database, you will receive a "
        "password recovery link at your email address in a few minutes."
    ),
    "confirmation": (
        "If your email address exists in our database, you will receive "
        "an email with instructions for how to confirm your email address "
        "in a few minutes."
    ),
    "unlock": (
        "If your account exists, you will receive an email with "
        "instructions for how to unlock it in a few minutes."
    ),
}


@dataclass(frozen=True)
class Settings:
    base_url: str
    database_url: str
    mailpit_url: str
    profile: str
    reference: bool
    peer_url: str
    overrides: tuple[str, ...] = ()
    database_container: str = ""

    @property
    def env(self) -> dict[str, str]:
        return environment(self.profile) | dict(value.split("=", 1) for value in self.overrides)


class API:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
        self.http = httpx.Client(
            base_url=self.url, timeout=15, follow_redirects=False, trust_env=False
        )

    def close(self) -> None:
        self.http.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> httpx.Response:
        self.http.cookies.clear()
        return self.http.request(method, path, headers=headers, json=json, params=params, data=data)

    def raw_get(self, path: str) -> httpx.Response:
        # DTA U3 emits a malformed Location; Client.request parses it even without following.
        # The raw transport preserves the exact response for the regression assertion.
        with httpx.HTTPTransport() as transport:
            request = httpx.Request(
                "GET",
                self.url + path,
                extensions={"timeout": {"connect": 15, "read": 15, "write": 15, "pool": 15}},
            )
            response = transport.handle_request(request)
            response.read()
            response.request = request
            return response

    def wire_batch_headers(self, headers: dict[str, str]) -> dict[str, bytes]:
        """Read real HTTP bytes: h11 strips OWS, hiding DTA's literal one-space value."""
        url = urlsplit(self.url)
        assert url.hostname is not None
        port = url.port or (443 if url.scheme == "https" else 80)
        request_headers = {"Host": url.netloc, "Connection": "close", **headers}
        assert all("\r" not in v and "\n" not in v for v in request_headers.values())
        request = (
            "GET /me HTTP/1.1\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in request_headers.items())
            + "\r\n"
        )
        with socket.create_connection((url.hostname, port), timeout=15) as connection:
            stream = (
                ssl.create_default_context().wrap_socket(connection, server_hostname=url.hostname)
                if url.scheme == "https"
                else connection
            )
            with stream:
                stream.sendall(request.encode("ascii"))
                raw = b""
                while b"\r\n\r\n" not in raw:
                    chunk = stream.recv(4096)
                    assert chunk, "response ended before its headers"
                    raw += chunk
                    assert len(raw) <= 65536, "oversized response headers"
        head = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        assert head[0].split()[1] == b"200", head[0]
        values: dict[str, bytes] = {}
        for line in head[1:]:
            key, separator, value = line.partition(b": ")
            assert separator, line
            values[key.decode("ascii").lower()] = value
        return values

    def signin(self, email: str = DEMO, password: str = PASSWORD) -> httpx.Response:
        return self.request("POST", "/auth/sign_in", json={"email": email, "password": password})

    def login(self, email: str = DEMO) -> dict[str, str]:
        response = self.signin(email)
        assert response.status_code == 200, response.text
        return credentials(response)

    def signup(self, email: str = "new@example.com", **extra: object) -> httpx.Response:
        return self.request(
            "POST",
            "/auth",
            json={
                "email": email,
                "password": PASSWORD,
                "password_confirmation": PASSWORD,
                "confirm_success_url": REDIRECT,
                **extra,
            },
        )


def credentials(response: httpx.Response) -> dict[str, str]:
    return {key: response.headers[key] for key in ("access-token", "client", "uid")}


def error(response: httpx.Response, status_code: int, message: str, **extra: object) -> None:
    assert response.status_code == status_code, response.text
    assert response.json() == {"success": False, "errors": [message], **extra}


def auth_headers(
    response: httpx.Response, settings: Settings, *, batch: bool | None = None
) -> None:
    assert set(response.headers) >= AUTH_KEYS, dict(response.headers)
    values = {key: response.headers[key] for key in AUTH_KEYS}
    if batch is None:
        batch = not values["access-token"].strip()
        if batch:
            assert settings.profile == "rotation"
    assert values["token-type"] == "Bearer"
    assert values["uid"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", values["client"])
    if batch:
        assert values["access-token"] == ""
        assert values["expiry"] == ""
    else:
        size = 22 if settings.reference else 43
        assert re.fullmatch(r"[A-Za-z0-9_-]{" + str(size) + "}", values["access-token"])
        assert values["expiry"].isdecimal()
    if settings.profile == "cookie":
        assert "authorization" not in response.headers
    else:
        encoded = response.headers["authorization"].split()[-1]
        bearer = json.loads(base64.b64decode(encoded, validate=True))
        if batch:
            assert set(bearer) == AUTH_KEYS
            assert bearer["access-token"].strip()
            assert bearer["expiry"].isdecimal()
            assert {k: bearer[k] for k in AUTH_KEYS - {"access-token", "expiry"}} == {
                k: values[k] for k in AUTH_KEYS - {"access-token", "expiry"}
            }
        else:
            assert bearer == values


def account_keys(settings: Settings, *, full: bool = False) -> set[str]:
    keys = FULL_KEYS if full else TOKEN_KEYS
    # The oracle fixture adds role; native DTA exposes every non-secret column (D-V).
    return keys | ({"role"} if settings.reference else set())


def account(
    response: httpx.Response,
    email: str,
    settings: Settings,
    *,
    full: bool = False,
    name: str | None = None,
    role: str = "user",
    allow: bool = False,
) -> dict[str, Any]:
    data: dict[str, Any] = response.json()["data"]
    assert response.status_code == 200, response.text
    assert set(data) == account_keys(settings, full=full), data
    assert data == {
        **({k: data[k] for k in ("created_at", "updated_at")} if full else {}),
        "id": data["id"],
        "provider": "email",
        "uid": email,
        "email": email,
        "name": name,
        "nickname": None,
        "image": None,
        **({"role": role} if settings.reference else {}),
        "allow_password_change": allow,
    }
    assert isinstance(data["id"], int)
    if full:
        for key in ("created_at", "updated_at"):
            assert data[key].endswith("Z")
            datetime.fromisoformat(data[key].replace("Z", "+00:00"))
    return data


def redirect(response: httpx.Response, *, target: str = REDIRECT) -> dict[str, str]:
    assert response.status_code == 302, response.text
    actual = urlsplit(response.headers["location"])
    expected = urlsplit(target)
    assert (actual.scheme, actual.netloc, actual.path, actual.fragment) == (
        expected.scheme,
        expected.netloc,
        expected.path,
        expected.fragment,
    )
    return {k: v[0] for k, v in parse_qs(actual.query).items()}


class Database:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.conn: psycopg.Connection[tuple[Any, ...]] = psycopg.connect(
            settings.database_url, autocommit=True
        )

    def close(self) -> None:
        self.conn.close()

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        self.conn.execute(sql.SQL(cast(LiteralString, query)), params)

    def one(self, query: str, params: tuple[Any, ...] = ()) -> Any:  # noqa: ANN401 -- SQL scalar
        row = self.conn.execute(sql.SQL(cast(LiteralString, query)), params).fetchone()
        assert row is not None
        return row[0]

    def update(self, email: str, **values: object) -> None:
        for column, value in values.items():
            self.conn.execute(
                sql.SQL("UPDATE users SET {} = %s WHERE email = %s").format(sql.Identifier(column)),
                (value, email),
            )

    def session_expiry(self, headers: dict[str, str], seconds: int) -> None:
        if self.settings.reference:
            self.execute(
                (
                    "UPDATE users SET tokens = jsonb_set(tokens::jsonb, "
                    "ARRAY[%s,'expiry'], to_jsonb(extract(epoch FROM "
                    "clock_timestamp())::bigint + %s))::text WHERE uid=%s"
                ),
                (headers["client"], seconds, headers["uid"]),
            )
        else:
            self.execute(
                (
                    "UPDATE ogiri_sessions SET created_at=least(created_at, "
                    "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + %s * 1000 - 1), "
                    "expires_at=floor(extract(epoch FROM "
                    "clock_timestamp()) * 1000)::bigint + %s * 1000 WHERE client=%s"
                ),
                (seconds, seconds, headers["client"]),
            )

    def reset(self) -> None:
        # The CLI opts into a disposable fixture database; no production URL is supported.
        self.execute("TRUNCATE users RESTART IDENTITY CASCADE")
        self.execute("TRUNCATE ogiri_sessions, ogiri_subject_locks")
        fixture = (Path(__file__).resolve().parents[1] / "fixtures/devise-users.sql").read_text()
        self.execute(fixture[fixture.index("INSERT INTO users") :])
        if self.one("SELECT to_regclass('public.admins')") is not None:
            self.execute("TRUNCATE admins")


class Mailbox:
    def __init__(self, url: str) -> None:
        self.http = httpx.Client(base_url=url, timeout=10, trust_env=False)

    def close(self) -> None:
        self.http.close()

    def clear(self) -> None:
        self.http.delete("/api/v1/messages").raise_for_status()

    def message(self, email: str, subject: str) -> dict[str, Any]:
        response = self.http.get("/api/v1/messages")
        response.raise_for_status()
        messages: list[dict[str, Any]] = response.json()["messages"]
        matches = [
            m
            for m in messages
            if subject.lower() in m["Subject"].lower()
            and any(t["Address"] == email for t in m["To"])
        ]
        assert matches, (email, subject, messages)
        found = self.http.get("/api/v1/message/" + matches[0]["ID"])
        found.raise_for_status()
        message: dict[str, Any] = found.json()
        assert [t["Address"] for t in message["To"]] == [email]
        return message

    def link(self, email: str, subject: str) -> str:
        body = self.message(email, subject)["HTML"]
        links = re.findall(r'href="([^"]+)"', body)
        assert len(links) == 1, body
        return html.unescape(links[0])

    def follow(self, api: API, email: str, subject: str) -> httpx.Response:
        # Keep the original URL path/query, rewriting host only for container addressability.
        url = urlsplit(self.link(email, subject))
        return api.request("GET", url.path + "?" + url.query)
