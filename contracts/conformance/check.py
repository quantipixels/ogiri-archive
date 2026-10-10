#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Black-box conformance suite for the Ogiri protocol (see ../PROTOCOL.md).

Runs against a running sample application that uses fixtures/devise-users.sql.
Standard library only. Exit status is non-zero when any check fails.

    python3 contracts/conformance/check.py --base-url http://localhost:8080
    python3 contracts/conformance/check.py --base-url http://a:8080 --peer-url http://b:8081
"""
import argparse
import http.client
import json
import re
import sys
import traceback
import urllib.parse
import uuid
from datetime import datetime, timedelta

PASSWORD = "test-password"
DEMO, ADMIN, LOCKED = "demo@example.com", "admin@example.com", "locked@example.com"
TOKEN = re.compile(r"^og1_[A-Za-z0-9_-]{43}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$")


class Response:
    def __init__(self, raw):
        self.status = raw.status
        self.headers = raw.getheaders()
        self.body = raw.read().decode("utf-8", "replace")

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def json(self):
        return json.loads(self.body)

    def __repr__(self):
        return f"<{self.status} {self.headers} {self.body[:200]!r}>"


class Server:
    def __init__(self, url, base_path):
        parsed = urllib.parse.urlsplit(url)
        self.host, self.port, self.prefix = parsed.hostname or "localhost", parsed.port, parsed.path.rstrip("/")
        self.auth = self.prefix + base_path

    def request(self, method, path, body=None, headers=()):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            data = body.encode() if isinstance(body, str) else body
            for name, value in headers:
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(data or b"")))
            connection.endheaders(data)
            return Response(connection.getresponse())
        finally:
            connection.close()

    def get(self, path, token=None):
        return self.request("GET", path, headers=[("Authorization", f"Bearer {token}")] if token else [])

    def delete(self, path, token):
        return self.request("DELETE", path, headers=[("Authorization", f"Bearer {token}")])

    def sign_in(self, username=DEMO, password=PASSWORD, client="conformance", headers=None, body=None):
        payload = body if body is not None else json.dumps({"username": username, "password": password, "client": client})
        default = [("Content-Type", "application/json"), ("X-Requested-With", "Ogiri")]
        return self.request("POST", self.auth + "/sign-in", payload, default if headers is None else headers)

    def token(self, username=DEMO, client="conformance"):
        response = self.sign_in(username, client=client)
        expect(response.status == 201, f"sign-in for {username} should succeed", response)
        return (response.header("Authorization") or "").removeprefix("Bearer ")


class Failure(AssertionError):
    pass


def expect(condition, message, response=None):
    if not condition:
        raise Failure(message + (f": {response!r}" if response is not None else ""))


def parse_time(value):
    expect(isinstance(value, str) and TIMESTAMP.match(value) is not None, f"timestamp {value!r} must be ISO-8601 UTC")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_session(document, subject_id, client):
    expect(set(document) == {"id", "subject", "client", "createdAt", "expiresAt"}, f"session keys {sorted(document)}")
    uuid.UUID(document["id"])
    expect(document["subject"] == {"realm": "users", "tenantId": "", "subjectId": subject_id}, f"subject {document['subject']}")
    expect(document["client"] == client, f"client {document['client']!r}")
    return parse_time(document["createdAt"]), parse_time(document["expiresAt"])


class Suite:
    def __init__(self, server, peer, lifetime, maximum):
        self.s, self.peer, self.lifetime, self.maximum = server, peer, lifetime, maximum

    def cleanup(self):
        for user in (DEMO, ADMIN):
            response = self.s.sign_in(user, client="cleanup")
            if response.status == 201:
                self.s.delete(self.s.auth + "/sessions", (response.header("Authorization") or "").removeprefix("Bearer "))

    def test_protected_route_challenges_anonymous_requests(self):
        r = self.s.get(self.s.prefix + "/me")
        expect(r.status == 401, "anonymous /me must be 401", r)
        expect((r.header("WWW-Authenticate") or "").startswith("Bearer"), "401 must carry a Bearer challenge", r)
        r = self.s.get(self.s.auth + "/session")
        expect(r.status == 401, "anonymous session lookup must be 401", r)

    def test_sign_in_requires_non_simple_json_request(self):
        r = self.s.sign_in(headers=[("Content-Type", "application/json")])
        expect(r.status == 403, "sign-in without X-Requested-With must be 403", r)
        r = self.s.sign_in(headers=[("Content-Type", "text/plain"), ("X-Requested-With", "Ogiri")])
        expect(r.status == 403, "non-JSON sign-in must be 403", r)

    def test_sign_in_rejects_invalid_fields(self):
        bad = [{"username": DEMO, "password": PASSWORD},
               {"username": " ", "password": PASSWORD, "client": "x"},
               {"username": DEMO, "password": PASSWORD, "client": ""},
               {"username": "a" * 256, "password": PASSWORD, "client": "x"},
               {"username": DEMO, "password": PASSWORD, "client": "c" * 256},
               {"username": DEMO, "password": "p" * 1025, "client": "x"},
               {"username": DEMO + "\u0000", "password": PASSWORD, "client": "x"}]
        for body in bad:
            r = self.s.sign_in(body=json.dumps(body))
            expect(r.status == 400, f"invalid sign-in body {list(body)} must be 400", r)
        r = self.s.sign_in(body="{not json")
        expect(r.status == 400, "unparseable JSON must be 400", r)

    def test_wrong_unknown_and_locked_accounts_are_unauthorized(self):
        for username, password in [(DEMO, "wrong-password"), ("nobody@example.com", PASSWORD), (LOCKED, PASSWORD)]:
            r = self.s.sign_in(username, password)
            expect(r.status == 401, f"sign-in for {username} must be 401", r)
            expect("no-store" in (r.header("Cache-Control") or ""), "401 must be no-store", r)
            expect((r.header("Content-Type") or "").startswith("application/problem+json"), "401 must be problem+json", r)
            expect(r.header("Authorization") is None, "failed sign-in must not issue a token", r)

    def test_sign_in_issues_opaque_bearer_session(self):
        r = self.s.sign_in(client="Pixel 9")
        expect(r.status == 201, "valid sign-in must be 201", r)
        expect("no-store" in (r.header("Cache-Control") or ""), "sign-in must be no-store", r)
        expect(not r.all("Set-Cookie"), "sign-in must not set cookies", r)
        authorization = r.header("Authorization") or ""
        expect(authorization.startswith("Bearer "), "token is returned in the Authorization header", r)
        token = authorization.removeprefix("Bearer ")
        expect(TOKEN.match(token) is not None, f"token format og1_ + 43 base64url chars, got {token!r}")
        expect(token not in r.body, "token must not appear in the response body", r)
        created, expires = check_session(r.json(), DEMO, "Pixel 9")
        expect(abs((expires - created) - timedelta(seconds=self.lifetime)) <= timedelta(milliseconds=1),
               f"lifetime must be {self.lifetime}s, got {expires - created}")
        current = self.s.get(self.s.auth + "/session", token)
        expect(current.status == 200, "session lookup must be 200", current)
        expect("no-store" in (current.header("Cache-Control") or ""), "session lookup must be no-store", current)
        expect(current.json()["id"] == r.json()["id"], "session lookup returns the issued session", current)
        check_session(current.json(), DEMO, "Pixel 9")

    def test_roles_come_from_the_account(self):
        demo, admin = self.s.token(DEMO), self.s.token(ADMIN)
        me = self.s.get(self.s.prefix + "/me", demo)
        expect(me.status == 200 and me.body == DEMO, "/me returns the subject id", me)
        r = self.s.get(self.s.prefix + "/admin", demo)
        expect(r.status == 403, "a user without the admin role gets 403 on /admin", r)
        r = self.s.get(self.s.prefix + "/admin", admin)
        expect(r.status == 200, "an admin gets 200 on /admin", r)

    def test_list_and_revoke_only_own_sessions(self):
        first, second, other = self.s.token(client="one"), self.s.token(client="two"), self.s.token(ADMIN)
        r = self.s.get(self.s.auth + "/sessions", first)
        expect(r.status == 200, "list must be 200", r)
        sessions = r.json()
        expect(all(s["subject"]["subjectId"] == DEMO for s in sessions), "list shows only the caller's sessions", r)
        expect([s["client"] for s in sessions][-2:] == ["one", "two"], "list is ordered by creation", r)
        expect(sessions == sorted(sessions, key=lambda s: (parse_time(s["createdAt"]), s["id"])), "ordered by createdAt, id", r)
        admin_id = self.s.get(self.s.auth + "/session", other).json()["id"]
        r = self.s.delete(f"{self.s.auth}/sessions/{admin_id}", first)
        expect(r.status == 404, "revoking another subject's session is 404", r)
        expect(self.s.get(self.s.auth + "/session", other).status == 200, "foreign session must survive")
        r = self.s.delete(f"{self.s.auth}/sessions/{uuid.uuid4()}", first)
        expect(r.status == 404, "revoking an unknown session is 404", r)
        r = self.s.delete(f"{self.s.auth}/sessions/not-a-uuid", first)
        expect(r.status == 400, "a non-UUID session id is 400", r)
        second_id = self.s.get(self.s.auth + "/session", second).json()["id"]
        r = self.s.delete(f"{self.s.auth}/sessions/{second_id}", first)
        expect(r.status == 204, "revoking an owned session is 204", r)
        r = self.s.get(self.s.prefix + "/me", second)
        expect(r.status == 401, "a revoked token is rejected on the next request", r)

    def test_sign_out_and_revoke_all(self):
        first, second = self.s.token(client="one"), self.s.token(client="two")
        r = self.s.delete(self.s.auth + "/sign-out", first)
        expect(r.status == 204, "sign-out is 204", r)
        r = self.s.get(self.s.prefix + "/me", first)
        expect(r.status == 401 and 'error="invalid_token"' in (r.header("WWW-Authenticate") or ""),
               "a signed-out token is invalid_token", r)
        expect(self.s.get(self.s.prefix + "/me", second).status == 200, "other sessions survive sign-out")
        r = self.s.delete(self.s.auth + "/sessions", second)
        expect(r.status == 204, "revoke all is 204", r)
        expect(self.s.get(self.s.prefix + "/me", second).status == 401, "revoke all ends every session")

    def test_bearer_transport_is_header_only_and_unambiguous(self):
        token = self.s.token()
        r = self.s.get(self.s.prefix + "/me?access_token=" + token)
        expect(r.status == 401, "query-string tokens are ignored", r)
        r = self.s.request("GET", self.s.prefix + "/me", headers=[("Authorization", f"Bearer {token}")] * 2)
        expect(r.status == 400, "duplicate Authorization headers are 400", r)
        for bad in ["og1_" + "A" * 43, "og1_" + "A" * 42 + "B", "og1_short", "not-a-token", token[:-1] + "!"]:
            r = self.s.get(self.s.prefix + "/me", bad)
            expect(r.status == 401 and 'error="invalid_token"' in (r.header("WWW-Authenticate") or ""),
                   f"malformed or unknown token {bad[:12]}… is invalid_token", r)

    def test_session_cap_rejects_instead_of_evicting(self):
        tokens = []
        try:
            tokens.extend(self.s.token(client=f"device-{n}") for n in range(self.maximum))
            r = self.s.sign_in(client="one-too-many")
            expect(r.status == 409, f"sign-in beyond {self.maximum} live sessions is 409", r)
            expect((r.header("Content-Type") or "").startswith("application/problem+json"), "409 is problem+json", r)
            expect(all(self.s.get(self.s.prefix + "/me", t).status == 200 for t in tokens), "no existing session is evicted")
        finally:
            if tokens:
                self.s.delete(self.s.auth + "/sessions", tokens[0])

    def test_peer_backend_shares_sessions(self):
        if self.peer is None:
            raise Skip("no --peer-url")
        token = self.s.token(client="cross-backend")
        r = self.peer.get(self.peer.prefix + "/me", token)
        expect(r.status == 200 and r.body == DEMO, "the peer backend accepts a token issued here", r)
        r = self.peer.delete(self.peer.auth + "/sign-out", token)
        expect(r.status == 204, "the peer backend can sign the session out", r)
        r = self.s.get(self.s.prefix + "/me", token)
        expect(r.status == 401, "revocation on the peer applies here on the next request", r)
        peer_token = self.peer.token(client="from-peer")
        r = self.s.get(self.s.auth + "/session", peer_token)
        expect(r.status == 200 and r.json()["client"] == "from-peer", "a peer-issued token works here", r)


class Skip(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--peer-url", help="second backend sharing the same session tables")
    parser.add_argument("--auth-path", default="/auth")
    parser.add_argument("--lifetime-seconds", type=int, default=7 * 24 * 3600)
    parser.add_argument("--maximum-sessions", type=int, default=10)
    parser.add_argument("-k", help="run only checks whose name contains this text")
    args = parser.parse_args()
    peer = Server(args.peer_url, args.auth_path) if args.peer_url else None
    suite = Suite(Server(args.base_url, args.auth_path), peer, args.lifetime_seconds, args.maximum_sessions)
    names = [n for n in dir(Suite) if n.startswith("test_") and (not args.k or args.k in n)]
    passed = failed = skipped = 0
    for name in names:
        suite.cleanup()
        try:
            getattr(suite, name)()
            passed += 1
            print(f"PASS {name}")
        except Skip as reason:
            skipped += 1
            print(f"SKIP {name}: {reason}")
        except Exception as error:
            failed += 1
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc()
            print(f"FAIL {name}: {detail}")
    suite.cleanup()
    print(f"{passed} passed, {failed} failed, {skipped} skipped against {args.base_url}")
    sys.exit(1 if failed or not passed else 0)


if __name__ == "__main__":
    main()
