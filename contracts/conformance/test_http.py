"""Wire parity: test names cite contract rev 3.5 behaviour ids."""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from profiles import REDIRECT
from support import (
    API,
    AUTH_KEYS,
    BAD_CREDENTIALS,
    DEMO,
    FULL_KEYS,
    LOCKED,
    PARANOID,
    PASSWORD,
    TOKEN_KEYS,
    Database,
    Mailbox,
    Settings,
    account,
    account_keys,
    auth_headers,
    credentials,
    error,
    redirect,
)


def test_H1_token_format(api: API, settings: Settings) -> None:
    response = api.signin()
    assert response.status_code == 200
    auth_headers(response, settings)
    size = 22 if settings.reference else 43
    assert re.fullmatch(r"[A-Za-z0-9_-]{" + str(size) + "}", response.headers["access-token"])
    assert response.headers["access-token"] not in response.text


def test_H2_bearer_and_per_field_header_precedence(api: API) -> None:
    first = api.signin()
    values = credentials(first)
    encoded = base64.b64encode(json.dumps(values).encode()).decode()
    for prefix in ("Bearer", "arbitrary words"):
        assert (
            api.request("GET", "/me", headers={"Authorization": prefix + " " + encoded}).status_code
            == 200
        )
    for invalid in ("Bearer !", "Bearer e30=", "Bearer"):
        assert api.request("GET", "/me", headers={"Authorization": invalid}).status_code == 401
    # Every explicit field takes precedence over that field in Authorization.
    for key in ("access-token", "client", "uid"):
        headers = {"Authorization": "Bearer " + encoded, key: "invalid"}
        assert api.request("GET", "/me", headers=headers).status_code == 401
    assert (
        api.request("GET", "/me", headers={"Authorization": "Bearer !", **values}).status_code
        == 200
    )


def test_H2_missing_client_defaults_to_default(api: API, db: Database, settings: Settings) -> None:
    values = api.login()
    if settings.reference:
        db.execute(
            (
                "UPDATE users SET tokens = jsonb_build_object('default', "
                "tokens::jsonb -> %s)::text WHERE uid=%s"
            ),
            (values["client"], DEMO),
        )
    else:
        db.execute(
            "UPDATE ogiri_sessions SET client='default' WHERE client=%s", (values["client"],)
        )
    values.pop("client")
    assert api.request("GET", "/me", headers=values).json() == {"uid": DEMO}


@pytest.mark.ogiri_only("D-Q: real DTA deliberately accepts query and form credentials")
def test_H2_D_Q_ignore_query_and_form(api: API) -> None:
    values = api.login()
    assert api.request("GET", "/me", params=values).status_code == 401
    assert api.request("DELETE", "/auth/sign_out", data=values).status_code == 404


def test_H3_invalid_uid_client_token_and_expired(api: API, db: Database) -> None:
    values = api.login()
    for key, replacement in (
        ("uid", "admin@example.com"),
        ("client", "a" * 65),
        ("access-token", "invalid"),
    ):
        assert api.request("GET", "/me", headers=values | {key: replacement}).status_code == 401
    assert (
        api.request("GET", "/me", headers={"access-token": values["access-token"]}).status_code
        == 401
    )
    db.session_expiry(values, -1)
    assert api.request("GET", "/me", headers=values).status_code == 401


def test_H4_headers_bearer_cors_and_cache(api: API, settings: Settings) -> None:
    response = api.signin()
    auth_headers(response, settings)
    current = api.request(
        "GET", "/me", headers=credentials(response) | {"Origin": "https://client.example.test"}
    )
    assert current.json() == {"uid": DEMO}
    auth_headers(current, settings)
    exposed = {
        h.strip().lower() for h in current.headers["access-control-expose-headers"].split(",")
    }
    assert {h.lower() for h in AUTH_KEYS} <= exposed
    expected = "max-age=0, private, must-revalidate" if settings.reference else "no-store"
    assert current.headers["cache-control"] == expected


@pytest.mark.profiles("default", "strict", "reset-token", "cookie")
def test_H5_rotation_disabled_expiry_fixed(api: API) -> None:
    first = api.signin()
    second = api.request("GET", "/me", headers=credentials(first))
    assert second.status_code == 200
    for key in AUTH_KEYS:
        assert first.headers[key] == second.headers[key]


@pytest.mark.profiles("default")
@pytest.mark.ogiri_only("D-R: the unconfigured Ogiri default must disable rotation; DTA enables it")
def test_H5_D_R_ogiri_default(api: API) -> None:
    # Run samples with no rotation override to check their default, see README.
    first = api.signin()
    second = api.request("GET", "/me", headers=credentials(first))
    assert first.headers["access-token"] == second.headers["access-token"]


@pytest.mark.profiles("rotation")
def test_H5_rotation_batch_buffer(api: API, settings: Settings) -> None:
    first = api.signin()
    original = credentials(first)
    initial_batch = api.request("GET", "/me", headers=original)
    assert initial_batch.status_code == 200
    auth_headers(initial_batch, settings, batch=True)
    # The HTTP parser removes optional whitespace; inspect actual bytes for H5's single space.
    wire = api.wire_batch_headers(original)
    assert wire["access-token"] == b" "
    assert wire["expiry"] == b" "
    time.sleep(float(settings.env["OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS"]) + 0.15)
    rotated = api.request("GET", "/me", headers=original)
    assert rotated.status_code == 200
    auth_headers(rotated, settings)
    assert rotated.headers["access-token"] != original["access-token"]
    batch = api.request("GET", "/me", headers=original)
    assert batch.status_code == 200
    auth_headers(batch, settings, batch=True)
    # Only the batch buffer uses real elapsed time. No lifespan/reset/unlock sleeps.
    time.sleep(float(settings.env["OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS"]) + 0.15)
    second_rotation = api.request("GET", "/me", headers=credentials(rotated))
    assert second_rotation.status_code == 200
    assert second_rotation.headers["access-token"] != rotated.headers["access-token"]
    assert api.request("GET", "/me", headers=original).status_code == 200
    time.sleep(float(settings.env["OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS"]) + 0.15)
    assert api.request("GET", "/me", headers=original).status_code == 401


def test_H6_device_cap_removes_earliest_expiry(api: API, db: Database, settings: Settings) -> None:
    maximum = int(settings.env["OGIRI_MAX_NUMBER_OF_DEVICES"])
    first = api.login()
    db.session_expiry(first, 60)
    values = [api.login() for _ in range(maximum)]
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert all(api.request("GET", "/me", headers=v).status_code == 200 for v in values)


def test_H6_concurrent_signin_cap(api: API, settings: Settings, db: Database) -> None:
    maximum = int(settings.env["OGIRI_MAX_NUMBER_OF_DEVICES"])
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(api.signin) for _ in range(maximum + 3)]
        responses = [future.result(timeout=30) for future in futures]
    assert all(r.status_code == 200 for r in responses)
    if settings.reference:
        count = db.one(
            ("SELECT count(*) FROM users, LATERAL jsonb_object_keys(tokens::jsonb) WHERE uid=%s"),
            (DEMO,),
        )
    else:
        count = db.one(
            (
                "SELECT count(*) FROM ogiri_sessions WHERE subject_id=(SELECT "
                "id::text FROM users WHERE uid=%s)"
            ),
            (DEMO,),
        )
    assert count == maximum


def test_H7_token_lifespan(api: API, db: Database, settings: Settings) -> None:
    now = int(db.one("SELECT extract(epoch FROM clock_timestamp())"))
    response = api.signin()
    expiry = int(response.headers["expiry"])
    assert 0 <= expiry - now - int(settings.env["OGIRI_TOKEN_LIFESPAN_SECONDS"]) <= 3


def test_H8_protection_and_roles(api: API, settings: Settings) -> None:
    anonymous = api.request("GET", "/me")
    assert anonymous.status_code == 401
    assert anonymous.json() == {"errors": ["You need to sign in or sign up before continuing."]}
    denied = api.request("GET", "/admin", headers=api.login())
    assert denied.status_code == 403
    if settings.reference:
        assert denied.content == b""
    else:
        assert denied.json() == {"errors": ["You are not authorized to access this resource."]}
    assert api.request("GET", "/admin", headers=api.login("admin@example.com")).json() == {
        "uid": "admin@example.com"
    }


def test_S1_json_and_form_signin(api: API, settings: Settings) -> None:
    for response in (
        api.signin(),
        api.request("POST", "/auth/sign_in", data={"email": DEMO, "password": PASSWORD}),
    ):
        assert response.status_code == 200
        assert set(response.json()) == {"data"}
        account(response, DEMO, settings)
        auth_headers(response, settings)


@pytest.mark.parametrize(
    "payload",
    [
        {"email": DEMO, "password": "wrong-password"},
        {"email": "unknown@example.com", "password": PASSWORD},
        {"email": DEMO},
        {"password": PASSWORD},
        {},
    ],
)
def test_S2_invalid_credentials(api: API, payload: dict[str, str]) -> None:
    response = api.request("POST", "/auth/sign_in", json=payload)
    error(response, 401, BAD_CREDENTIALS)
    assert "access-token" not in response.headers


@pytest.mark.profiles("strict")
def test_S3_unconfirmed_paranoid(api: API, db: Database, settings: Settings) -> None:
    db.update(DEMO, confirmed_at=None)
    message = (
        BAD_CREDENTIALS
        if settings.env["OGIRI_PARANOID"] == "true"
        else (
            f"A confirmation email was sent to your account at '{DEMO}'. "
            "You must follow the instructions in the email before your account can be activated"
        )
    )
    error(api.signin(), 401, message)


@pytest.mark.profiles("strict")
def test_S4_locked_paranoid(api: API, settings: Settings) -> None:
    message = BAD_CREDENTIALS if settings.env["OGIRI_PARANOID"] == "true" else LOCKED
    error(api.signin("locked@example.com"), 401, message)


def test_S5_get_signin(api: API) -> None:
    error(
        api.request("GET", "/auth/sign_in"),
        405,
        "Use POST /sign_in to sign in. GET is not supported.",
    )


def test_S6_signout_only_one_client(api: API) -> None:
    first, other = api.login(), api.login()
    response = api.request("DELETE", "/auth/sign_out", headers=first)
    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert not (set(response.headers) & (AUTH_KEYS | {"authorization"}))
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert api.request("GET", "/me", headers=other).status_code == 200


def test_S7_anonymous_signout(api: API) -> None:
    error(api.request("DELETE", "/auth/sign_out"), 404, "User was not found or was not logged in.")


def test_S8_email_normalization(api: API) -> None:
    assert api.signin("  DEMO@EXAMPLE.COM  ").status_code == 200
    response = api.signup("  NEW@EXAMPLE.COM  ")
    assert response.status_code == 200
    assert response.json()["data"]["email"] == "new@example.com"
    assert response.json()["data"]["uid"] == "new@example.com"


def test_V1_validate(api: API, settings: Settings) -> None:
    response = api.request("GET", "/auth/validate_token", headers=api.login())
    assert response.status_code == 200
    assert set(response.json()) == {"success", "data"}
    assert response.json()["success"] is True
    account(response, DEMO, settings)
    auth_headers(response, settings)


def test_V2_invalid_validate(api: API) -> None:
    error(api.request("GET", "/auth/validate_token"), 401, "Invalid login credentials")


def test_R1_signup(api: API, settings: Settings, mail: Mailbox) -> None:
    response = api.signup(name="New User", role="admin", provider="github", uid="forged")
    assert response.status_code == 200
    assert set(response.json()) == {"status", "data"}
    assert response.json()["status"] == "success"
    account(response, "new@example.com", settings, full=True, name="New User")
    if settings.profile == "strict":
        assert "access-token" not in response.headers
        assert "/auth/confirmation?" in mail.link("new@example.com", "Confirmation")
    else:
        auth_headers(response, settings)


@pytest.mark.parametrize(
    "email,password,confirmation,errors",
    [
        (
            "bad-email",
            PASSWORD,
            PASSWORD,
            {"email": ["is not an email"], "full_messages": ["Email is not an email"]},
        ),
        (
            DEMO,
            PASSWORD,
            PASSWORD,
            {
                "email": ["has already been taken"],
                "full_messages": ["Email has already been taken"],
            },
        ),
        (
            "new@example.com",
            "short",
            "short",
            {
                "password": ["is too short (minimum is 6 characters)"],
                "full_messages": ["Password is too short (minimum is 6 characters)"],
            },
        ),
        (
            "new@example.com",
            "x" * 129,
            "x" * 129,
            {
                "password": ["is too long (maximum is 128 characters)"],
                "full_messages": ["Password is too long (maximum is 128 characters)"],
            },
        ),
        (
            "new@example.com",
            PASSWORD,
            "different",
            {
                "password_confirmation": ["doesn't match Password"],
                "full_messages": ["Password confirmation doesn't match Password"],
            },
        ),
    ],
)
def test_R2_registration_errors(
    api: API,
    settings: Settings,
    email: str,
    password: str,
    confirmation: str,
    errors: dict[str, list[str]],
) -> None:
    response = api.signup(email, password=password, password_confirmation=confirmation)
    assert response.status_code == 422, response.text
    body = response.json()
    assert set(body) == {"status", "data", "errors"}
    assert body["status"] == "error"
    assert body["errors"] == errors
    assert set(body["data"]) == account_keys(settings, full=True)
    assert body["data"]["id"] is None
    assert body["data"]["created_at"] is None
    assert body["data"]["updated_at"] is None
    assert body["data"] == {
        "id": None,
        "provider": "email",
        "uid": "",
        "email": email,
        "name": None,
        "nickname": None,
        "image": None,
        **({"role": "user"} if settings.reference else {}),
        "allow_password_change": False,
        "created_at": None,
        "updated_at": None,
    }


def test_R3_empty_signup(api: API) -> None:
    error(
        api.request("POST", "/auth", json={"role": "admin"}),
        422,
        "Please submit proper sign up data in request body.",
        status="error",
    )


@pytest.mark.profiles("strict")
def test_R4_missing_confirmation_redirect(api: API, settings: Settings) -> None:
    response = api.request("POST", "/auth", json={"email": "new@example.com", "password": PASSWORD})
    if settings.env["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"]:
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        return
    error(
        response,
        422,
        "Missing 'confirm_success_url' parameter.",
        status="error",
        data=response.json()["data"],
    )
    assert set(response.json()["data"]) == account_keys(settings, full=True)


@pytest.mark.profiles("strict")
def test_R5_redirect_allowlist(api: API) -> None:
    response = api.signup(confirm_success_url="https://evil.example/done")
    error(
        response,
        422,
        "Redirect to 'https://evil.example/done' not allowed.",
        status="error",
        data=response.json()["data"],
    )


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_R6_update_permitted_attributes(api: API, settings: Settings, method: str) -> None:
    response = api.request(
        method,
        "/auth",
        headers=api.login(),
        json={"name": "Changed", "current_password": PASSWORD, "role": "admin"},
    )
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"status", "data"}
    assert response.json()["status"] == "success"
    account(response, DEMO, settings, full=True, name="Changed")
    auth_headers(response, settings)


def test_R6_password_update_default_needs_no_current_password(api: API, settings: Settings) -> None:
    response = api.request(
        "PUT",
        "/auth",
        headers=api.login(),
        json={"password": "changed-password", "password_confirmation": "changed-password"},
    )
    if settings.profile == "strict":
        assert response.status_code == 422
        assert response.json() == {
            "status": "error",
            "errors": {
                "current_password": ["can't be blank"],
                "full_messages": ["Current password can't be blank"],
            },
        }
    else:
        assert response.status_code == 200, response.text
        assert api.signin(password="changed-password").status_code == 200


def test_R7_wrong_current_password(api: API, settings: Settings) -> None:
    response = api.request(
        "PUT", "/auth", headers=api.login(), json={"name": "Changed", "current_password": "wrong"}
    )
    if (
        not settings.reference
        and settings.env["OGIRI_CHECK_CURRENT_PASSWORD_BEFORE_UPDATE"] == "false"  # noqa: S105 -- setting enum
    ):
        assert response.status_code == 200, response.text
        account(response, DEMO, settings, full=True, name="Changed")
        return
    assert response.status_code == 422
    assert response.json() == {
        "status": "error",
        "errors": {
            "current_password": ["is invalid"],
            "full_messages": ["Current password is invalid"],
        },
    }


def test_R8_empty_update(api: API) -> None:
    error(
        api.request("PUT", "/auth", headers=api.login(), json={"role": "admin"}),
        422,
        "Please submit proper account update data in request body.",
        status="error",
    )


@pytest.mark.parametrize(
    "method,message",
    [("PUT", "User not found."), ("DELETE", "Unable to locate account for destruction.")],
)
def test_R9_anonymous_account_change(api: API, method: str, message: str) -> None:
    error(api.request(method, "/auth", json={"name": "Changed"}), 404, message, status="error")


@pytest.mark.parametrize(
    "method,message",
    [
        ("PUT", "User not found."),
        ("PATCH", "User not found."),
        ("DELETE", "Unable to locate account for destruction."),
    ],
)
@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_R9_rejected_credentials_account_change(
    api: API, db: Database, method: str, message: str, state: str
) -> None:
    values = api.login()
    if state == "revoked":
        response = api.request("DELETE", "/auth/sign_out", headers=values)
        assert response.status_code == 200
        assert response.json() == {"success": True}
    else:
        db.session_expiry(values, -1)
    error(
        api.request(method, "/auth", headers=values, json={"name": "Changed"}),
        404,
        message,
        status="error",
    )


def test_R10_destroy_account_all_clients(api: API) -> None:
    first, second = api.login(), api.login()
    response = api.request("DELETE", "/auth", headers=first)
    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "message": f"Account with UID '{DEMO}' has been destroyed.",
    }
    assert not (set(response.headers) & (AUTH_KEYS | {"authorization"}))
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert api.request("GET", "/me", headers=second).status_code == 401


@pytest.mark.profiles("strict")
def test_R11_reconfirmation(api: API, db: Database, mail: Mailbox, settings: Settings) -> None:
    response = api.request(
        "PUT",
        "/auth",
        headers=api.login(),
        json={"email": "changed@example.com", "current_password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["email"] == DEMO
    assert response.json()["data"]["uid"] == DEMO
    assert (
        db.one("SELECT unconfirmed_email FROM users WHERE email=%s", (DEMO,))
        == "changed@example.com"
    )
    link = urlsplit(mail.link("changed@example.com", "Confirmation"))
    confirmed = api.request(
        "GET",
        link.path + "?" + link.query,
        params={**{k: v[0] for k, v in parse_qs(link.query).items()}, "redirect_url": REDIRECT},
    )
    assert redirect(confirmed) == {"account_confirmation_success": "true"}
    assert api.signin("changed@example.com").status_code == 200


@pytest.mark.profiles("strict")
@pytest.mark.reference_only("D-B: R11/C1 nil URL crashes after successful reconfirmation")
def test_R11_C1_reference_nil_redirect(
    api: API, db: Database, mail: Mailbox, settings: Settings
) -> None:
    response = api.request(
        "PUT",
        "/auth",
        headers=api.login(),
        json={"email": "changed@example.com", "current_password": PASSWORD},
    )
    assert response.status_code == 200
    confirmed = mail.follow(api, "changed@example.com", "Confirmation")
    if settings.env["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"]:
        assert (
            redirect(confirmed, target=settings.env["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"])[
                "account_confirmation_success"
            ]
            == "true"
        )
    else:
        # Devise reconfirms first; DTA then tries URI(nil), yielding 500 without a default.
        assert confirmed.status_code == 500
        assert confirmed.content == b""
    assert api.signin("changed@example.com").status_code == 200


def test_P1_reset_instructions(api: API, settings: Settings, mail: Mailbox) -> None:
    response = api.request("POST", "/auth/password", json={"email": DEMO, "redirect_url": REDIRECT})
    assert response.status_code == 200
    message = (
        PARANOID["password"]
        if settings.env["OGIRI_PARANOID"] == "true"
        else (
            f"An email has been sent to '{DEMO}' "
            "containing instructions for resetting your password."
        )
    )
    assert response.json() == {"success": True, "message": message}
    assert "/auth/password/edit?" in mail.link(DEMO, "Reset password")


@pytest.mark.parametrize("case", ["email", "redirect", "unknown", "both"])
def test_P2_request_errors(api: API, settings: Settings, case: str) -> None:
    if case in {"redirect", "both"} and settings.env["OGIRI_DEFAULT_PASSWORD_RESET_URL"]:
        pytest.skip(
            "P2 missing-redirect error disabled by configured default; default covered separately"
        )
    if case == "email":
        error(
            api.request("POST", "/auth/password", json={"redirect_url": REDIRECT}),
            401,
            "You must provide an email address.",
        )
    elif case in {"redirect", "both"}:
        error(
            api.request(
                "POST", "/auth/password", json={"email": DEMO} if case == "redirect" else {}
            ),
            401,
            "Missing redirect URL.",
        )
    else:
        response = api.request(
            "POST",
            "/auth/password",
            json={"email": "unknown@example.com", "redirect_url": REDIRECT},
        )
        if settings.env["OGIRI_PARANOID"] == "true":
            assert response.status_code == 200
            assert response.json() == {"success": True, "message": PARANOID["password"]}
        else:
            error(response, 404, "Unable to find user with email 'unknown@example.com'.")


@pytest.mark.profiles("strict")
def test_P2_disallowed_redirect(api: API) -> None:
    error(
        api.request(
            "POST", "/auth/password", json={"email": DEMO, "redirect_url": "https://evil.example/"}
        ),
        422,
        "Redirect to 'https://evil.example/' not allowed.",
        status="error",
        data=None,
    )


def reset_link(api: API, mail: Mailbox, email: str = DEMO) -> str:
    response = api.request(
        "POST",
        "/auth/password",
        json={"email": email, "redirect_url": REDIRECT, "config_name": "suite"},
    )
    assert response.status_code == 200, response.text
    return mail.link(email, "Reset password")


def test_P3_follow_reset_email(api: API, db: Database, mail: Mailbox, settings: Settings) -> None:
    if settings.profile == "strict":
        db.update(DEMO, confirmed_at=None)
    link = reset_link(api, mail)
    parsed = urlsplit(link)
    response = api.request("GET", parsed.path + "?" + parsed.query)
    query = redirect(response)
    assert response.headers["location"].startswith(REDIRECT + "?")
    raw = parse_qs(parsed.query)["reset_password_token"][0]
    if settings.profile == "reset-token":
        assert query == {"reset_password_token": raw}
    else:
        assert set(query) == {
            "access-token",
            "client",
            "client_id",
            "config",
            "expiry",
            "reset_password",
            "token",
            "uid",
            "reset_password_token",
        }
        assert query["config"] == "suite"
        assert query["client_id"] == query["client"]
        assert query["token"] == query["access-token"]
        assert query["reset_password"] == "true"  # noqa: S105 -- redirect flag, not a secret
        assert query["uid"] == DEMO
        assert query["reset_password_token"] == raw
        assert (
            api.request(
                "GET", "/me", headers={k: query[k] for k in ("access-token", "client", "uid")}
            ).status_code
            == 200
        )
    assert db.one("SELECT allow_password_change FROM users WHERE email=%s", (DEMO,)) is True
    if settings.profile == "strict":
        assert db.one("SELECT confirmed_at FROM users WHERE email=%s", (DEMO,)) is not None


@pytest.mark.parametrize("expired", [False, True])
def test_P3_invalid_or_expired_reset(api: API, mail: Mailbox, db: Database, expired: bool) -> None:
    parsed = urlsplit(reset_link(api, mail))
    if expired:
        db.execute(
            (
                "UPDATE users SET "
                "reset_password_sent_at=clock_timestamp()-interval '7 hours' "
                "WHERE email=%s"
            ),
            (DEMO,),
        )
        query = parsed.query
    else:
        query = "reset_password_token=invalid&redirect_url=" + REDIRECT
    assert api.request("GET", parsed.path + "?" + query).status_code == 404


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_P4_change_password_via_email_link(
    api: API, mail: Mailbox, db: Database, settings: Settings, method: str
) -> None:
    parsed = urlsplit(reset_link(api, mail))
    query = redirect(api.request("GET", parsed.path + "?" + parsed.query))
    body = {"password": "changed-password", "password_confirmation": "changed-password"}
    headers = None
    if settings.profile == "reset-token":
        body["reset_password_token"] = query["reset_password_token"]
    else:
        headers = {k: query[k] for k in ("access-token", "client", "uid")}
    response = api.request(method, "/auth/password", headers=headers, json=body)
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"success", "data", "message"}
    assert response.json()["success"] is True
    assert response.json()["message"] == "Your password has been successfully updated."
    account(response, DEMO, settings, full=True)
    assert db.one("SELECT allow_password_change FROM users WHERE email=%s", (DEMO,)) is False
    assert api.signin(password="changed-password").status_code == 200
    assert api.signin().status_code == 401
    # One-time reset credential cannot be reused after success.
    assert api.request("GET", parsed.path + "?" + parsed.query).status_code == 404


def test_P4_default_update_needs_no_current_password(api: API, settings: Settings) -> None:
    response = api.request(
        "PUT",
        "/auth/password",
        headers=api.login(),
        json={"password": "changed-password", "password_confirmation": "changed-password"},
    )
    assert response.status_code == (422 if settings.profile == "strict" else 200), response.text


def test_P5_unauthorized_and_missing_fields(api: API) -> None:
    error(
        api.request(
            "PUT", "/auth/password", json={"password": PASSWORD, "password_confirmation": PASSWORD}
        ),
        401,
        "Unauthorized",
    )
    error(
        api.request("PUT", "/auth/password", headers=api.login(), json={}),
        422,
        "You must fill out the fields labeled 'Password' and 'Password confirmation'.",
    )


def test_P5_password_validation(api: API, settings: Settings) -> None:
    response = api.request(
        "PUT",
        "/auth/password",
        headers=api.login(),
        json={"password": "short", "password_confirmation": "short"}
        | ({"current_password": PASSWORD} if settings.profile == "strict" else {}),
    )
    assert response.status_code == 422
    assert response.json() == {
        "success": False,
        "errors": {
            "password": ["is too short (minimum is 6 characters)"],
            "full_messages": ["Password is too short (minimum is 6 characters)"],
        },
    }


def test_P5_non_email_provider(api: API, db: Database) -> None:
    values = api.login()
    db.update(DEMO, provider="github")
    error(
        api.request(
            "PUT",
            "/auth/password",
            headers=values,
            json={"password": PASSWORD, "password_confirmation": PASSWORD},
        ),
        422,
        "This account does not require a password. Sign in using your 'Github' account instead.",
    )


@pytest.mark.profiles("strict")
def test_P6_matching_expiry_and_recency(api: API, db: Database, mail: Mailbox) -> None:
    first = api.login()
    db.session_expiry(first, 60)
    second = api.login()
    db.session_expiry(second, 120)
    parsed = urlsplit(reset_link(api, mail))
    query = redirect(api.request("GET", parsed.path + "?" + parsed.query))
    newest = {k: query[k] for k in ("access-token", "client", "uid")}
    response = api.request(
        "PUT",
        "/auth/password",
        headers=newest,
        json={"password": "changed-password", "password_confirmation": "changed-password"},
    )
    assert response.status_code == 200
    assert api.request("GET", "/me", headers=newest).status_code == 200
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert api.request("GET", "/me", headers=second).status_code == 401


@pytest.mark.profiles("strict")
def test_C1_confirmation_link_and_invalid(
    api: API, mail: Mailbox, db: Database, settings: Settings
) -> None:
    assert api.signup().status_code == 200
    response = mail.follow(api, "new@example.com", "Confirmation")
    assert redirect(response) == {"account_confirmation_success": "true"}
    assert api.signin("new@example.com").status_code == 200
    invalid = api.request(
        "GET",
        "/auth/confirmation",
        params={"confirmation_token": "invalid", "redirect_url": REDIRECT},
    )
    assert redirect(invalid) == {"account_confirmation_success": "false"}
    missing_redirect = api.request(
        "GET", "/auth/confirmation", params={"confirmation_token": "invalid"}
    )
    if settings.env["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"]:
        assert redirect(
            missing_redirect, target=settings.env["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"]
        ) == {"account_confirmation_success": "false"}
    else:
        assert missing_redirect.status_code == 404
    assert db.one("SELECT confirmed_at FROM users WHERE email='new@example.com'") is not None


@pytest.mark.profiles("strict")
def test_C2_confirmation_resend(api: API, mail: Mailbox, db: Database, settings: Settings) -> None:
    db.update(DEMO, confirmed_at=None)
    response = api.request(
        "POST", "/auth/confirmation", json={"email": DEMO, "redirect_url": REDIRECT}
    )
    assert response.status_code == 200
    message = (
        PARANOID["confirmation"]
        if settings.env["OGIRI_PARANOID"] == "true"
        else (
            f"An email has been sent to '{DEMO}' "
            "containing instructions for confirming your account."
        )
    )
    assert response.json() == {"success": True, "message": message}
    assert "/auth/confirmation?" in mail.link(DEMO, "Confirmation")
    unknown = api.request(
        "POST",
        "/auth/confirmation",
        json={"email": "unknown@example.com", "redirect_url": REDIRECT},
    )
    if settings.env["OGIRI_PARANOID"] == "true":
        assert unknown.status_code == 200
        assert unknown.json() == response.json()
    else:
        error(unknown, 404, "Unable to find user with email 'unknown@example.com'.")
    error(
        api.request("POST", "/auth/confirmation", json={}),
        401,
        "You must provide an email address.",
    )


@pytest.mark.profiles("strict")
def test_U1_failed_attempts_lock_and_time_unlock(
    api: API, settings: Settings, db: Database, mail: Mailbox
) -> None:
    maximum = int(settings.env["OGIRI_MAXIMUM_ATTEMPTS"])
    for _ in range(maximum):
        error(api.signin(password="wrong-password"), 401, BAD_CREDENTIALS)
    assert db.one("SELECT failed_attempts FROM users WHERE email=%s", (DEMO,)) == maximum
    assert db.one("SELECT locked_at FROM users WHERE email=%s", (DEMO,)) is not None
    error(
        api.signin(), 401, BAD_CREDENTIALS if settings.env["OGIRI_PARANOID"] == "true" else LOCKED
    )
    assert "/auth/unlock?" in mail.link(DEMO, "Unlock")
    db.execute(
        "UPDATE users SET locked_at=clock_timestamp()-interval '31 seconds' WHERE email=%s", (DEMO,)
    )
    assert api.signin().status_code == 200
    assert db.one("SELECT failed_attempts FROM users WHERE email=%s", (DEMO,)) == 0


@pytest.mark.profiles("strict")
def test_U2_unlock_resend(api: API, mail: Mailbox, settings: Settings) -> None:
    response = api.request("POST", "/auth/unlock", json={"email": "locked@example.com"})
    assert response.status_code == 200
    message = (
        PARANOID["unlock"]
        if settings.env["OGIRI_PARANOID"] == "true"
        else (
            "An email has been sent to 'locked@example.com' "
            "containing instructions for unlocking your account."
        )
    )
    assert response.json() == {"success": True, "message": message}
    assert "/auth/unlock?" in mail.link("locked@example.com", "Unlock")
    unknown = api.request("POST", "/auth/unlock", json={"email": "unknown@example.com"})
    if settings.env["OGIRI_PARANOID"] == "true":
        assert unknown.status_code == 200
        assert unknown.json() == response.json()
    else:
        error(unknown, 404, "Unable to find user with email 'unknown@example.com'.")
    error(api.request("POST", "/auth/unlock", json={}), 401, "You must provide an email address.")


@pytest.mark.profiles("strict")
@pytest.mark.reference_only("D-B: Rails emits a malformed relative redirect")
def test_U3_unlock_email_link(api: API, mail: Mailbox) -> None:
    assert (
        api.request("POST", "/auth/unlock", json={"email": "locked@example.com"}).status_code == 200
    )
    link = urlsplit(mail.link("locked@example.com", "Unlock"))
    response = api.raw_get(link.path + "?" + link.query)
    assert response.status_code == 302
    location = response.headers["location"]
    query = {k: v[0] for k, v in parse_qs(location.split("?", 1)[1]).items()}
    assert set(query) == {
        "access-token",
        "client",
        "client_id",
        "config",
        "expiry",
        "token",
        "uid",
        "unlock",
    }
    assert location.split("?", 1)[0] == api.url + ":///"
    assert query["unlock"] == "true"
    assert query["client"] == query["client_id"]
    assert query["token"] == query["access-token"]
    assert (
        api.request(
            "GET", "/me", headers={k: query[k] for k in ("access-token", "client", "uid")}
        ).status_code
        == 200
    )
    assert api.request("GET", "/auth/unlock", params={"unlock_token": "invalid"}).status_code == 404


def test_E1_email_tokens_and_config(
    api: API, db: Database, mail: Mailbox, settings: Settings
) -> None:
    link = urlsplit(reset_link(api, mail))
    values = parse_qs(link.query)
    assert set(values) == {"config", "redirect_url", "reset_password_token"}
    assert values["config"] == ["suite"]
    assert values["redirect_url"] == [REDIRECT]
    raw = values["reset_password_token"][0]
    stored = db.one("SELECT reset_password_token FROM users WHERE email=%s", (DEMO,))
    assert stored != raw
    assert re.fullmatch(r"[0-9a-f]{64}", stored)
    assert redirect(api.request("GET", link.path + "?" + link.query))
    after = db.one("SELECT reset_password_token FROM users WHERE email=%s", (DEMO,))
    assert after == stored
    assert after != raw


@pytest.mark.profiles("cookie")
@pytest.mark.reference_only("D-K: Rails cookie sign-out requires no double-submit token")
def test_K1_cookie_auth_and_signout(api: API, settings: Settings) -> None:
    response = api.signin()
    auth_headers(response, settings)
    cookie = next(
        c for c in response.headers.get_list("set-cookie") if c.startswith("auth_cookie=")
    )
    assert "auth_cookie=" in cookie and "httponly" in cookie.lower()
    value = cookie.split(";", 1)[0]
    payload = json.loads(unquote(value.split("=", 1)[1]))
    assert payload == {k: response.headers[k] for k in AUTH_KEYS}
    current = api.request("GET", "/me", headers={"Cookie": value})
    assert current.status_code == 200
    assert current.json() == {"uid": DEMO}
    # Rails suppresses a Set-Cookie write when the supplied cookie is unchanged.
    assert not any(c.startswith("auth_cookie=") for c in current.headers.get_list("set-cookie"))
    signed_out = api.request("DELETE", "/auth/sign_out", headers={"Cookie": value})
    assert signed_out.json() == {"success": True}
    deleted = next(
        c for c in signed_out.headers.get_list("set-cookie") if c.startswith("auth_cookie=")
    )
    assert "max-age=0" in deleted.lower()
    assert api.request("GET", "/me", headers={"Cookie": value}).status_code == 401


def test_O1_oauth() -> None:
    pytest.skip("O1 no fake OAuth provider configured")


def test_G1_account_type_isolation(api: API, mail: Mailbox) -> None:
    user = api.login()
    assert api.request("GET", "/admin_auth/validate_token", headers=user).status_code == 401
    registration = api.request(
        "POST",
        "/admin_auth",
        json={
            "email": DEMO,
            "password": PASSWORD,
            "password_confirmation": PASSWORD,
            "confirm_success_url": REDIRECT,
        },
    )
    assert registration.status_code == 200, registration.text
    # Confirmable admin can be activated by the ordinary confirmation email in strict.
    if "access-token" not in registration.headers:
        mail.follow(api, DEMO, "Confirmation")
        registration = api.request(
            "POST",
            "/admin_auth/sign_in",
            json={"email": DEMO, "password": PASSWORD},
        )
    admin = credentials(registration)
    assert api.request("GET", "/auth/validate_token", headers=admin).status_code == 401
    assert api.request("GET", "/admin_auth/validate_token", headers=admin).status_code == 200


def test_A1_A2_fixture_bcrypt_and_new_hash(api: API, db: Database) -> None:
    assert api.signin().status_code == 200
    assert api.signup().status_code == 200
    stored = db.one("SELECT encrypted_password FROM users WHERE email='new@example.com'")
    assert re.fullmatch(r"\$2[aby]\$12\$[./A-Za-z0-9]{53}", stored)


def test_A3_views(api: API, settings: Settings) -> None:
    account(api.signin(), DEMO, settings)
    response = api.signup()
    account(response, "new@example.com", settings, full=True)


@pytest.mark.profiles("strict")
@pytest.mark.parametrize(
    "field,value", [("locked_at", "2099-01-01 00:00:00"), ("confirmed_at", None)]
)
@pytest.mark.reference_only("D-L: Rails accepts inactive accounts' existing tokens")
def test_A4_inactive_existing_tokens(api: API, db: Database, field: str, value: str | None) -> None:
    values = api.login()
    db.update(DEMO, **{field: value})
    # DTA token validation bypasses active_for_authentication?; document this conflict.
    assert api.request("GET", "/auth/validate_token", headers=values).status_code == 200
    assert api.request("GET", "/me", headers=values).status_code == 200


def test_A5_unpermitted_fields(api: API, db: Database) -> None:
    response = api.signup(role="admin", encrypted_password="forged", confirmed_at="2099-01-01")
    assert response.status_code == 200
    assert db.one("SELECT role FROM users WHERE email='new@example.com'") == "user"
    assert db.one("SELECT encrypted_password FROM users WHERE email='new@example.com'") != "forged"


@pytest.mark.ac2
def test_T3_AC2_cross_backend_auth_and_revocation(api: API, settings: Settings) -> None:
    peer = API(
        settings.peer_url, login_csrf=settings.profile == "cookie" and not settings.reference
    )
    try:
        values = api.login()
        assert peer.request("GET", "/me", headers=values).json() == {"uid": DEMO}
        assert peer.request("DELETE", "/auth/sign_out", headers=values).json() == {"success": True}
        assert api.request("GET", "/me", headers=values).status_code == 401
        values = peer.login()
        assert api.request("GET", "/me", headers=values).json() == {"uid": DEMO}
        assert api.request("DELETE", "/auth/sign_out", headers=values).json() == {"success": True}
        assert peer.request("GET", "/me", headers=values).status_code == 401
    finally:
        peer.close()


@pytest.mark.ogiri_only("D1 is an Ogiri device API; DTA has no /sessions route")
def test_D1_list_clients(api: API) -> None:
    first, second = api.login(), api.login()
    response = api.request("GET", "/auth/sessions", headers=second)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"success", "data"} and body["success"] is True
    rows = body["data"]
    assert len(rows) == 2
    assert [r["client"] for r in rows] == [first["client"], second["client"]]
    assert [r["current"] for r in rows] == [False, True]
    assert all(set(r) == {"client", "created_at", "expiry", "current"} for r in rows)


@pytest.mark.ogiri_only("D2 is an Ogiri device API; DTA has no /sessions route")
def test_D2_remove_owned_client(api: API) -> None:
    first, second, other = api.login(), api.login(), api.login("admin@example.com")
    response = api.request("DELETE", "/auth/sessions/" + first["client"], headers=second)
    assert response.status_code == 200 and response.json() == {"success": True}
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert api.request("GET", "/me", headers=second).status_code == 200
    error(
        api.request("DELETE", "/auth/sessions/" + other["client"], headers=second),
        404,
        "Session not found.",
    )
    error(
        api.request("DELETE", "/auth/sessions/missing", headers=second), 404, "Session not found."
    )


@pytest.mark.ogiri_only("D3 is an Ogiri device API; DTA has no /sessions route")
def test_D3_revoke_all(api: API) -> None:
    first, second, other = api.login(), api.login(), api.login("admin@example.com")
    response = api.request("DELETE", "/auth/sessions", headers=first)
    assert response.status_code == 200 and response.json() == {"success": True}
    assert not (set(response.headers) & (AUTH_KEYS | {"authorization"}))
    assert api.request("GET", "/me", headers=first).status_code == 401
    assert api.request("GET", "/me", headers=second).status_code == 401
    assert api.request("GET", "/me", headers=other).status_code == 200


@pytest.mark.ogiri_only("D-S: DTA stores bcrypt sessions in users.tokens, not the Ogiri table")
def test_T1_T4_session_storage_and_lock_key(api: API, db: Database) -> None:
    values = api.login()
    subject = str(db.one("SELECT id FROM users WHERE uid=%s", (DEMO,)))
    row = db.conn.execute(
        "SELECT realm, tenant_id, subject_id, token_hash FROM ogiri_sessions WHERE client=%s",
        (values["client"],),
    ).fetchone()
    assert row == ("users", "", subject, hashlib.sha256(values["access-token"].encode()).digest())
    parts = [p.encode() for p in ("users", "", subject)]
    raw = b"ogiri-session-admission-v1" + b"".join(len(p).to_bytes(4, "big") + p for p in parts)
    key = hashlib.sha256(raw).digest()
    assert db.one("SELECT count(*) FROM ogiri_subject_locks WHERE lock_key=%s", (key,)) == 1


@pytest.mark.ogiri_only(
    "T2 independent transaction and DB-clock storage is the D-S implementation contract"
)
def test_T2_committed_session_visible_to_second_connection(
    api: API, db: Database, settings: Settings
) -> None:
    values = api.login()
    other = Database(settings)
    try:
        count = other.one(
            (
                "SELECT count(*) FROM ogiri_sessions WHERE client=%s AND "
                "created_at <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint"
            ),
            (values["client"],),
        )
        assert count == 1
        assert (
            db.one("SELECT count(*) FROM ogiri_sessions WHERE client=%s", (values["client"],)) == 1
        )
    finally:
        other.close()


@pytest.mark.reference_only("D-B: Rails crashes on Bearer JSON null")
def test_H2_valid_json_non_object_raises_500(api: API) -> None:
    response = api.request("GET", "/me", headers={"Authorization": "Bearer bnVsbA=="})
    assert response.status_code == 500
    assert response.content == b""


@pytest.mark.profiles("default", "reset-token", "rotation", "cookie")
@pytest.mark.reference_only("D-B: Rails crashes on current_password with default setting")
def test_P5_current_password_with_default_update_raises_500(api: API) -> None:
    response = api.request(
        "PUT",
        "/auth/password",
        headers=api.login(),
        json={
            "password": "changed-password",
            "password_confirmation": "changed-password",
            "current_password": PASSWORD,
        },
    )
    assert response.status_code == 500
    assert response.content == b""


@pytest.mark.profiles("rotation")
def test_H5_rotation_slides_expiry(api: API, db: Database, settings: Settings) -> None:
    values = api.login()
    db.session_expiry(values, 60)
    if not settings.reference:
        # DTA's unbatch parameter is outside the Ogiri contract. Move the DB rotation clock.
        buffer = int(settings.env["OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS"])
        db.execute(
            "UPDATE ogiri_sessions SET rotated_at=floor(extract(epoch FROM "
            "clock_timestamp()) * 1000)::bigint - %s WHERE client=%s",
            ((buffer + 1) * 1000, values["client"]),
        )
    response = api.request("GET", "/me", headers=values, params={"unbatch": "true"})
    assert response.status_code == 200
    auth_headers(response, settings, batch=False)
    now = int(db.one("SELECT extract(epoch FROM clock_timestamp())"))
    assert int(response.headers["expiry"]) - now >= 1209595


def check_store_outage(api: API, settings: Settings) -> None:
    name = settings.database_container
    if not name:
        pytest.skip("H8 store-outage injection requires runner-owned --database-container")
    assert name.startswith("ogiri-suite-")
    docker = shutil.which("docker")
    assert docker is not None
    values = api.login()
    try:
        subprocess.run(  # noqa: S603
            [docker, "stop", name], check=True, capture_output=True, timeout=30
        )
        response = api.request("GET", "/me", headers=values)
        if settings.reference:
            assert response.status_code == 500
            assert response.content == b""
        else:
            error(response, 503, "Authentication service unavailable.")
    finally:
        subprocess.run(  # noqa: S603
            [docker, "start", name], check=True, capture_output=True, timeout=30
        )
        # Restore readiness for fixture connections. This is infrastructure readiness,
        # not an authentication expiry/window wait.
        from runner import wait_database

        wait_database(settings.database_url)


@pytest.mark.parametrize("prefix", ["$2a$", "$2b$", "$2y$"])
def test_A2_migrated_bcrypt_prefixes(api: API, db: Database, prefix: str) -> None:
    stored = str(db.one("SELECT encrypted_password FROM users WHERE email=%s", (DEMO,)))
    db.update(DEMO, encrypted_password=prefix + stored[4:])
    assert api.signin().status_code == 200


@pytest.mark.profiles("strict")
@pytest.mark.parametrize("kind", ["confirmation", "unlock"])
@pytest.mark.reference_only("D-M / E1: Devise one-time token storage differs")
def test_E1_confirmation_raw_and_unlock_digest(
    api: API, db: Database, mail: Mailbox, kind: str
) -> None:
    if kind == "confirmation":
        assert api.signup().status_code == 200
        email, column = "new@example.com", "confirmation_token"
    else:
        email, column = "locked@example.com", "unlock_token"
        assert api.request("POST", "/auth/unlock", json={"email": email}).status_code == 200
    link = urlsplit(mail.link(email, kind))
    values = parse_qs(link.query)
    raw = values[column][0]
    query = (
        "SELECT confirmation_token FROM users WHERE email=%s"
        if kind == "confirmation"
        else "SELECT unlock_token FROM users WHERE email=%s"
    )
    stored = db.one(query, (email,))
    if kind == "confirmation":
        assert set(values) == {"confirmation_token", "config", "redirect_url"}
        assert values["redirect_url"] == [REDIRECT]
        # Pinned Devise stores friendly_token itself, not a digest (E1 disagreement).
        assert stored == raw
        assert re.fullmatch(r"[A-Za-z0-9_-]{20}", stored)
    else:
        assert set(values) == {"unlock_token", "config"}
        assert stored != raw
        assert re.fullmatch(r"[0-9a-f]{64}", stored)
    assert values["config"] == ["default"]


@pytest.mark.profiles("strict")
def test_P3_edit_redirect_allowlist(api: API, mail: Mailbox) -> None:
    link = urlsplit(reset_link(api, mail))
    token = parse_qs(link.query)["reset_password_token"][0]
    response = api.request(
        "GET",
        link.path,
        params={"reset_password_token": token, "redirect_url": "https://evil.example/"},
    )
    error(
        response, 422, "Redirect to 'https://evil.example/' not allowed.", status="error", data=None
    )


@pytest.mark.profiles("strict")
def test_U1_success_resets_failed_attempts(api: API, db: Database) -> None:
    assert api.signin(password="wrong-password").status_code == 401
    assert db.one("SELECT failed_attempts FROM users WHERE email=%s", (DEMO,)) == 1
    assert api.signin().status_code == 200
    assert db.one("SELECT failed_attempts FROM users WHERE email=%s", (DEMO,)) == 0


@pytest.mark.profiles("cookie")
@pytest.mark.reference_only("H2/K1 cookie versus Bearer precedence is unspecified in rev 3")
def test_K1_cookie_precedes_bearer(api: API) -> None:
    response = api.signin()
    cookie = next(
        c for c in response.headers.get_list("set-cookie") if c.startswith("auth_cookie=")
    )
    other = api.login("admin@example.com")
    bearer = base64.b64encode(json.dumps(other).encode()).decode()
    response = api.request(
        "GET",
        "/me",
        headers={"Cookie": cookie.split(";", 1)[0], "Authorization": "Bearer " + bearer},
    )
    assert response.status_code == 200
    assert response.json() == {"uid": DEMO}


def test_P2_configured_default_reset_redirect(api: API, settings: Settings, mail: Mailbox) -> None:
    if not settings.env["OGIRI_DEFAULT_PASSWORD_RESET_URL"]:
        pytest.skip("P2 configured redirect default is exercised with --setting variant")
    response = api.request("POST", "/auth/password", json={"email": DEMO})
    assert response.status_code == 200
    link = urlsplit(mail.link(DEMO, "Reset password"))
    assert parse_qs(link.query)["redirect_url"] == [
        settings.env["OGIRI_DEFAULT_PASSWORD_RESET_URL"]
    ]
    redirect(
        mail.follow(api, DEMO, "Reset password"),
        target=settings.env["OGIRI_DEFAULT_PASSWORD_RESET_URL"],
    )


@pytest.mark.profiles("strict")
def test_C1_auth_headers_confirmation_does_not_issue_client(
    api: API, db: Database, mail: Mailbox
) -> None:
    values = api.login()
    db.update(DEMO, confirmed_at=None)
    assert (
        api.request(
            "POST", "/auth/confirmation", json={"email": DEMO, "redirect_url": REDIRECT}
        ).status_code
        == 200
    )
    link = urlsplit(mail.link(DEMO, "Confirmation"))
    response = api.request("GET", link.path + "?" + link.query, headers=values)
    assert redirect(response) == {"account_confirmation_success": "true"}
    assert "access-token" not in response.headers
    # Neither backend issues a client for DTA token headers; C1 is public in rev 3.
    assert api.request("GET", "/me", headers=values).status_code == 200


@pytest.mark.profiles("strict")
@pytest.mark.reference_only("C1 allowlist contract question; Rails accepts disallowed URLs")
def test_C1_confirmation_does_not_check_redirect_allowlist(api: API, mail: Mailbox) -> None:
    assert api.signup().status_code == 200
    link = urlsplit(mail.link("new@example.com", "Confirmation"))
    token = parse_qs(link.query)["confirmation_token"][0]
    response = api.request(
        "GET",
        link.path,
        params={"confirmation_token": token, "redirect_url": "https://evil.example/"},
    )
    assert response.status_code == 302
    assert response.headers["location"] == "https://evil.example/?account_confirmation_success=true"


@pytest.mark.ogiri_only("D-T: H1 requires a 32-byte, 43-character access token")
def test_H1_D_T_32_byte_token(api: API, settings: Settings) -> None:
    response = api.signin()
    auth_headers(response, settings)
    raw = response.headers["access-token"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", raw)
    assert len(base64.urlsafe_b64decode(raw + "=")) == 32


@pytest.mark.reference_only("D-Q: Rails accepts query and form credentials")
def test_H2_reference_query_and_form_credentials(api: API) -> None:
    values = api.login()
    assert api.request("GET", "/me", params=values).json() == {"uid": DEMO}
    assert api.request("DELETE", "/auth/sign_out", data=values).json() == {"success": True}


@pytest.mark.ogiri_only("D-H: H4 requires Cache-Control no-store")
def test_H4_D_H_no_store(api: API) -> None:
    issued = api.signin()
    current = api.request("GET", "/me", headers=credentials(issued))
    assert current.status_code == 200
    assert issued.headers["cache-control"] == "no-store"
    assert current.headers["cache-control"] == "no-store"


@pytest.mark.ogiri_only("D-B: malformed Bearer JSON null is ignored under H2")
def test_H2_D_B_json_null_ignored(api: API) -> None:
    headers = {"Authorization": "Bearer bnVsbA=="}
    response = api.request("GET", "/me", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"errors": ["You need to sign in or sign up before continuing."]}
    values = api.login()
    assert api.request("GET", "/me", headers=headers | values).json() == {"uid": DEMO}


@pytest.mark.profiles("default", "reset-token", "rotation", "cookie")
@pytest.mark.ogiri_only("D-B: P4 ignores current_password with the default setting")
@pytest.mark.parametrize("current", [PASSWORD, "wrong"])
def test_P4_D_B_ignored_current_password(api: API, settings: Settings, current: str) -> None:
    response = api.request(
        "PUT",
        "/auth/password",
        headers=api.login(),
        json={
            "password": "changed-password",
            "password_confirmation": "changed-password",
            "current_password": current,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["message"] == "Your password has been successfully updated."
    account(response, DEMO, settings, full=True)
    assert api.signin(password="changed-password").status_code == 200


@pytest.mark.profiles("default", "reset-token", "rotation", "cookie")
@pytest.mark.ogiri_only("D-B / R6: rev 3 says supplied current_password is otherwise ignored")
def test_R6_ignored_current_password_default(api: API, settings: Settings) -> None:
    response = api.request(
        "PUT",
        "/auth",
        headers=api.login(),
        json={"name": "Changed", "current_password": "wrong"},
    )
    assert response.status_code == 200, response.text
    account(response, DEMO, settings, full=True, name="Changed")


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-L: inactive accounts fail H3/A4 on the next request")
@pytest.mark.parametrize(
    "field,value", [("locked_at", "2099-01-01 00:00:00"), ("confirmed_at", None)]
)
def test_A4_D_L_inactive_tokens_rejected(
    api: API, db: Database, field: str, value: str | None, settings: Settings
) -> None:
    values = api.login()
    db.update(DEMO, **{field: value})
    error(
        api.request("GET", "/auth/validate_token", headers=values), 401, "Invalid login credentials"
    )
    response = api.request("GET", "/me", headers=values)
    assert response.status_code == 401
    assert response.json() == {"errors": ["You need to sign in or sign up before continuing."]}
    if settings.peer_url:
        peer = API(
            settings.peer_url, login_csrf=settings.profile == "cookie" and not settings.reference
        )
        try:
            assert peer.request("GET", "/me", headers=values).status_code == 401
        finally:
            peer.close()


@pytest.mark.ogiri_only("D-B / H8: store outages return the documented 503 JSON")
def test_H8_D_B_store_outage(api: API, settings: Settings) -> None:
    check_store_outage(api, settings)


@pytest.mark.reference_only("D-B / H8: native Rails returns empty 500 on store outage")
def test_H8_reference_store_outage(api: API, settings: Settings) -> None:
    check_store_outage(api, settings)


@pytest.mark.ogiri_only("D-B / H8: role failures return the documented 403 JSON")
def test_H8_forbidden_body(api: API) -> None:
    response = api.request("GET", "/admin", headers=api.login())
    assert response.status_code == 403
    assert response.json() == {"errors": ["You are not authorized to access this resource."]}


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-B: U3 redirects to a valid local root instead of DTA's malformed URL")
def test_U3_D_B_valid_root_redirect(api: API, mail: Mailbox, db: Database) -> None:
    assert (
        api.request("POST", "/auth/unlock", json={"email": "locked@example.com"}).status_code == 200
    )
    link = urlsplit(mail.link("locked@example.com", "Unlock"))
    response = api.request("GET", link.path + "?" + link.query)
    location = response.headers["location"]
    query = (
        redirect(response, target=api.url + "/")
        if location.startswith("http")
        else redirect(response, target="/")
    )
    assert set(query) == {
        "access-token",
        "client",
        "client_id",
        "config",
        "expiry",
        "token",
        "uid",
        "unlock",
    }
    assert query["unlock"] == "true"
    assert query["client"] == query["client_id"]
    assert query["token"] == query["access-token"]
    values = {k: query[k] for k in ("access-token", "client", "uid")}
    assert api.request("GET", "/me", headers=values).json() == {"uid": "locked@example.com"}
    assert db.one("SELECT locked_at FROM users WHERE email='locked@example.com'") is None
    assert api.request("GET", "/auth/unlock", params={"unlock_token": "invalid"}).status_code == 404


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-C: C1 ignores absent, invalid, stale and valid request credentials")
@pytest.mark.parametrize("kind", ["absent", "invalid", "stale", "valid"])
def test_C1_D_C_credentials_never_issue_client(
    api: API, db: Database, mail: Mailbox, kind: str
) -> None:
    values = api.login()
    if kind == "stale":
        assert api.request("DELETE", "/auth/sign_out", headers=values).status_code == 200
    headers = {} if kind == "absent" else values
    if kind == "invalid":
        headers = values | {"access-token": "invalid"}
    assert api.signup().status_code == 200
    before = db.one("SELECT count(*) FROM ogiri_sessions")
    link = urlsplit(mail.link("new@example.com", "Confirmation"))
    response = api.request("GET", link.path + "?" + link.query, headers=headers)
    assert redirect(response) == {"account_confirmation_success": "true"}
    assert not (set(response.headers) & (AUTH_KEYS | {"authorization"}))
    assert db.one("SELECT count(*) FROM ogiri_sessions") == before
    assert db.one("SELECT confirmed_at FROM users WHERE email='new@example.com'") is not None


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-B: R11/C1 nil redirect requires a contract decision")
def test_C1_D_B_nil_redirect_contract_question() -> None:
    pytest.skip("Rev 3 specifies no valid-token result without a known redirect; report question")


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-C: C1 redirect allowlist requires a contract decision")
def test_C1_redirect_allowlist_contract_question() -> None:
    pytest.skip(
        "Rev 3 does not settle C1 allowlist enforcement or its rejection body; report question"
    )


@pytest.mark.ogiri_only("D-M / E1: all new one-time tokens use 32 bytes and SHA-256 hex storage")
@pytest.mark.parametrize("kind", ["password", "confirmation", "unlock"])
def test_E1_ogiri_sha256_one_time_tokens(
    api: API, db: Database, mail: Mailbox, settings: Settings, kind: str
) -> None:
    if kind != "password" and settings.profile != "strict":
        pytest.skip("confirmation/unlock require strict profile")
    if kind == "password":
        link = urlsplit(reset_link(api, mail))
        email, column = DEMO, "reset_password_token"
    elif kind == "confirmation":
        assert api.signup().status_code == 200
        link = urlsplit(mail.link("new@example.com", "Confirmation"))
        email, column = "new@example.com", "confirmation_token"
    else:
        email, column = "locked@example.com", "unlock_token"
        assert api.request("POST", "/auth/unlock", json={"email": email}).status_code == 200
        link = urlsplit(mail.link(email, "Unlock"))
    raw = parse_qs(link.query)[column][0]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", raw)
    assert len(base64.urlsafe_b64decode(raw + "=")) == 32
    queries = {
        "reset_password_token": "SELECT reset_password_token FROM users WHERE email=%s",
        "confirmation_token": "SELECT confirmation_token FROM users WHERE email=%s",
        "unlock_token": "SELECT unlock_token FROM users WHERE email=%s",
    }
    stored = db.one(queries[column], (email,))
    assert stored == hashlib.sha256(raw.encode("ascii")).hexdigest()
    if settings.peer_url:
        peer = API(
            settings.peer_url, login_csrf=settings.profile == "cookie" and not settings.reference
        )
        try:
            response = peer.request("GET", link.path + "?" + link.query)
            assert response.status_code == 302
        finally:
            peer.close()


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-M: an in-flight Devise raw confirmation token is not an Ogiri digest")
def test_E1_D_M_legacy_raw_confirmation_rejected(api: API, db: Database) -> None:
    raw = "legacy-confirm-token"
    db.update(DEMO, confirmed_at=None, confirmation_token=raw)
    response = api.request(
        "GET", "/auth/confirmation", params={"confirmation_token": raw, "redirect_url": REDIRECT}
    )
    assert redirect(response) == {"account_confirmation_success": "false"}
    assert db.one("SELECT confirmed_at FROM users WHERE email=%s", (DEMO,)) is None


@pytest.mark.profiles("cookie")
@pytest.mark.ogiri_only("D-K: K1 cookie defaults and double-submit CSRF on unsafe cookie auth")
def test_K1_D_K_cookie_defaults_and_csrf(api: API) -> None:
    bootstrap = api.request("GET", "/auth/sign_in")
    xsrf = next(c for c in bootstrap.headers.get_list("set-cookie") if c.startswith("XSRF-TOKEN="))
    issued = api.request(
        "POST",
        "/auth/sign_in",
        json={"email": DEMO, "password": PASSWORD},
        headers={
            "Cookie": xsrf.split(";", 1)[0],
            "X-XSRF-TOKEN": unquote(xsrf.split(";", 1)[0].split("=", 1)[1]),
        },
    )
    assert issued.status_code == 200, issued.text
    cookies = issued.headers.get_list("set-cookie") + bootstrap.headers.get_list("set-cookie")
    auth = next(c for c in cookies if c.startswith("auth_cookie="))
    xsrf = next(c for c in cookies if c.startswith("XSRF-TOKEN="))
    for attribute in ("httponly", "samesite=lax", "path=/"):
        assert attribute in auth.lower()
    assert "httponly" not in xsrf.lower()
    cookie = auth.split(";", 1)[0] + "; " + xsrf.split(";", 1)[0]
    assert api.request("GET", "/me", headers={"Cookie": cookie}).status_code == 200
    for extra in ({}, {"X-XSRF-TOKEN": "wrong"}):
        rejected = api.request("DELETE", "/auth/sign_out", headers={"Cookie": cookie} | extra)
        assert 400 <= rejected.status_code < 500
        assert api.request("GET", "/me", headers={"Cookie": cookie}).status_code == 200
    value = unquote(xsrf.split(";", 1)[0].split("=", 1)[1])
    signed_out = api.request(
        "DELETE", "/auth/sign_out", headers={"Cookie": cookie, "X-XSRF-TOKEN": value}
    )
    assert signed_out.status_code == 200
    assert signed_out.json() == {"success": True}
    assert not (set(signed_out.headers) & (AUTH_KEYS | {"authorization"}))
    deleted = next(
        c for c in signed_out.headers.get_list("set-cookie") if c.startswith("auth_cookie=")
    )
    assert "max-age=0" in deleted.lower() or "expires=" in deleted.lower()
    assert api.request("GET", "/me", headers={"Cookie": cookie}).status_code == 401
    # Explicit auth headers select header authentication and never need CSRF.
    headers = api.login()
    assert api.request("DELETE", "/auth/sign_out", headers=headers).status_code == 200


@pytest.mark.ogiri_only("D-S / H4: removing the current device ends its response session")
def test_D2_current_client_has_no_auth_headers(api: API) -> None:
    values = api.login()
    response = api.request("DELETE", "/auth/sessions/" + values["client"], headers=values)
    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert not (set(response.headers) & (AUTH_KEYS | {"authorization"}))
    assert api.request("GET", "/me", headers=values).status_code == 401


@pytest.mark.ogiri_only("D-S / T5: session clocks are epoch milliseconds; wire expiry is seconds")
def test_T5_epoch_ms_and_header_floor(api: API, db: Database, settings: Settings) -> None:
    before = int(db.one("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)"))
    issued = api.signin()
    values = credentials(issued)
    row = db.conn.execute(
        "SELECT created_at, expires_at, rotated_at FROM ogiri_sessions WHERE client=%s",
        (values["client"],),
    ).fetchone()
    assert row is not None
    created, expires, rotated = row
    after = int(db.one("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)"))
    assert before <= created <= after
    assert abs(expires - created - int(settings.env["OGIRI_TOKEN_LIFESPAN_SECONDS"]) * 1000) <= 3000
    assert int(issued.headers["expiry"]) == expires // 1000
    assert rotated is None or before <= rotated <= after


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-S / T5: P6 retains greatest (created_at, id), independent of expiry")
@pytest.mark.parametrize("tie", [False, True])
def test_P6_T5_recency_not_expiry(api: API, db: Database, mail: Mailbox, tie: bool) -> None:
    first = api.login()
    link = urlsplit(reset_link(api, mail))
    query = redirect(api.request("GET", link.path + "?" + link.query))
    last = {k: query[k] for k in ("access-token", "client", "uid")}
    now = int(db.one("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)"))
    if tie:
        db.execute(
            "UPDATE ogiri_sessions SET created_at=%s WHERE client IN (%s,%s)",
            (now - 1000, first["client"], last["client"]),
        )
    else:
        db.execute(
            "UPDATE ogiri_sessions SET created_at=%s WHERE client=%s", (now - 2000, first["client"])
        )
        db.execute(
            "UPDATE ogiri_sessions SET created_at=%s WHERE client=%s", (now - 1000, last["client"])
        )
    winner = str(
        db.one("SELECT client FROM ogiri_sessions ORDER BY created_at DESC, id DESC LIMIT 1")
    )
    loser = last["client"] if winner == first["client"] else first["client"]
    db.execute("UPDATE ogiri_sessions SET expires_at=%s WHERE client=%s", (now + 120000, winner))
    db.execute("UPDATE ogiri_sessions SET expires_at=%s WHERE client=%s", (now + 240000, loser))
    response = api.request(
        "PUT",
        "/auth/password",
        headers=last,
        json={"password": "changed-password", "password_confirmation": "changed-password"},
    )
    assert response.status_code == 200
    assert db.one("SELECT count(*) FROM ogiri_sessions") == 1
    assert db.one("SELECT client FROM ogiri_sessions") == winner
    for values in (first, last):
        assert api.request("GET", "/me", headers=values).status_code == (
            200 if values["client"] == winner else 401
        )


@pytest.mark.profiles("strict")
@pytest.mark.reference_only("D-S / T5: DTA retains greatest expiry rather than issuance order")
def test_P6_reference_greatest_expiry_over_issuance(api: API, db: Database, mail: Mailbox) -> None:
    first = api.login()
    db.session_expiry(first, 2400000)
    link = urlsplit(reset_link(api, mail))
    query = redirect(api.request("GET", link.path + "?" + link.query))
    last = {k: query[k] for k in ("access-token", "client", "uid")}
    response = api.request(
        "PUT",
        "/auth/password",
        headers=last,
        json={"password": "changed-password", "password_confirmation": "changed-password"},
    )
    assert response.status_code == 200
    assert api.request("GET", "/me", headers=first).status_code == 200
    assert api.request("GET", "/me", headers=last).status_code == 401


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-A: redirect patterns match URL parts, never the raw URL")
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/#.example.test/x",
        "https://evil.test/?a=.example.test/",
        "https://user@evil.test/x",
    ],
)
def test_R5_D_A_deceptive_confirmation_redirect(api: API, settings: Settings, url: str) -> None:
    assert settings.env["OGIRI_REDIRECT_ALLOWLIST"] == "https://*.example.test/*"
    response = api.signup(confirm_success_url=url)
    error(
        response,
        422,
        f"Redirect to '{url}' not allowed.",
        status="error",
        data=response.json()["data"],
    )
    assert set(response.json()["data"]) == FULL_KEYS
    assert "location" not in response.headers


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-A: reset links never redirect to deceptive wildcard matches")
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/#.example.test/x",
        "https://evil.test/?a=.example.test/",
        "https://user@evil.test/x",
    ],
)
def test_P3_D_A_deceptive_reset_redirect(
    api: API, mail: Mailbox, settings: Settings, url: str
) -> None:
    assert settings.env["OGIRI_REDIRECT_ALLOWLIST"] == "https://*.example.test/*"
    link = urlsplit(reset_link(api, mail))
    token = parse_qs(link.query)["reset_password_token"][0]
    response = api.request(
        "GET", link.path, params={"reset_password_token": token, "redirect_url": url}
    )
    error(response, 422, f"Redirect to '{url}' not allowed.", status="error", data=None)
    assert "location" not in response.headers


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("D-A: a real wildcard subdomain remains allowed")
@pytest.mark.parametrize("endpoint", ["registration", "reset"])
def test_R5_P3_D_A_allowed_subdomain(
    api: API, mail: Mailbox, settings: Settings, endpoint: str
) -> None:
    assert settings.env["OGIRI_REDIRECT_ALLOWLIST"] == "https://*.example.test/*"
    url = "https://app.example.test/reset"
    if endpoint == "registration":
        response = api.signup(confirm_success_url=url)
        assert response.status_code == 200, response.text
        link = urlsplit(mail.link("new@example.com", "Confirmation"))
        assert parse_qs(link.query)["redirect_url"] == [url]
    else:
        link = urlsplit(reset_link(api, mail))
        token = parse_qs(link.query)["reset_password_token"][0]
        response = api.request(
            "GET", link.path, params={"reset_password_token": token, "redirect_url": url}
        )
        assert redirect(response, target=url)["reset_password"] == "true"  # noqa: S105


@pytest.mark.ogiri_only("D-V: default views omit the unconfigured fixture role column")
def test_A3_D_V_default_views(api: API, db: Database) -> None:
    signed_in = api.signin("admin@example.com")
    assert signed_in.status_code == 200, signed_in.text
    assert set(signed_in.json()["data"]) == TOKEN_KEYS
    validated = api.request("GET", "/auth/validate_token", headers=credentials(signed_in))
    assert validated.status_code == 200, validated.text
    assert set(validated.json()["data"]) == TOKEN_KEYS
    updated = api.request(
        "PATCH",
        "/auth",
        headers=credentials(signed_in),
        json={"name": "Admin", "current_password": PASSWORD},
    )
    assert updated.status_code == 200, updated.text
    assert set(updated.json()["data"]) == FULL_KEYS
    registered = api.signup()
    assert registered.status_code == 200, registered.text
    assert set(registered.json()["data"]) == FULL_KEYS
    assert db.one("SELECT role FROM users WHERE email='admin@example.com'") == "admin"


def test_R6_P6_password_change_invalidates_earlier_reset_link(
    api: API, db: Database, mail: Mailbox, settings: Settings
) -> None:
    earlier = api.login()
    db.session_expiry(earlier, 60)
    current = api.login()
    link = urlsplit(reset_link(api, mail))
    assert db.one("SELECT reset_password_token FROM users WHERE email=%s", (DEMO,))
    response = api.request(
        "PATCH",
        "/auth",
        headers=current,
        json={"password": "changed-password", "password_confirmation": "changed-password"}
        | ({"current_password": PASSWORD} if settings.profile == "strict" else {}),
    )
    assert response.status_code == 200, response.text
    assert db.one("SELECT reset_password_token FROM users WHERE email=%s", (DEMO,)) is None
    assert db.one("SELECT reset_password_sent_at FROM users WHERE email=%s", (DEMO,)) is None
    assert api.request("GET", link.path + "?" + link.query).status_code == 404
    assert api.request("GET", "/me", headers=current).status_code == 200
    assert api.request("GET", "/me", headers=earlier).status_code == (
        401
        if settings.env["OGIRI_REMOVE_TOKENS_AFTER_PASSWORD_RESET"] == "true"  # noqa: S105 -- boolean setting
        else 200
    )
    assert api.signin(password="changed-password").status_code == 200


@pytest.mark.profiles("strict")
@pytest.mark.ogiri_only("U2/U3: pinned DTA sends unlock mail even when the account is unlocked")
def test_U2_U3_unlocked_account_sends_no_mail(
    api: API, db: Database, mail: Mailbox, settings: Settings
) -> None:
    assert db.one("SELECT locked_at FROM users WHERE email=%s", (DEMO,)) is None
    response = api.request("POST", "/auth/unlock", json={"email": DEMO})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "success": True,
        "message": PARANOID["unlock"]
        if settings.env["OGIRI_PARANOID"] == "true"
        else (
            f"An email has been sent to '{DEMO}' "
            "containing instructions for unlocking your account."
        ),
    }
    messages = mail.http.get("/api/v1/messages")
    messages.raise_for_status()
    assert messages.json()["messages"] == []
    assert db.one("SELECT unlock_token FROM users WHERE email=%s", (DEMO,)) is None


@pytest.mark.profiles("strict")
@pytest.mark.reference_only("U2: native DTA bypasses Devise's if_access_locked guard")
def test_U2_reference_unlocked_account_receives_mail(api: API, db: Database, mail: Mailbox) -> None:
    assert db.one("SELECT locked_at FROM users WHERE email=%s", (DEMO,)) is None
    response = api.request("POST", "/auth/unlock", json={"email": DEMO})
    assert response.status_code == 200, response.text
    assert "/auth/unlock?" in mail.link(DEMO, "Unlock")
    assert db.one("SELECT unlock_token FROM users WHERE email=%s", (DEMO,)) is not None
    assert db.one("SELECT locked_at FROM users WHERE email=%s", (DEMO,)) is None


@pytest.mark.profiles("cookie")
@pytest.mark.ogiri_only("D-K: cookie-mode login requires double-submit even without auth cookies")
def test_K1_login_csrf_and_stale_cookie_signin(api: API, db: Database) -> None:
    payload = {"email": DEMO, "password": PASSWORD}
    before = db.one("SELECT COUNT(*) FROM ogiri_sessions")
    for headers in ({}, {"Cookie": "auth_cookie=stale"}, {"X-XSRF-TOKEN": "forged"}):
        response = api.request(
            "POST", "/auth/sign_in", json=payload, headers=headers, login_csrf=False
        )
        error(response, 403, "Invalid CSRF token")
    bootstrap = api.request("GET", "/auth/sign_in")
    xsrf = next(
        c.split(";", 1)[0]
        for c in bootstrap.headers.get_list("set-cookie")
        if c.startswith("XSRF-TOKEN=")
    )
    parameter_only = api.request(
        "POST",
        "/auth/sign_in",
        json=payload,
        params={"_csrf": xsrf.split("=", 1)[1]},
        headers={"Cookie": xsrf},
        login_csrf=False,
    )
    error(parameter_only, 403, "Invalid CSRF token")
    assert db.one("SELECT COUNT(*) FROM ogiri_sessions") == before
    response = api.request(
        "POST", "/auth/sign_in", json=payload, headers={"Cookie": "auth_cookie=stale"}
    )
    assert response.status_code == 200, response.text
    assert api.request("GET", "/me", headers=credentials(response)).status_code == 200


@pytest.mark.profiles("cookie")
@pytest.mark.ogiri_only("H2/D-K: malformed or partial Bearer fields cannot bypass cookie CSRF")
def test_K1_source_precedence_and_realm_isolation(api: API) -> None:
    bootstrap = api.request("GET", "/auth/sign_in")
    csrf = next(
        c.split(";", 1)[0]
        for c in bootstrap.headers.get_list("set-cookie")
        if c.startswith("XSRF-TOKEN=")
    )
    issued = api.request(
        "POST",
        "/auth/sign_in",
        json={"email": DEMO, "password": PASSWORD},
        headers={"Cookie": csrf, "X-XSRF-TOKEN": unquote(csrf.split("=", 1)[1])},
    )
    assert issued.status_code == 200, issued.text
    auth = next(
        c.split(";", 1)[0]
        for c in issued.headers.get_list("set-cookie")
        if c.startswith("auth_cookie=")
    )
    xsrf = csrf
    cookie = auth + "; " + xsrf
    malformed = base64.b64encode(
        json.dumps({"uid": 1, "access-token": False, "client": []}).encode()
    ).decode()
    for extra in (
        {"Authorization": "Bearer !!!"},
        {"Authorization": "Bearer " + malformed},
        {"uid": DEMO},
    ):
        rejected = api.request("DELETE", "/auth/sign_out", headers={"Cookie": cookie} | extra)
        error(rejected, 403, "Invalid CSRF token")
        assert api.request("GET", "/me", headers={"Cookie": auth}).status_code == 200
    for foreign in (auth, auth.replace("auth_cookie=", "admin_auth_cookie=", 1)):
        error(
            api.request("GET", "/admin_auth/validate_token", headers={"Cookie": foreign}),
            401,
            "Invalid login credentials",
        )
    encoded = base64.b64encode(json.dumps(credentials(issued)).encode()).decode()
    signed_out = api.request(
        "DELETE", "/auth/sign_out", headers={"Cookie": cookie, "Authorization": "Bearer " + encoded}
    )
    assert signed_out.status_code == 200, signed_out.text
    assert any(
        "max-age=0" in c.lower()
        for c in signed_out.headers.get_list("set-cookie")
        if c.startswith("auth_cookie=")
    )


@pytest.mark.profiles("cookie")
@pytest.mark.ogiri_only("D-K rev 3.5: registration that signs in requires double-submit CSRF")
@pytest.mark.parametrize("form", [True, False], ids=["form", "json"])
@pytest.mark.parametrize(
    "mount, table, auth_cookie",
    [
        ("/auth", "users", "auth_cookie"),
        ("/admin_auth/", "admins", "admin_auth_cookie"),
    ],
)
def test_K1_registration_csrf_before_account_and_session_creation(
    api: API,
    db: Database,
    settings: Settings,
    form: bool,
    mount: str,
    table: str,
    auth_cookie: str,
) -> None:
    assert settings.env["OGIRI_CONFIRMABLE"] == "false"
    payload = {
        "email": "csrf-signup@example.com",
        "password": PASSWORD,
        "password_confirmation": PASSWORD,
    }
    # Table names are constrained by the parametrization; use fixed SQL per realm.
    count_sql = "SELECT count(*) FROM users" if table == "users" else "SELECT count(*) FROM admins"
    accounts = db.one(count_sql)
    sessions = db.one("SELECT count(*) FROM ogiri_sessions")
    rejected = api.request(
        "POST",
        mount,
        data=payload if form else None,
        json=None if form else payload,
        login_csrf=False,
    )
    assert rejected.status_code == 403, rejected.text
    assert rejected.json() == {"success": False, "errors": ["Invalid CSRF token"]}
    assert db.one(count_sql) == accounts
    assert db.one("SELECT count(*) FROM ogiri_sessions") == sessions
    assert not any(c.startswith(auth_cookie + "=") for c in rejected.headers.get_list("set-cookie"))
    bootstrap = api.request("GET", mount)
    xsrf = next(
        c.split(";", 1)[0]
        for c in bootstrap.headers.get_list("set-cookie")
        if c.startswith("XSRF-TOKEN=")
    )
    accepted = api.request(
        "POST",
        mount,
        data=payload if form else None,
        json=None if form else payload,
        login_csrf=False,
        headers={"Cookie": xsrf, "X-XSRF-TOKEN": unquote(xsrf.split("=", 1)[1])},
    )
    assert accepted.status_code == 200, accepted.text
    assert any(c.startswith(auth_cookie + "=") for c in accepted.headers.get_list("set-cookie"))
    assert db.one(count_sql) == accounts + 1
    assert db.one("SELECT count(*) FROM ogiri_sessions") == sessions + 1


@pytest.mark.profiles("cookie")
@pytest.mark.ogiri_only("D-K rev 3.5: late batch responses cannot overwrite rotated auth cookies")
def test_K1_H5_late_batch_preserves_rotated_auth_cookie(
    api: API, db: Database, settings: Settings
) -> None:
    if settings.env["OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST"] != "true":
        pytest.skip("requires cookie profile with OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST=true")
    issued = api.signin()
    assert issued.status_code == 200, issued.text
    original = next(
        c.split(";", 1)[0]
        for c in issued.headers.get_list("set-cookie")
        if c.startswith("auth_cookie=")
    )
    client = issued.headers["client"]
    db.execute("UPDATE ogiri_sessions SET rotated_at=0 WHERE client=%s", (client,))
    rotated = api.request("GET", "/me", headers={"Cookie": original})
    assert rotated.status_code == 200, rotated.text
    current = next(
        c.split(";", 1)[0]
        for c in rotated.headers.get_list("set-cookie")
        if c.startswith("auth_cookie=")
    )
    assert current != original
    late = api.request("GET", "/me", headers={"Cookie": original})
    assert late.status_code == 200, late.text
    assert not late.headers["access-token"].strip()
    assert not any(c.startswith("auth_cookie=") for c in late.headers.get_list("set-cookie"))
    db.execute("UPDATE ogiri_sessions SET rotated_at=0 WHERE client=%s", (client,))
    assert api.request("GET", "/me", headers={"Cookie": original}).status_code == 401
    assert api.request("GET", "/me", headers={"Cookie": current}).status_code == 200
