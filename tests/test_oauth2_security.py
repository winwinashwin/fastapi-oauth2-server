"""HTTP-level security contract tests for the example OAuth 2.0 provider."""

import base64
import hashlib
import json
import re
import time
import typing as t
from urllib.parse import parse_qs, urlencode, urlparse

import httpx2
import jwt
import jwt.algorithms
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


REDIRECT_URI = "https://client.example.test/callback"


@pytest.fixture(scope="session")
def browser(tmp_path_factory: pytest.TempPathFactory) -> t.Iterator[TestClient]:
    database = tmp_path_factory.mktemp("oauth") / "oauth.sqlite"
    pytest.MonkeyPatch().setenv("SECRET_KEY", "a" * 36)
    pytest.MonkeyPatch().setenv("SQLALCHEMY_DATABASE_URI", f"sqlite:///{database}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pytest.MonkeyPatch().setenv("OIDC_ISSUER", "https://server.example.test")
    pytest.MonkeyPatch().setenv("OIDC_PRIVATE_KEY_PEM", private_key)
    pytest.MonkeyPatch().setenv("OIDC_KEY_ID", "test-key")

    from fastapi_oauth2.asgi import create_app

    with TestClient(create_app(), base_url="https://server.example.test") as client:
        yield client


def basic_auth(client: dict[str, str]) -> httpx2.Auth:
    return httpx2.BasicAuth(client["client_id"], client["client_secret"])


def create_client(
    browser: TestClient,
    *,
    name: str,
    grant_types: str,
    scope: str,
    redirect_uri: str = REDIRECT_URI,
    response_types: str = "code",
) -> dict[str, str]:
    browser.post("/sessions", data={"username": name})
    response = browser.post(
        "/clients",
        data={
            "client_name": name,
            "client_uri": "https://client.example.test",
            "scope": scope,
            "redirect_uri": redirect_uri,
            "grant_type": grant_types,
            "response_type": response_types,
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert response.status_code == 200
    values = dict(re.findall(r"<strong>\s*(client_id|client_secret):\s*</strong>\s*([^<\s]+)", response.text))
    assert values.keys() == {"client_id", "client_secret"}
    return values


@pytest.fixture
def code_client(browser: TestClient, request: pytest.FixtureRequest) -> dict[str, str]:
    return create_client(
        browser,
        name=f"code-{request.node.name}",
        grant_types="authorization_code\nrefresh_token",
        scope="user:read",
    )


def verifier() -> str:
    return "A" * 43


def challenge(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def test_session_routes_create_and_delete_the_browser_session(browser: TestClient) -> None:
    created = browser.post("/sessions", data={"username": "session-route-user"}, follow_redirects=False)
    assert created.status_code == 302
    assert created.headers["location"] == "/"
    assert "Welcome back, session-route-user" in browser.get("/").text

    deleted = browser.post("/sessions/current", follow_redirects=False)
    assert deleted.status_code == 302
    assert deleted.headers["location"] == "/"
    assert "Sign in to continue" in browser.get("/").text


def authorize(
    browser: TestClient,
    client: dict[str, str],
    *,
    redirect_uri: str = REDIRECT_URI,
    state: str = "state-value",
    code_verifier: str | None = None,
    response_type: str = "code",
    scope: str = "user:read",
    extra: list[tuple[str, str]] | None = None,
) -> httpx2.Response:
    code_verifier = code_verifier or verifier()
    params: list[tuple[str, str]] = [
        ("response_type", response_type),
        ("client_id", client["client_id"]),
        ("redirect_uri", redirect_uri),
        ("scope", scope),
        ("state", state),
        ("code_challenge", challenge(code_verifier)),
        ("code_challenge_method", "S256"),
    ]
    if extra:
        params.extend(extra)
    query = urlencode(params)
    consent = browser.get(f"/oauth/authorize?{query}", follow_redirects=False)
    if consent.status_code != 200:
        return consent
    return browser.post(f"/oauth/authorize?{query}", data={"confirm": "on"}, follow_redirects=False)


def authorization_code(response: httpx2.Response) -> str:
    assert response.status_code == 302
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def exchange(browser: TestClient, client: dict[str, str], code: str, **data: str) -> httpx2.Response:
    payload = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, **data}
    return browser.post("/oauth/token", data=payload, auth=basic_auth(client))


def assert_oauth_error(response: httpx2.Response, error: str, status_code: int = 400) -> None:
    assert response.status_code == status_code
    assert response.json()["error"] == error


def test_s256_authorization_code_and_state_survive(browser: TestClient, code_client: dict[str, str]) -> None:
    response = authorize(browser, code_client, state="opaque%2Bvalue / unchanged")
    parsed = parse_qs(urlparse(response.headers["location"]).query)
    assert parsed["state"] == ["opaque%2Bvalue / unchanged"]
    token = exchange(browser, code_client, parsed["code"][0], code_verifier=verifier())
    assert token.status_code == 200
    assert (
        browser.get("/users/me", headers={"Authorization": f"Bearer {token.json()['access_token']}"}).status_code == 200
    )


def test_authorization_code_cannot_be_reused(browser: TestClient, code_client: dict[str, str]) -> None:
    code = authorization_code(authorize(browser, code_client))
    assert exchange(browser, code_client, code, code_verifier=verifier()).status_code == 200
    assert_oauth_error(exchange(browser, code_client, code, code_verifier=verifier()), "invalid_grant")


@pytest.mark.parametrize("binding", ["client", "redirect_uri", "verifier"])
def test_code_is_bound_to_client_redirect_uri_and_verifier(
    browser: TestClient, code_client: dict[str, str], request: pytest.FixtureRequest, binding: str
) -> None:
    code = authorization_code(authorize(browser, code_client))
    other = create_client(
        browser, name=f"other-{request.node.name}", grant_types="authorization_code", scope="user:read"
    )
    kwargs = {"code_verifier": verifier()}
    client = code_client
    if binding == "client":
        client = other
    elif binding == "redirect_uri":
        kwargs["redirect_uri"] = "https://client.example.test/other"
    else:
        kwargs["code_verifier"] = "B" * 43
    assert_oauth_error(exchange(browser, client, code, **kwargs), "invalid_grant")


def test_authorization_codes_have_short_lifetimes(
    browser: TestClient,
    code_client: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi_oauth2 import models

    def is_expired(self: t.Any) -> bool:  # noqa: ANN401
        return self.auth_time + 1 < time.time()

    monkeypatch.setattr(models.OAuth2AuthorizationCode, "is_expired", is_expired)
    code = authorization_code(authorize(browser, code_client))
    time.sleep(1.1)
    assert_oauth_error(exchange(browser, code_client, code, code_verifier=verifier()), "invalid_grant")


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ([("code_challenge", "")], "invalid_request"),
        (
            [("code_challenge", verifier()), ("code_challenge_method", "plain")],
            "invalid_request",
        ),
        ([("code_challenge", challenge(verifier()))], "invalid_request"),
    ],
)
def test_authorization_cannot_downgrade_pkce(
    browser: TestClient, code_client: dict[str, str], extra: list[tuple[str, str]], expected: str
) -> None:
    # Build the requests directly because this helper normally adds S256.
    params = [
        ("response_type", "code"),
        ("client_id", code_client["client_id"]),
        ("redirect_uri", REDIRECT_URI),
        *extra,
    ]
    response = browser.get("/oauth/authorize?" + urlencode(params), follow_redirects=False)
    assert response.status_code in {302, 400}
    if response.status_code == 302:
        assert parse_qs(urlparse(response.headers["location"]).query)["error"] == [expected]
    else:
        assert response.json()["error"] == expected


@pytest.mark.parametrize(
    "candidate",
    [
        "https://client.example.test/callback/",
        "https://client.example.test:443/callback",
        "http://client.example.test/callback",
        "https://client.example.test/callback?x=1",
    ],
)
def test_redirect_uri_requires_exact_matching(browser: TestClient, code_client: dict[str, str], candidate: str) -> None:
    response = authorize(browser, code_client, redirect_uri=candidate)
    assert response.status_code == 400
    assert "client.example.test/callback" not in response.headers.get("location", "")


def test_unsupported_response_type_preserves_state(browser: TestClient, code_client: dict[str, str]) -> None:
    response = authorize(browser, code_client, response_type="token", state="do-not-change")

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["do-not-change"]


def test_duplicate_and_malformed_parameters_are_rejected_safely(
    browser: TestClient, code_client: dict[str, str]
) -> None:
    duplicate = authorize(browser, code_client, extra=[("state", "second")])
    assert_oauth_error(duplicate, "invalid_request")

    code = authorization_code(authorize(browser, code_client))
    token = browser.post(
        "/oauth/token",
        content=f"grant_type=authorization_code&code={code}&code=evil&redirect_uri={REDIRECT_URI}&code_verifier={verifier()}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=basic_auth(code_client),
    )
    assert_oauth_error(token, "invalid_grant")
    malformed = browser.get("/oauth/authorize?%ZZ", follow_redirects=False)
    assert malformed.status_code < 500


def test_client_credentials_are_unambiguous_and_secret_transport_is_basic_only(
    browser: TestClient, code_client: dict[str, str]
) -> None:
    ambiguous = browser.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": code_client["client_id"]},
        auth=basic_auth(code_client),
    )
    assert_oauth_error(ambiguous, "unauthorized_client")

    payload = {
        "grant_type": "client_credentials",
        "client_id": code_client["client_id"],
        "client_secret": code_client["client_secret"],
    }
    for location in ("form", "query", "json"):
        if location == "form":
            response = browser.post("/oauth/token", data=payload)
            assert_oauth_error(response, "invalid_client", 401)
        elif location == "query":
            response = browser.post("/oauth/token", params=payload)
            assert_oauth_error(response, "invalid_client", 401)
        elif location == "json":
            response = browser.post("/oauth/token", json=payload)
            assert_oauth_error(response, "unsupported_grant_type", 400)


def test_refresh_token_is_client_bound_rotated_and_revocable(browser: TestClient, code_client: dict[str, str]) -> None:
    code = authorization_code(authorize(browser, code_client))
    initial = exchange(browser, code_client, code, code_verifier=verifier()).json()
    other = create_client(browser, name="refresh-other", grant_types="refresh_token", scope="user:read")
    wrong_client = browser.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": initial["refresh_token"]},
        auth=basic_auth(other),
    )
    assert_oauth_error(wrong_client, "invalid_grant")

    rotated = browser.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": initial["refresh_token"]},
        auth=basic_auth(code_client),
    )
    assert rotated.status_code == 200
    assert "refresh_token" in rotated.json()
    assert_oauth_error(
        browser.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": initial["refresh_token"]},
            auth=basic_auth(code_client),
        ),
        "invalid_grant",
    )

    revoke = browser.post(
        "/oauth/revoke",
        data={"token": rotated.json()["refresh_token"], "token_type_hint": "refresh_token"},
        auth=basic_auth(code_client),
    )
    assert revoke.status_code == 200
    assert_oauth_error(
        browser.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": rotated.json()["refresh_token"]},
            auth=basic_auth(code_client),
        ),
        "invalid_grant",
    )


def test_machine_credentials_receive_only_machine_scope(browser: TestClient) -> None:
    client = create_client(
        browser,
        name="machine",
        grant_types="client_credentials",
        scope="machine:read",
        redirect_uri="",
        response_types="",
    )
    token = browser.post(
        "/oauth/token", data={"grant_type": "client_credentials", "scope": "machine:read"}, auth=basic_auth(client)
    )
    assert token.status_code == 200
    bearer = {"Authorization": f"Bearer {token.json()['access_token']}"}
    identity = browser.get("/clients/me", headers=bearer)
    assert identity.status_code == 200
    assert identity.json() == {"client_id": client["client_id"]}
    assert browser.get("/users/me", headers=bearer).status_code == 403


def test_openid_code_flow_returns_a_verifiable_id_token_and_userinfo(browser: TestClient) -> None:
    client = create_client(
        browser,
        name="oidc-client",
        grant_types="authorization_code",
        scope="openid profile",
    )
    nonce = "nonce-value"
    code = authorization_code(
        authorize(
            browser,
            client,
            scope="openid profile",
            extra=[("nonce", nonce)],
        )
    )
    response = exchange(browser, client, code, code_verifier=verifier())
    assert response.status_code == 200
    tokens = response.json()
    jwks = browser.get("/oauth/jwks").json()
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    claims = jwt.decode(
        tokens["id_token"],
        public_key,
        algorithms=["RS256"],
        audience=client["client_id"],
        issuer="https://server.example.test",
    )
    assert claims["nonce"] == nonce
    assert claims["preferred_username"] == "oidc-client"
    assert {"iss", "sub", "aud", "exp", "iat", "auth_time", "jti"} <= claims.keys()

    userinfo = browser.get("/oauth/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert userinfo.status_code == 200
    assert userinfo.json() == {"sub": claims["sub"], "preferred_username": "oidc-client"}


@pytest.mark.parametrize("extra", [[], [("nonce", "one"), ("nonce", "two")]])
def test_openid_requests_require_exactly_one_nonce(browser: TestClient, extra: list[tuple[str, str]]) -> None:
    client = create_client(
        browser,
        name=f"oidc-nonce-{len(extra)}",
        grant_types="authorization_code",
        scope="openid",
    )
    response = authorize(browser, client, scope="openid", extra=extra)
    assert response.status_code in {302, 400}
    if response.status_code == 302:
        assert parse_qs(urlparse(response.headers["location"]).query)["error"] == ["invalid_request"]
    else:
        assert response.json()["error"] == "invalid_request"


def test_openid_discovery_and_userinfo_reject_non_oidc_tokens(browser: TestClient, code_client: dict[str, str]) -> None:
    discovery = browser.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == "https://server.example.test"
    assert discovery.json()["jwks_uri"] == "https://server.example.test/oauth/jwks"
    assert browser.get("/oauth/jwks").json()["keys"][0]["alg"] == "RS256"

    code = authorization_code(authorize(browser, code_client))
    access_token = exchange(browser, code_client, code, code_verifier=verifier()).json()["access_token"]
    assert browser.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 403
