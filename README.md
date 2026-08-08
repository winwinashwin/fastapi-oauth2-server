# FastAPI OAuth 2.0 and OpenID Connect example

A deliberately small authorization server built with FastAPI, Authlib, SQLAlchemy, and PyJWT. It demonstrates secure OAuth 2.0 authorization-code and client-credentials flows, plus OpenID Connect Core for browser sign-in.

This is an educational example, not a production-ready identity provider. In particular, users authenticate with a dummy password (`valid`), clients are created through a local HTML page, and schema creation is automatic.

## Features

- OAuth 2.0 authorization-code grant with required PKCE S256.
- Refresh-token rotation and revocation.
- Client-credentials grant for the `machine:read` scope.
- OpenID Connect authorization-code flow with required `nonce`, RS256 ID Tokens, discovery, JWKS, and UserInfo.
- Exact redirect URI matching, one-time authorization codes, and short code lifetime.
- OAuth error handling and black-box security regression tests.

Unsupported flows include implicit and resource-owner-password grants. Dynamic client registration and OIDC logout are also out of scope.

## Requirements

- Python 3.11 or later
- `uv`
- An RSA private key for OpenID Connect signing

Install the project:

```bash
uv sync
```

## Configuration

The application reads environment variables and also supports a `.env` file.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | Yes | Signs browser sessions and internal OAuth access/refresh JWTs. Use a long random value. |
| `SQLALCHEMY_DATABASE_URI` | Yes | SQLAlchemy database URL, for example `sqlite:///oauth.sqlite`. |
| `OIDC_ISSUER` | Yes | Canonical external issuer URL, such as `https://id.example.com`. It becomes the ID Token `iss` claim and discovery `issuer`. |
| `OIDC_PRIVATE_KEY_PEM` | Yes | PEM-encoded RSA private key used to sign RS256 ID Tokens. |
| `OIDC_KEY_ID` | Yes | Stable key identifier (`kid`) published in JWKS and ID Token headers. |

For local development, create a key and export the configuration:

```bash
openssl genrsa -out oidc-private.pem 2048

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SQLALCHEMY_DATABASE_URI="sqlite:///oauth.sqlite"
export OIDC_ISSUER="http://127.0.0.1:8000"
export OIDC_PRIVATE_KEY_PEM="$(cat oidc-private.pem)"
export OIDC_KEY_ID="local-rs256-1"
```

Use an HTTPS issuer and protect the private key in every non-local environment. Do not commit the `.env` file or signing key.

## Run the server

```bash
uv run uvicorn fastapi_oauth2.asgi:create_app --factory
```

On startup the application creates its database tables. Open <http://127.0.0.1:8000/> to create a local user and OAuth client. The example's password flow is intentionally absent; submitting a username to `POST /sessions` creates and signs in that user.

When creating a client, configure the grants, response types, scopes, redirect URIs, and token endpoint authentication method. Use one redirect URI per line. The UI displays the generated client ID and secret after registration.

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Local OAuth client dashboard |
| `/sessions` | POST | Create a local browser session |
| `/sessions/current` | POST | End the current local browser session |
| `/clients/new` | GET | OAuth client registration form |
| `/clients` | POST | Register an OAuth client |
| `/oauth/authorize` | GET, POST | User authorization and consent |
| `/oauth/token` | POST | Token exchange and client-credentials tokens |
| `/oauth/revoke` | POST | OAuth token revocation |
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/oauth/jwks` | GET | RS256 public signing key set |
| `/oauth/userinfo` | GET | OIDC UserInfo claims |
| `/users/me` | GET | Example user resource; requires `user:read` |
| `/clients/me` | GET | Example machine resource; requires `machine:read` |

## OAuth 2.0 authorization-code flow

Register a client with:

- grant types: `authorization_code` and, if needed, `refresh_token`
- response type: `code`
- scope: `user:read` (and OIDC scopes when applicable)
- an exact HTTPS callback URL

Generate a PKCE verifier and S256 challenge, then send the user to the authorization endpoint. The user must be signed into this example server and approve the consent page.

```text
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&
  scope=user%3Aread&
  state=opaque-client-state&
  code_challenge=BASE64URL_SHA256_VERIFIER&
  code_challenge_method=S256
```

The server redirects to the registered URI with `code` and the unchanged `state`. Exchange the code using client authentication and the original verifier:

```bash
curl --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode code="$CODE" \
  --data-urlencode redirect_uri="https://client.example/callback" \
  --data-urlencode code_verifier="$CODE_VERIFIER" \
  http://127.0.0.1:8000/oauth/token
```

Authorization codes are single-use, bound to the client, exact redirect URI, and verifier, and expire shortly after issuance.

## OpenID Connect

OIDC uses the authorization-code flow above. Register `openid` in the client's permitted scopes, include `openid` in the authorization request, and supply exactly one `nonce`:

```text
scope=openid%20profile&nonce=random-rp-nonce
```

The token response includes an `id_token` signed with RS256. Relying parties should:

1. Fetch discovery from `/.well-known/openid-configuration`.
2. Fetch the signing key from `jwks_uri` and select the key matching the JWT `kid`.
3. Verify RS256 signature, `iss`, `aud`, `exp`, `iat`, and the original `nonce`.

The ID Token always contains `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, and `jti`. When `profile` is granted, it also contains `preferred_username`.

Call UserInfo with the OAuth access token, not an ID or refresh token:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/oauth/userinfo
```

UserInfo requires the `openid` scope. It returns `sub` and adds `preferred_username` when `profile` is present.

## Client credentials

Register a client with grant type `client_credentials` and scope `machine:read`, then request a machine token:

```bash
curl --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode scope=machine:read \
  http://127.0.0.1:8000/oauth/token
```

Use the resulting access token with the machine resource:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/clients/me
```

Machine tokens cannot access `/users/me` or `/oauth/userinfo`.

## Refresh and revocation

Clients registered for `refresh_token` receive a refresh token from the authorization-code exchange. Refreshing returns a replacement refresh token and invalidates the predecessor:

```bash
curl --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode refresh_token="$REFRESH_TOKEN" \
  http://127.0.0.1:8000/oauth/token
```

Revoke a token with the owning client credentials:

```bash
curl --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode token="$REFRESH_TOKEN" \
  --data-urlencode token_type_hint=refresh_token \
  http://127.0.0.1:8000/oauth/revoke
```

## Testing

The suite drives the public HTML registration and consent flow, then treats the server as an HTTP black box:

```bash
uv run pytest .
```

It covers authorization-code binding and replay, PKCE, redirect URI matching, OAuth parameter safety, client authentication, refresh/revocation, machine access, and the OIDC discovery, nonce, ID Token, JWKS, and UserInfo contracts.

## Production notes

This repository intentionally omits many concerns required for a real authorization server: hardened user authentication and password storage, CSRF protections around account management, consent persistence, audit logging, key rotation, migrations, rate limiting, secure cookie deployment settings, monitoring, and operational key management. Treat it as a learning and test fixture rather than an identity service to deploy.
