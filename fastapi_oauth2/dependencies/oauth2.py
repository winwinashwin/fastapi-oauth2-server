import typing as t

import jwt
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_revocation_endpoint,
    create_save_token_func,
)
from authlib.oauth2.rfc6749 import InvalidRequestError, grants
from authlib.oauth2.rfc7636 import CodeChallenge
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from pydantic import BaseModel, ValidationError

from fastapi_oauth2.dependencies.db_session import DBSessionDep
from fastapi_oauth2.models import OAuth2Client, OAuth2Token
from fastapi_oauth2.oauth2 import (
    AuthorizationCodeGrant,
    AuthorizationServer,
    FastAPIOAuth2Request,
    RefreshTokenGrant,
)
from fastapi_oauth2.settings import Settings


class S256CodeChallenge(CodeChallenge):
    """PKCE extension that rejects the insecure `plain` method entirely."""

    DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    SUPPORTED_CODE_CHALLENGE_METHOD = ("S256",)

    def validate_code_challenge(self, grant: AuthorizationCodeGrant, redirect_uri: str) -> None:
        request: FastAPIOAuth2Request = grant.request
        challenge = request.payload.data.get("code_challenge")
        method = request.payload.data.get("code_challenge_method")
        if not challenge or method != self.DEFAULT_CODE_CHALLENGE_METHOD:
            raise InvalidRequestError("Missing 'code_challenge'")
        super().validate_code_challenge(grant, redirect_uri)


class OIDCNonce:
    def __call__(self, grant: AuthorizationCodeGrant) -> None:
        grant.register_hook("after_validate_authorization_request_payload", self.validate_nonce)

    @staticmethod
    def validate_nonce(grant: AuthorizationCodeGrant, redirect_uri: str) -> None:
        request: FastAPIOAuth2Request = grant.request
        if "openid" not in (request.payload.scope or "").split():
            return
        nonces = request.payload.datalist.get("nonce", [])
        if len(nonces) != 1 or not nonces[0] or len(nonces[0]) > 255:
            raise InvalidRequestError("A single nonce is required for OpenID Connect")


def get_oauth_server(session: DBSessionDep) -> AuthorizationServer:
    query_client = create_query_client_func(session, OAuth2Client)
    save_token = create_save_token_func(session, OAuth2Token)
    server = AuthorizationServer(
        scopes_supported=["openid", "profile", "user:read", "machine:read"],
        query_client=query_client,
        save_token=save_token,
        session=session,
    )
    # support all grants
    server.register_grant(AuthorizationCodeGrant, [S256CodeChallenge(required=True), OIDCNonce()])
    server.register_grant(RefreshTokenGrant)
    server.register_grant(grants.ClientCredentialsGrant)
    # server.register_grant(grants.ImplicitGrant) # Used by old browsers/SPAs, generally not recommended
    # server.register_grant(PasswordGrant) # Used by legacy trusted apps, not recommended

    # support revocation
    revocation_cls = create_revocation_endpoint(session, OAuth2Token)
    server.register_endpoint(revocation_cls)

    return server


OAuth2ServerDep = t.Annotated[AuthorizationServer, Depends(get_oauth_server)]


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/oauth/token",
    scopes={
        "openid": "OpenID Connect authentication",
        "profile": "Read basic profile information",
        "user:read": "Read user information",
    },
)


class TokenClaims(BaseModel):
    sub: str | None = None
    client_id: str
    scope: str = ""
    type: str


def get_token_claims(token: t.Annotated[str, Depends(oauth2_scheme)]) -> TokenClaims:
    settings = Settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        return TokenClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid access token")


TokenClaimsDep = t.Annotated[TokenClaims, Depends(get_token_claims)]


def require_scopes(security_scopes: SecurityScopes, claims: TokenClaimsDep) -> None:
    token_scopes = set(claims.scope.split())

    missing = set(security_scopes.scopes) - token_scopes

    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing scopes: {', '.join(sorted(missing))}",
        )
