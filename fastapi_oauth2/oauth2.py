import collections
import datetime
import time
import typing as t
import uuid

import anyio.from_thread
import jwt
import sqlalchemy as sa
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer, JsonRequest, OAuth2Error, OAuth2Request
from authlib.oauth2.rfc6749 import JsonPayload, OAuth2Payload, grants
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from fastapi import Request, Response
from fastapi.datastructures import FormData, Headers, QueryParams
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, scoped_session

from fastapi_oauth2.models import OAuth2AuthorizationCode, OAuth2Client, OAuth2Token, User
from fastapi_oauth2.oidc import create_id_token
from fastapi_oauth2.settings import Settings


class FastAPIOAuth2Payload(OAuth2Payload):
    _request: Request

    def __init__(self, request: Request) -> None:
        anyio.from_thread.run(self.from_request, request)

    async def from_request(self, request: Request) -> None:
        form = await request.form()

        values = collections.defaultdict(list)

        # Query params
        for key, value in request.query_params.multi_items():
            values[key].append(value)

        # Form params
        for key, value in form.multi_items():
            values[key].append(value)

        self._request = request
        self._datalist = values
        self._data = {key: items[0] if items else None for key, items in values.items()}

    @property
    def data(self) -> dict:
        return self._data

    @property
    def datalist(self) -> dict:
        return self._datalist


class FastAPIOAuth2Request(OAuth2Request):
    _request: Request
    payload: FastAPIOAuth2Payload

    def __init__(self, request: Request) -> None:
        super().__init__(method=request.method, uri=str(request.url), headers=request.headers)
        self._request = request
        self.payload = FastAPIOAuth2Payload(request)

    @property
    def args(self) -> QueryParams:
        return self._request.query_params

    @property
    def form(self) -> FormData:
        return anyio.from_thread.run(self._request.form)


class FastAPIJsonPayload(JsonPayload):
    _request: Request

    def __init__(self, request: Request) -> None:
        self._request = request

    @property
    def data(self) -> t.Any:  # noqa: ANN401
        return anyio.from_thread.run(self._request.json)


class FastAPIJsonRequest(JsonRequest):
    def __init__(self, request: Request) -> None:
        super().__init__(request.method, str(request.url), request.headers)
        self.payload = FastAPIJsonPayload(request)


class Generators:
    @staticmethod
    def access_token_generator(client: OAuth2Client, grant_type: str, user: User | None, scope: str) -> str:
        settings = Settings()

        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        payload = {
            "jti": str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + datetime.timedelta(seconds=Generators.expires_generator(client, grant_type)),
            "aud": [client.client_id],
            "scope": scope,
            "type": "access_token",
            "client_id": client.client_id,
        }
        if user is not None:
            payload["sub"] = str(user.id)
        return jwt.encode(payload, settings.secret_key, algorithm="HS256")

    @staticmethod
    def refresh_token_generator(client: OAuth2Client, grant_type: str, user: User | None, scope: str) -> str:
        if user is None:
            raise ValueError("Refresh tokens require a resource owner")
        settings = Settings()

        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        payload = {
            "jti": str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "sub": str(user.id),
            "exp": now + datetime.timedelta(seconds=Generators.expires_generator(client, grant_type)),
            "aud": [client.client_id],
            "scope": scope,
            "type": "refresh_token",
        }
        return jwt.encode(payload, settings.secret_key, algorithm="HS256")

    @staticmethod
    def expires_generator(client: OAuth2Client, grant_type: str) -> int:
        return BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)


class AuthorizationServer(_AuthorizationServer):
    session: scoped_session[Session]

    def __init__(
        self,
        *,
        scopes_supported: t.Sequence[str] | None = None,
        query_client: t.Callable[[str], OAuth2Client | None],
        save_token: t.Callable[[dict[str, t.Any], OAuth2Request], None],
        session: scoped_session[Session],
    ) -> None:
        super().__init__(scopes_supported)
        self._query_client = query_client
        self._save_token = save_token
        self.session = session
        self._error_uris = None

        self.register_token_generator(
            "default",
            BearerTokenGenerator(
                Generators.access_token_generator,
                Generators.refresh_token_generator,
                Generators.expires_generator,
            ),
        )

    def send_signal(self, name: str, *args, **kwargs) -> None:
        # Signals are not required with FastAPI, ignore.
        return None

    def query_client(self, client_id: str) -> OAuth2Client | None:
        return self._query_client(client_id)

    def save_token(self, token: dict[str, t.Any], request: OAuth2Request) -> None:
        return self._save_token(token, request)

    def get_error_uri(self, request: OAuth2Request, error: OAuth2Error) -> str | None:
        if self._error_uris:
            uris = dict(self._error_uris)
            return uris.get(error.error)
        return None

    def create_oauth2_request(self, request: Request) -> FastAPIOAuth2Request:
        return FastAPIOAuth2Request(request)

    def create_json_request(self, request: Request) -> FastAPIJsonRequest:
        return FastAPIJsonRequest(request)

    def handle_response(self, status: int, body: t.Any, headers: list[tuple[str, str]] | None) -> Response:  # noqa: ANN401
        headers: Headers | None = Headers(dict(headers)) if headers is not None else None
        if isinstance(body, dict):
            return JSONResponse(body, status, headers=headers)
        return Response(body, status, headers=headers)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    server: AuthorizationServer
    request: FastAPIOAuth2Request

    def save_authorization_code(self, code: str, request: FastAPIOAuth2Request) -> OAuth2AuthorizationCode:
        code_challenge = request.payload.data.get("code_challenge")
        code_challenge_method = request.payload.data.get("code_challenge_method")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.payload.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=request.payload.data.get("nonce"),
        )
        self.server.session.add(auth_code)
        self.server.session.commit()
        return auth_code

    def query_authorization_code(self, code: str, client: OAuth2Client) -> OAuth2AuthorizationCode | None:
        auth_code = self.server.session.scalars(
            sa.select(OAuth2AuthorizationCode).filter_by(code=code, client_id=client.client_id).limit(1)
        ).first()
        if auth_code is not None and not auth_code.is_expired():
            return auth_code
        return None

    def delete_authorization_code(self, authorization_code: OAuth2AuthorizationCode) -> None:
        self.server.session.delete(authorization_code)
        self.server.session.commit()

    def authenticate_user(self, authorization_code: OAuth2AuthorizationCode) -> User | None:
        return self.server.session.get(User, authorization_code.user_id)

    def create_token_response(self) -> tuple[int, dict[str, t.Any], list[tuple[str, str]]]:
        authorization_code = self.request.authorization_code
        user = self.authenticate_user(authorization_code)
        status, token, headers = super().create_token_response()
        if "openid" in authorization_code.scope.split() and user is not None:
            token["id_token"] = create_id_token(
                client=self.request.client,
                user=user,
                scope=authorization_code.scope,
                nonce=authorization_code.nonce,
                auth_time=authorization_code.auth_time,
            )
        return status, token, headers


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    server: AuthorizationServer

    def authenticate_user(self, username: str, password: str) -> User | None:
        user = self.server.session.scalars(sa.select(User).filter_by(username=username).limit(1)).first()
        if user is not None and user.check_password(password):
            return user
        return None


class RefreshTokenGrant(grants.RefreshTokenGrant):
    server: AuthorizationServer
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token: str) -> OAuth2Token | None:
        token = self.server.session.scalars(
            sa.select(OAuth2Token).filter_by(refresh_token=refresh_token).limit(1)
        ).first()
        if token and token.is_refresh_token_active():
            return token
        return None

    def authenticate_user(self, refresh_token: OAuth2Token) -> User | None:
        return self.server.session.get(User, refresh_token.user_id)

    def revoke_old_credential(self, refresh_token: OAuth2Token) -> None:
        refresh_token.refresh_token_revoked_at = int(time.time())
        self.server.session.add(refresh_token)
        self.server.session.commit()
