import logging
import secrets
import time
import typing as t

import anyio.from_thread
import sqlalchemy as sa
from authlib.oauth2 import OAuth2Error
from fastapi import APIRouter, Form, HTTPException, Request, Response, Security, status
from fastapi.datastructures import URL
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from fastapi_oauth2.dependencies.current_user import CurrentUserDep
from fastapi_oauth2.dependencies.db_session import DBSessionDep
from fastapi_oauth2.dependencies.oauth2 import OAuth2ServerDep, TokenClaimsDep, require_scopes
from fastapi_oauth2.models import OAuth2Client, User
from fastapi_oauth2.oidc import jwks
from fastapi_oauth2.settings import Settings


logger = logging.getLogger(__name__)
router = APIRouter()


templates = Jinja2Templates(directory="fastapi_oauth2/templates")


@router.post("/")
def create_homepage_for_user(request: Request, session: DBSessionDep) -> RedirectResponse:
    form_data = anyio.from_thread.run(request.form)
    username = form_data.get("username")
    user = session.scalars(sa.select(User).filter_by(username=username).limit(1)).first()
    if not user:
        user = User(username=username)
        session.add(user)
        session.commit()
    request.session["id"] = user.id
    # if user is not just to log in, but need to head back to the auth page, then go for it
    next_page = request.query_params.get("next")
    if next_page:
        return RedirectResponse(next_page, status_code=status.HTTP_302_FOUND)
    return RedirectResponse("/", status_code=status.HTTP_302_FOUND)


@router.get("/")
def home(request: Request, session: DBSessionDep, user: CurrentUserDep) -> HTMLResponse:
    clients = session.scalars(sa.select(OAuth2Client).filter_by(user_id=user.id)).all() if user else []
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"user": user, "clients": clients},
    )


@router.get("/logout")
@router.post("/logout")
def logout(request: Request) -> RedirectResponse:
    del request.session["id"]
    return RedirectResponse("/", status_code=status.HTTP_302_FOUND)


@router.get("/create_client")
def create_client_form(request: Request, user: CurrentUserDep) -> Response:
    if not user:
        return RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="create_client.html")


class CreateClientForm(BaseModel):
    client_name: str
    client_uri: str
    grant_type: str
    redirect_uri: str
    response_type: str
    token_endpoint_auth_method: t.Literal["none", "client_secret_basic", "client_secret_post"]
    scope: str


def split_by_crlf(s: str) -> list[str]:
    return [v for v in s.splitlines() if v]


@router.post("/create_client")
def create_client(
    request: Request,
    user: CurrentUserDep,
    session: DBSessionDep,
    form_data: t.Annotated[CreateClientForm, Form()],
) -> Response:

    if not user:
        return RedirectResponse("/", status_code=status.HTTP_302_FOUND)

    client_id = secrets.token_urlsafe(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )
    client_metadata = {
        "client_name": form_data.client_name,
        "client_uri": form_data.client_uri,
        "grant_types": split_by_crlf(form_data.grant_type),
        "redirect_uris": split_by_crlf(form_data.redirect_uri),
        "response_types": split_by_crlf(form_data.response_type),
        "scope": form_data.scope,
        "token_endpoint_auth_method": form_data.token_endpoint_auth_method,
    }
    client.set_client_metadata(client_metadata)

    if form_data.token_endpoint_auth_method == "none":  # noqa: S105
        client.client_secret = ""
    else:
        client.client_secret = secrets.token_urlsafe(48)

    session.add(client)
    session.commit()
    return RedirectResponse("/", status_code=status.HTTP_302_FOUND)


@router.get("/oauth/authorize")
@router.post("/oauth/authorize")
def authorize(
    request: Request,
    user: CurrentUserDep,
    session: DBSessionDep,
    oauth2_server: OAuth2ServerDep,
) -> Response:
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return RedirectResponse(URL("/").replace_query_params(next=str(request.url)), status_code=status.HTTP_302_FOUND)
    if request.method == "GET":
        try:
            grant = oauth2_server.get_consent_grant(request=request, end_user=user)
        except OAuth2Error as error:
            return oauth2_server.handle_error_response(request, error)

        return templates.TemplateResponse(
            request=request, name="authorize.html", context={"user": user, "grant": grant}
        )

    form_data = anyio.from_thread.run(request.form)
    if not user and "username" in form_data:
        username = form_data["username"]
        user = session.scalars(sa.select(User).filter_by(username=username).limit(1)).first()

    grant = oauth2_server.get_authorization_grant(oauth2_server.create_oauth2_request(request))
    grant_user = user if form_data["confirm"] else None
    return oauth2_server.create_authorization_response(request=request, grant=grant, grant_user=grant_user)


@router.post("/oauth/token")
def issue_token(request: Request, oauth2_server: OAuth2ServerDep) -> Response:
    return oauth2_server.create_token_response(request=request)


@router.post("/oauth/revoke")
def revoke_token(request: Request, oauth2_server: OAuth2ServerDep) -> Response:
    return oauth2_server.create_endpoint_response("revocation", request=request)


@router.get("/.well-known/openid-configuration")
def openid_configuration() -> dict[str, t.Any]:
    issuer = Settings().oidc_issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/oauth/jwks",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "user:read", "machine:read"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
    }


@router.get("/oauth/jwks")
def openid_jwks() -> dict[str, list[dict[str, str]]]:
    return jwks(Settings())


@router.get(
    "/whoami",
    dependencies=[
        Security(require_scopes, scopes=["user:read"]),
    ],
)
def whoami(claims: TokenClaimsDep, session: DBSessionDep) -> dict[str, t.Any]:
    if claims.type != "access_token" or claims.sub is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Machine tokens cannot access user resources")
    user = session.get(User, int(claims.sub))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    return {"id": user.id, "username": user.username}


@router.get(
    "/machine/whoami",
    dependencies=[Security(require_scopes, scopes=["machine:read"])],
)
def machine_whoami(claims: TokenClaimsDep) -> dict[str, str]:
    if claims.type != "access_token" or claims.sub is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User tokens cannot access machine resources")
    return {"client_id": claims.client_id}


@router.get(
    "/oauth/userinfo",
    dependencies=[Security(require_scopes, scopes=["openid"])],
)
def userinfo(claims: TokenClaimsDep, session: DBSessionDep) -> dict[str, str]:
    if claims.type != "access_token" or claims.sub is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "An OpenID Connect access token is required")
    user = session.get(User, int(claims.sub))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown subject")
    result = {"sub": str(user.id)}
    if "profile" in claims.scope.split():
        result["preferred_username"] = user.username
    return result
