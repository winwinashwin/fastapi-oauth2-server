import typing as t

from fastapi import Depends, Request

from fastapi_oauth2.dependencies.db_session import DBSessionDep
from fastapi_oauth2.models import User


def _get_current_user(request: Request, session: DBSessionDep) -> User | None:
    if "id" in request.session:
        return session.get(User, request.session["id"])
    return None


CurrentUserDep = t.Annotated[User | None, Depends(_get_current_user)]
