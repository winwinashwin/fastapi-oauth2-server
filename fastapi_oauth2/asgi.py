import typing as t

import anyio.to_thread
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from fastapi_oauth2.dependencies.db_session import SQLAlchemy
from fastapi_oauth2.models import Base
from fastapi_oauth2.routes import router
from fastapi_oauth2.settings import Settings


class DBSessionMiddleware:
    """Keep the SQLAlchemy context alive for the complete ASGI request.

    A pure ASGI middleware avoids the task/context split introduced by
    ``BaseHTTPMiddleware`` and works with both a real server and ASGI test
    transports.
    """

    def __init__(self, app: t.Callable[..., t.Any]) -> None:
        self.app = app

    async def __call__(
        self, scope: dict[str, t.Any], receive: t.Callable[..., t.Any], send: t.Callable[..., t.Any]
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        with SQLAlchemy.scoped_context():
            try:
                await self.app(scope, receive, send)
            finally:
                await anyio.to_thread.run_sync(SQLAlchemy.session.remove)


def create_app() -> FastAPI:
    settings = Settings()
    SQLAlchemy.init(settings)
    if SQLAlchemy.engine is None:
        raise RuntimeError("Unable to initialize SQLAlchemy")
    Base.metadata.create_all(SQLAlchemy.engine)

    app = FastAPI(title="FastAPI OAuth2 Server")
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)
    app.add_middleware(DBSessionMiddleware)
    app.include_router(router)
    return app
