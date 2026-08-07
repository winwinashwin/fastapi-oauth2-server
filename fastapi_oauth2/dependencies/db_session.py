import contextlib
import contextvars
import typing as t
import uuid

from fastapi import Depends
from sqlalchemy import Engine, engine_from_config
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from fastapi_oauth2.settings import Settings


class SQLAlchemy:
    session_context: t.ClassVar = contextvars.ContextVar[str]("session_context")
    factory: t.ClassVar = sessionmaker(autoflush=False, autocommit=False)

    session: t.ClassVar = scoped_session(factory, session_context.get)
    engine: t.ClassVar[Engine | None] = None

    @classmethod
    @contextlib.contextmanager
    def scoped_context(cls) -> t.Generator[None, None, None]:
        session_id = str(uuid.uuid4())
        token = cls.session_context.set(session_id)
        try:
            yield
        finally:
            cls.session_context.reset(token)

    @classmethod
    def init(cls, settings: Settings) -> None:
        if cls.engine is not None:
            return

        cls.engine = engine_from_config({"url": settings.sqlalchemy_database_uri}, prefix="")
        cls.factory.configure(bind=cls.engine)


def _get_db_session() -> scoped_session[Session]:
    return SQLAlchemy.session


DBSessionDep = t.Annotated[scoped_session[Session], Depends(_get_db_session)]
