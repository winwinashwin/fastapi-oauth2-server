import typing as t

import sqlalchemy as sa
from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.schema import CreateTable
from sqlalchemy.sql.compiler import DDLCompiler


def get_autoincrement_col(table: sa.Table) -> sa.Column[t.Any] | None:
    autoincrement_cols: list[sa.Column[t.Any]] = []
    for col in table.primary_key.columns:
        # autoincrement='auto' is True only when 1 PK is present AND integer type
        is_autoincrement = (
            col.table.primary_key.columns == {col} and isinstance(col.type, (sa.Integer, sa.BigInteger))
            if col.autoincrement == "auto"
            else col.autoincrement
        )
        if is_autoincrement:
            autoincrement_cols.append(col)
    if len(autoincrement_cols) == 0:
        return None
    if len(autoincrement_cols) > 1:
        raise AssertionError(
            f"Expected only 1 autoincrement column. Got: {len(autoincrement_cols)} columns in {table.name}"
        )
    return autoincrement_cols[0]


class Base(DeclarativeBase):
    pass


class BaseModel(Base):
    __abstract__ = True

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)


class User(BaseModel):
    __tablename__ = "user"

    username: Mapped[str] = mapped_column(sa.String(40), unique=True)

    def __str__(self) -> str:
        return self.username

    def get_user_id(self) -> int:
        return self.id

    def check_password(self, password: str) -> bool:
        return password == "valid"  # noqa: S105 -- This is a dummy example


class OAuth2Client(BaseModel, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    client_secret: Mapped[str]

    user_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("user.id", ondelete="CASCADE"))
    user: Mapped[User] = relationship("User")


class OAuth2AuthorizationCode(BaseModel, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    scope: Mapped[str]
    nonce: Mapped[str]
    auth_time: Mapped[int]

    user_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("user.id", ondelete="CASCADE"))
    user: Mapped[User] = relationship("User")


class OAuth2Token(BaseModel, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    refresh_token_revoked_at: Mapped[int]

    user_id: Mapped[int] = mapped_column(sa.Integer, sa.ForeignKey("user.id", ondelete="CASCADE"))
    user: Mapped[User] = relationship("User")

    def is_refresh_token_active(self) -> bool:
        return not self.is_revoked() and not self.is_expired()


@compiles(CreateTable)
def compile_create_table(element: CreateTable, compiler: DDLCompiler) -> str:
    """Add AUTOINCREMENT to primary key in sqlite.

    By default primary_key in sqlite does not use autoincrement.
    https://www.sqlite.org/autoinc.html
    sqlite_autoincrement has to be explicitly added for a table to treat it as autoincrement
    https://docs.sqlalchemy.org/en/14/dialects/sqlite.html
    We use this compile hook to convert the SQL to add autoincremen to primary key constraint.
    """
    text = t.cast("str", compiler.visit_create_table(element))
    table = element.element
    autoincrement_col = get_autoincrement_col(table)

    if compiler.dialect.name == "sqlite" and autoincrement_col is not None:
        text = text.replace(
            f"PRIMARY KEY ({autoincrement_col.key})",
            f"PRIMARY KEY ({autoincrement_col.key} AUTOINCREMENT)",
        )

    return text
