import typing as t

from authlib.oauth2.rfc6750 import BearerTokenGenerator
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    secret_key: str  # User for both user sessions and jwt

    # DB
    sqlalchemy_database_uri: str

    # OAuth 2.0
    grant_types_expiry_conf: t.Annotated[
        dict[str, int],
        Field(
            default_factory=lambda: {
                **BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN,
                "authorization_code": 24 * 60 * 60,  # 24 hours, default is 10 days
            }
        ),
    ]
    refresh_token_expires_in: int = 10 * 24 * 60 * 60  # 10 days

    # OIDC
    oidc_issuer: str
    oidc_private_key_pem: str
    oidc_key_id: str
