from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    secret_key: str  # User for both user sessions and jwt

    # DB
    sqlalchemy_database_uri: str

    # OIDC
    oidc_issuer: str
    oidc_private_key_pem: str
    oidc_key_id: str
