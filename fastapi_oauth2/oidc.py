import base64
import datetime
import typing as t
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi_oauth2.models import OAuth2Client, User
from fastapi_oauth2.settings import Settings


def _base64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _private_key(settings: Settings) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(settings.oidc_private_key_pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("OIDC_PRIVATE_KEY_PEM must contain an RSA private key")
    return key


def jwks(settings: Settings) -> dict[str, list[dict[str, str]]]:
    public_numbers = _private_key(settings).public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": settings.oidc_key_id,
                "alg": "RS256",
                "n": _base64url_uint(public_numbers.n),
                "e": _base64url_uint(public_numbers.e),
            }
        ]
    }


def create_id_token(*, client: OAuth2Client, user: User, scope: str, nonce: str, auth_time: int) -> str:
    settings = Settings()
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    payload: dict[str, t.Any] = {
        "iss": settings.oidc_issuer,
        "sub": str(user.id),
        "aud": client.client_id,
        "exp": now + datetime.timedelta(seconds=3600),
        "iat": now,
        "auth_time": auth_time,
        "nonce": nonce,
        "jti": str(uuid.uuid4()),
    }
    if "profile" in scope.split():
        payload["preferred_username"] = user.username
    return jwt.encode(
        payload,
        _private_key(settings),
        algorithm="RS256",
        headers={"kid": settings.oidc_key_id, "typ": "JWT"},
    )
