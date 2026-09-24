import os
import requests
from cachetools import TTLCache
from jose import jwt, JWTError

ISSUER = os.getenv("MONOCLOUD_ISSUER_URL")

# Cache JWKS for 10 minutes — avoids a network call on every token validation
# and handles key rotation automatically on cache refresh.
_jwks_cache: TTLCache = TTLCache(maxsize=1, ttl=600)


def _get_monocloud_jwks() -> dict:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    oidc_config = requests.get(
        f"{ISSUER}/.well-known/openid-configuration", timeout=10
    ).json()
    jwks = requests.get(oidc_config["jwks_uri"], timeout=10).json()
    _jwks_cache["jwks"] = jwks
    return jwks


def validate_monocloud_jwt(token: str) -> dict:
    """Validate a JWT issued by MonoCloud (human users or M2M clients).

    Do NOT use this for the custom agent delegation JWT — that is validated
    by validate_agent_jwt() in services/delegation.py.
    """
    try:
        return jwt.decode(
            token,
            _get_monocloud_jwks(),
            algorithms=["RS256"],
            audience=os.getenv("MONOCLOUD_AUDIENCE"),
            issuer=ISSUER,
        )
    except JWTError as e:
        raise ValueError(f"Invalid MonoCloud token: {e}")


def client_id_from_monocloud_claims(claims: dict) -> str | None:
    """The OAuth client a MonoCloud token was issued to (for an agent's M2M token,
    that is the agent's monocloud_client_id)."""
    return claims.get("client_id") or claims.get("azp")
