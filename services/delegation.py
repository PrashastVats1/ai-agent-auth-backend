import os
import jwt
import datetime

JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
EXPIRY_MINUTES = 30


def issue_agent_jwt(
    user_id: str,
    user_email: str,
    agent_id: str,
    agent_name: str,
    scopes: list[str],
) -> str:
    """Issue a short-lived agent delegation JWT signed with JWT_SECRET.

    This token is NOT issued by MonoCloud and must NOT be validated against
    MonoCloud's JWKS. Use validate_agent_jwt() to verify it.
    """
    now = datetime.datetime.utcnow()
    payload = {
        "user_id": user_id,
        "user_email": user_email,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "scopes": scopes,
        "token_type": "agent_delegation",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def validate_agent_jwt(token: str) -> dict:
    """Validate the custom agent delegation JWT issued by this backend.

    Do NOT use this for MonoCloud-issued tokens — use validate_monocloud_jwt()
    in services/monocloud.py for those.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise ValueError("Agent token expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid agent token: {e}")
