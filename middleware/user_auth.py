from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models.tables import User
from services.monocloud import validate_monocloud_jwt

bearer = HTTPBearer()


def get_current_user(token=Depends(bearer), db: Session = Depends(get_db)) -> User:
    """Resolve the signed-in dashboard user from their MonoCloud JWT.

    The identity is the token's `sub` claim, never anything from the request body.
    This is for MonoCloud tokens only; agents authenticate with delegation JWTs
    via middleware/policy_check.py.
    """
    try:
        claims = validate_monocloud_jwt(token.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    user = db.query(User).filter(User.monocloud_user_id == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — call /api/users/sync first")
    return user
