from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import UserSync, UserOut
from models.tables import User
from services.monocloud import validate_monocloud_jwt
from fastapi.security import HTTPBearer

router = APIRouter(prefix="/api/users", tags=["users"])
bearer = HTTPBearer()


@router.post("/sync", response_model=UserOut)
def sync_user(token=Depends(bearer), db: Session = Depends(get_db)):
    """Create or return the user row for the authenticated MonoCloud user.

    Called once after login to ensure the user exists in Neon.
    User identity comes from the validated token — never from the request body.
    """
    try:
        claims = validate_monocloud_jwt(token.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    monocloud_user_id = claims["sub"]

    user = db.query(User).filter(User.monocloud_user_id == monocloud_user_id).first()
    if not user:
        email = claims.get("email")
        if not email:
            raise HTTPException(
                status_code=400,
                detail="Token has no email claim — the app must request the 'email' scope",
            )
        user = User(monocloud_user_id=monocloud_user_id, email=email)
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="A user with this email already exists")
        db.refresh(user)

    return user
