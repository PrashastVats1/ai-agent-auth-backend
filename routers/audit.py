from fastapi import APIRouter, Depends, Query
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import AuditLogOut
from models.tables import AuditLog, User
from services.monocloud import validate_monocloud_jwt
from fastapi import HTTPException

router = APIRouter(prefix="/api/audit", tags=["audit"])
bearer = HTTPBearer()


def _get_current_user(token=Depends(bearer), db: Session = Depends(get_db)) -> User:
    try:
        claims = validate_monocloud_jwt(token.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    user = db.query(User).filter(User.monocloud_user_id == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    """Returns audit log entries for agents owned by the current user, newest first."""
    from models.tables import Agent
    owned_agent_ids = [a.id for a in db.query(Agent).filter(Agent.owner_id == user.id).all()]
    return (
        db.query(AuditLog)
        .filter(AuditLog.agent_id.in_(owned_agent_ids))
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
