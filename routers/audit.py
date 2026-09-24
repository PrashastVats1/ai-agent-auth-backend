from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from middleware.user_auth import get_current_user
from models.schemas import AuditLogOut
from models.tables import Agent, AuditLog, User

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns audit log entries for agents owned by the current user, newest first."""
    owned_agent_ids = select(Agent.id).where(Agent.owner_id == user.id)
    return (
        db.query(AuditLog)
        .filter(AuditLog.agent_id.in_(owned_agent_ids))
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
