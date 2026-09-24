import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from middleware.user_auth import get_current_user
from models.schemas import ConsentRequestCreate, ConsentStatusOut, ConsentApprove
from models.tables import Agent, ConsentRequest, User
from services.audit import add_audit_log
from services.monocloud import client_id_from_monocloud_claims, validate_monocloud_jwt
from services.consent import expire_stale_consents, is_destructive_scope

router = APIRouter(prefix="/consent", tags=["consent"])
bearer = HTTPBearer()  # for the agent M2M token on GET /consent/status/{id}


@router.post("/request", response_model=ConsentStatusOut, status_code=201)
def request_consent(
    body: ConsentRequestCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Agent calls this to create a pending consent record for a destructive scope."""
    if not is_destructive_scope(body.scope):
        raise HTTPException(status_code=400, detail="Consent is only required for destructive scopes (delete:, write:, admin:)")

    agent = db.query(Agent).filter(
        Agent.monocloud_client_id == body.monocloud_client_id,
        Agent.owner_id == user.id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    consent = ConsentRequest(
        agent_id=agent.id,
        user_id=user.id,
        scope=body.scope,
    )
    db.add(consent)
    add_audit_log(
        db, agent_id=agent.id, user_id=user.id, endpoint="/consent/request", method="POST",
        action="consent_requested", consent_required=True,
    )
    db.commit()
    db.refresh(consent)
    return consent


@router.get("/status/{consent_id}", response_model=ConsentStatusOut)
def get_consent_status(consent_id: uuid.UUID, agent_m2m_token=Depends(bearer), db: Session = Depends(get_db)):
    """Agent polls this every 4 seconds. Stale pending records are expired inline.

    The caller must present the agent's own MonoCloud M2M token, and it must
    belong to the agent the consent was requested for.
    """
    try:
        agent_claims = validate_monocloud_jwt(agent_m2m_token.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    agent_client_id = client_id_from_monocloud_claims(agent_claims)

    expire_stale_consents(db)

    # Someone else's consent gets the same 404 as a nonexistent one.
    consent = (
        db.query(ConsentRequest)
        .join(Agent, ConsentRequest.agent_id == Agent.id)
        .filter(ConsentRequest.id == consent_id, Agent.monocloud_client_id == agent_client_id)
        .first()
    )
    if not consent:
        raise HTTPException(status_code=404, detail="Consent request not found")

    if consent.status == "expired":
        raise HTTPException(status_code=410, detail="Consent request expired")

    return consent


@router.get("/pending", response_model=list[ConsentStatusOut])
def list_pending(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Dashboard polls this every 4 seconds to show the user what needs approval."""
    expire_stale_consents(db)
    return (
        db.query(ConsentRequest)
        .filter(ConsentRequest.user_id == user.id, ConsentRequest.status == "pending")
        .order_by(ConsentRequest.created_at.desc())
        .all()
    )


@router.post("/approve")
def approve_consent(
    body: ConsentApprove,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """User approves or denies a pending consent request from the dashboard."""
    expire_stale_consents(db)

    consent = db.query(ConsentRequest).filter(
        ConsentRequest.id == body.consent_id,
        ConsentRequest.user_id == user.id,
    ).first()
    if not consent:
        raise HTTPException(status_code=404, detail="Consent request not found")
    if consent.status != "pending":
        raise HTTPException(status_code=409, detail=f"Consent already {consent.status}")

    consent.status = "approved" if body.approved else "denied"
    consent.resolved_at = datetime.now(timezone.utc)
    add_audit_log(
        db, agent_id=consent.agent_id, user_id=user.id, endpoint="/consent/approve", method="POST",
        action="consent_approved" if body.approved else "consent_denied",
        consent_required=True, consent_given=body.approved,
    )
    db.commit()

    return {"status": consent.status}
