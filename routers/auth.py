from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import AgentTokenRequest, AgentTokenResponse
from models.tables import Agent, User
from services.consent import redeem_consent
from services.monocloud import validate_monocloud_jwt
from services.delegation import issue_agent_jwt, EXPIRY_MINUTES

router = APIRouter(prefix="/auth", tags=["auth"])

DEFAULT_SCOPES = ["read"]


@router.post("/agent-token", response_model=AgentTokenResponse)
def get_agent_token(body: AgentTokenRequest, db: Session = Depends(get_db)):
    """Exchange a MonoCloud user JWT + the agent's MonoCloud M2M JWT for a delegation JWT.

    The returned token encodes both the user identity and the agent identity.
    It is signed with JWT_SECRET and must be validated with validate_agent_jwt(),
    never against MonoCloud's JWKS.

    The token carries only the "read" scope unless the caller redeems an approved
    consent (consent_id), in which case that consent's scope is added. Each
    approval can be redeemed once.
    """
    # Step 1: validate the human user's MonoCloud JWT
    try:
        user_claims = validate_monocloud_jwt(body.monocloud_user_jwt)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    monocloud_user_id = user_claims.get("sub")
    if not monocloud_user_id:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    # Step 2: validate the agent's own MonoCloud M2M JWT. This proves the caller
    # holds the agent's credentials, not just its (public) client ID.
    try:
        agent_claims = validate_monocloud_jwt(body.monocloud_agent_jwt)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Agent token rejected: {e}")

    token_client_id = agent_claims.get("client_id") or agent_claims.get("azp")
    if token_client_id != body.monocloud_client_id:
        raise HTTPException(status_code=401, detail="Agent token was not issued to this client ID")

    # Step 3: look up the user in our database (they must have synced first)
    user = db.query(User).filter(User.monocloud_user_id == monocloud_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — call /api/users/sync first")

    # Step 4: the agent must exist AND belong to this user. A missing agent and
    # someone else's agent get the same response so client IDs can't be probed.
    agent = db.query(Agent).filter(
        Agent.monocloud_client_id == body.monocloud_client_id,
        Agent.owner_id == user.id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Step 5: optionally redeem an approved consent for a destructive scope
    scopes = list(DEFAULT_SCOPES)
    if body.consent_id is not None:
        consented_scope = redeem_consent(db, body.consent_id, user.id, agent.id)
        if consented_scope is None:
            raise HTTPException(status_code=403, detail="Consent is not approved, was already used, or has expired")
        scopes.append(consented_scope)

    # Step 6: issue the delegation JWT, then commit so the redemption only sticks if we got this far
    token = issue_agent_jwt(
        user_id=str(user.id),
        user_email=user.email,
        agent_id=str(agent.id),
        agent_name=agent.name,
        scopes=scopes,
    )
    db.commit()

    return AgentTokenResponse(
        agent_delegation_jwt=token,
        expires_in=EXPIRY_MINUTES * 60,
        scopes=scopes,
    )
