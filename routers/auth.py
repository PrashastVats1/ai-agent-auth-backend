from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import AgentTokenRequest, AgentTokenResponse
from models.tables import Agent, User
from services.monocloud import validate_monocloud_jwt
from services.delegation import issue_agent_jwt, EXPIRY_MINUTES

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/agent-token", response_model=AgentTokenResponse)
def get_agent_token(body: AgentTokenRequest, db: Session = Depends(get_db)):
    """Exchange a MonoCloud user JWT + agent client ID for a delegation JWT.

    The returned token encodes both the user identity and the agent identity.
    It is signed with JWT_SECRET and must be validated with validate_agent_jwt(),
    never against MonoCloud's JWKS.
    """
    # Step 1: validate the human user's MonoCloud JWT
    try:
        user_claims = validate_monocloud_jwt(body.monocloud_user_jwt)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    monocloud_user_id = user_claims.get("sub")
    if not monocloud_user_id:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    # Step 2: look up the user in our database (they must have synced first)
    user = db.query(User).filter(User.monocloud_user_id == monocloud_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — call /api/users/sync first")

    # Step 3: look up the agent by its MonoCloud M2M client ID
    agent = db.query(Agent).filter(Agent.monocloud_client_id == body.monocloud_client_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Step 4: issue the delegation JWT
    token = issue_agent_jwt(
        user_id=str(user.id),
        user_email=user.email,
        agent_id=str(agent.id),
        agent_name=agent.name,
        scopes=["read"],  # default scope; consent flow gates destructive scopes
    )

    return AgentTokenResponse(
        agent_delegation_jwt=token,
        expires_in=EXPIRY_MINUTES * 60,
    )
