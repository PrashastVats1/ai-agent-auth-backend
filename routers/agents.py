from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import AgentCreate, AgentOut
from models.tables import Agent, User
from services.monocloud import validate_monocloud_jwt

router = APIRouter(prefix="/api/agents", tags=["agents"])
bearer = HTTPBearer()


def _get_current_user(token=Depends(bearer), db: Session = Depends(get_db)) -> User:
    try:
        claims = validate_monocloud_jwt(token.credentials)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    user = db.query(User).filter(User.monocloud_user_id == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — call /api/users/sync first")
    return user


@router.get("", response_model=list[AgentOut])
def list_agents(user: User = Depends(_get_current_user), db: Session = Depends(get_db)):
    return db.query(Agent).filter(Agent.owner_id == user.id).all()


@router.post("", response_model=AgentOut, status_code=201)
def create_agent(
    body: AgentCreate,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(Agent).filter(Agent.monocloud_client_id == body.monocloud_client_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Agent with this client ID already exists")
    agent = Agent(name=body.name, monocloud_client_id=body.monocloud_client_id, owner_id=user.id)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


@router.delete("/{agent_id}", status_code=204)
def delete_agent(
    agent_id: str,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.owner_id == user.id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    db.delete(agent)
    db.commit()
