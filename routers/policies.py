from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models.schemas import PolicyCreate, PolicyOut
from models.tables import Agent, Policy, User
from services.monocloud import validate_monocloud_jwt

router = APIRouter(prefix="/api/policies", tags=["policies"])
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


def _owned_agent(agent_id: str, user: User, db: Session) -> Agent:
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.owner_id == user.id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/{agent_id}", response_model=PolicyOut)
def get_policy(
    agent_id: str,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    agent = _owned_agent(agent_id, user, db)
    policy = db.query(Policy).filter(Policy.agent_id == agent.id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="No policy set for this agent")
    return policy


@router.put("/{agent_id}", response_model=PolicyOut)
def upsert_policy(
    agent_id: str,
    body: PolicyCreate,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    agent = _owned_agent(agent_id, user, db)
    policy = db.query(Policy).filter(Policy.agent_id == agent.id).first()
    if policy:
        policy.allowed_endpoints = body.allowed_endpoints
        policy.allowed_methods = body.allowed_methods
        policy.time_window_start = body.time_window_start
        policy.time_window_end = body.time_window_end
        policy.allowed_days = body.allowed_days
    else:
        policy = Policy(
            agent_id=agent.id,
            allowed_endpoints=body.allowed_endpoints,
            allowed_methods=body.allowed_methods,
            time_window_start=body.time_window_start,
            time_window_end=body.time_window_end,
            allowed_days=body.allowed_days,
        )
        db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{agent_id}", status_code=204)
def delete_policy(
    agent_id: str,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    agent = _owned_agent(agent_id, user, db)
    policy = db.query(Policy).filter(Policy.agent_id == agent.id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="No policy to delete")
    db.delete(policy)
    db.commit()
