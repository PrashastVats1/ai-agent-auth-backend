from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer

from database import get_db
from models.tables import Policy, AuditLog
from services.delegation import validate_agent_jwt

bearer = HTTPBearer()
IST = ZoneInfo("Asia/Kolkata")


def _log(db, claims: dict, endpoint: str, method: str, action: str, consent_required=False, consent_given=None):
    db.add(AuditLog(
        agent_id=claims.get("agent_id"),
        user_id=claims.get("user_id"),
        endpoint=endpoint,
        method=method,
        action=action,
        consent_required=consent_required,
        consent_given=consent_given,
    ))
    db.commit()


def enforce_policy(request: Request, token=Depends(bearer), db=Depends(get_db)) -> dict:
    """FastAPI dependency that validates the agent delegation JWT and enforces
    per-agent policy rules. Attach with Depends(enforce_policy).

    Returns the validated claims dict so downstream routes can read user_id,
    agent_id, scopes, etc. without re-decoding the token.
    """
    try:
        claims = validate_agent_jwt(token.credentials)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired agent token")

    agent_id = claims["agent_id"]
    method = request.method
    endpoint = request.url.path

    policy = db.query(Policy).filter(Policy.agent_id == agent_id).first()
    if not policy:
        # No policy configured — allow but log.
        _log(db, claims, endpoint, method, "allowed_no_policy")
        return claims

    if policy.allowed_endpoints and endpoint not in policy.allowed_endpoints:
        _log(db, claims, endpoint, method, "rejected_endpoint")
        raise HTTPException(status_code=403, detail="Endpoint not permitted by agent policy")

    if policy.allowed_methods and method not in policy.allowed_methods:
        _log(db, claims, endpoint, method, "rejected_method")
        raise HTTPException(status_code=403, detail="Method not permitted by agent policy")

    if policy.time_window_start and policy.time_window_end:
        now_ist = datetime.now(IST).time()
        if not (policy.time_window_start <= now_ist <= policy.time_window_end):
            _log(db, claims, endpoint, method, "rejected_time_window")
            raise HTTPException(status_code=403, detail="Request outside allowed time window")

    if policy.allowed_days:
        day_name = datetime.now(IST).strftime("%A").lower()
        if day_name not in [d.lower() for d in policy.allowed_days]:
            _log(db, claims, endpoint, method, "rejected_day")
            raise HTTPException(status_code=403, detail="Request on disallowed day")

    _log(db, claims, endpoint, method, "allowed")
    return claims
