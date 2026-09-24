from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer

from database import get_db
from models.tables import Policy
from services.audit import add_audit_log
from services.delegation import validate_agent_jwt
from services.policy import REJECTION_MESSAGES, check_request

bearer = HTTPBearer()


def _log(db, claims: dict, endpoint: str, method: str, action: str, consent_required=False, consent_given=None):
    add_audit_log(
        db,
        agent_id=claims.get("agent_id"),
        user_id=claims.get("user_id"),
        endpoint=endpoint,
        method=method,
        action=action,
        consent_required=consent_required,
        consent_given=consent_given,
    )
    db.commit()


def _decode_agent_claims(token) -> dict:
    try:
        return validate_agent_jwt(token.credentials)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired agent token")


def _apply_policy(request: Request, claims: dict, db, consent_required=False, consent_given=None) -> None:
    """Check the agent's policy against this request. Logs every outcome and
    raises 403 on a violation. An agent with no policy is denied."""
    endpoint = request.url.path
    method = request.method

    policy = db.query(Policy).filter(Policy.agent_id == claims["agent_id"]).first()
    rejection = check_request(policy, endpoint, method)

    _log(db, claims, endpoint, method, rejection or "allowed", consent_required, consent_given)
    if rejection:
        raise HTTPException(status_code=403, detail=REJECTION_MESSAGES[rejection])


def enforce_policy(request: Request, token=Depends(bearer), db=Depends(get_db)) -> dict:
    """FastAPI dependency that validates the agent delegation JWT and enforces
    per-agent policy rules. Attach with Depends(enforce_policy).

    Returns the validated claims dict so downstream routes can read user_id,
    agent_id, scopes, etc. without re-decoding the token.
    """
    claims = _decode_agent_claims(token)
    _apply_policy(request, claims, db)
    return claims


def require_scope(required_scope: str):
    """Like enforce_policy, but the delegation JWT must also carry `required_scope`.

    Destructive scopes only end up in a token after the user approved a consent
    request, so this is what makes that approval binding. Use as
    Depends(require_scope("delete:orders")).
    """
    def dependency(request: Request, token=Depends(bearer), db=Depends(get_db)) -> dict:
        claims = _decode_agent_claims(token)
        if required_scope not in claims.get("scopes", []):
            _log(db, claims, request.url.path, request.method, "rejected_scope", consent_required=True, consent_given=False)
            raise HTTPException(
                status_code=403,
                detail=f"Scope '{required_scope}' not granted — request consent first",
            )
        _apply_policy(request, claims, db, consent_required=True, consent_given=True)
        return claims

    return dependency
