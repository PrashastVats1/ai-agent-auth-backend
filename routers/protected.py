from fastapi import APIRouter, Depends
from middleware.policy_check import enforce_policy

router = APIRouter(prefix="/api/protected", tags=["protected"])


@router.get("/orders")
def list_orders(claims: dict = Depends(enforce_policy)):
    """Demo endpoint protected by the agent delegation JWT + policy enforcement.

    Any agent calling this must present a valid delegation JWT. If a policy
    exists for the agent, endpoint/method/time/day rules are enforced and
    every call is logged to audit_logs.
    """
    return {
        "message": f"Agent '{claims['agent_name']}' acting on behalf of '{claims['user_email']}' accessed orders.",
        "agent_id": claims["agent_id"],
        "user_id": claims["user_id"],
        "scopes": claims["scopes"],
    }
