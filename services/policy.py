from datetime import datetime, time
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

# Audit action -> message returned to the caller
REJECTION_MESSAGES = {
    "rejected_no_policy": "No policy is configured for this agent",
    "rejected_endpoint": "Endpoint not permitted by agent policy",
    "rejected_method": "Method not permitted by agent policy",
    "rejected_time_window": "Request outside allowed time window",
    "rejected_day": "Request on disallowed day",
}


def endpoint_matches(endpoint: str, patterns: list[str]) -> bool:
    """Exact match, or prefix match for a pattern ending in '*' ("/api/orders/*")."""
    for pattern in patterns:
        if pattern.endswith("*"):
            if endpoint.startswith(pattern[:-1]):
                return True
        elif endpoint == pattern:
            return True
    return False


def within_time_window(start: time, end: time, now: time) -> bool:
    """Inclusive window. start > end means it crosses midnight (22:00-06:00)."""
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


def check_schedule(policy, now: datetime | None = None) -> str | None:
    """Rules that depend only on *when*, so they can be checked at token issuance.

    Returns the audit action for the first violation, or None if allowed.
    A missing policy is a violation: agents are denied until a policy is set.
    """
    if policy is None:
        return "rejected_no_policy"

    now_ist = (now or datetime.now(IST)).astimezone(IST)

    if policy.time_window_start is not None and policy.time_window_end is not None:
        if not within_time_window(policy.time_window_start, policy.time_window_end, now_ist.time()):
            return "rejected_time_window"

    if policy.allowed_days:
        if now_ist.strftime("%A").lower() not in [d.lower() for d in policy.allowed_days]:
            return "rejected_day"

    return None


def check_request(policy, endpoint: str, method: str, now: datetime | None = None) -> str | None:
    """Full policy check for one request: endpoint, method, then the schedule.

    Returns the audit action for the first violation, or None if allowed.
    An empty allowed_endpoints / allowed_methods list means "no restriction".
    """
    if policy is None:
        return "rejected_no_policy"
    if policy.allowed_endpoints and not endpoint_matches(endpoint, policy.allowed_endpoints):
        return "rejected_endpoint"
    if policy.allowed_methods and method not in policy.allowed_methods:
        return "rejected_method"
    return check_schedule(policy, now)
