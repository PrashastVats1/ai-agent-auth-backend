"""
Demo agent script — simulates a real AI agent doing the full auth flow:
1. Get a MonoCloud M2M token using client credentials (the agent's own identity)
2. Exchange it (+ the user's JWT) for a read-only delegation JWT from our backend
3. Call a policy-protected endpoint with it
4. Try a destructive call with the read-only token (expect 403)
5. Request consent for delete:orders and poll every 4 seconds until the user decides
6. Redeem the approved consent for a new delegation JWT and retry the destructive call

Prerequisite: the agent must be registered in the dashboard AND have a policy
(agents without one are denied). A policy that allows GET and DELETE on
/api/protected/orders works; so does one with every field left empty.

Configuration comes from environment variables so no secrets live in this file:

    export MONOCLOUD_ISSUER_URL=https://<your-monocloud-domain>
    export AGENT_CLIENT_ID=<agent M2M client id>
    export AGENT_CLIENT_SECRET=<agent M2M client secret>
    export USER_JWT=<user access_token from the dashboard session>
    export BACKEND_URL=http://localhost:8000     # optional, this is the default
    python3 examples/agent_demo.py

Get USER_JWT from the browser console while signed in to the dashboard:
    const keys = Object.keys(sessionStorage).filter(k => k.includes('oidc'))
    JSON.parse(sessionStorage.getItem(keys[0])).access_token
"""

import os
import sys
import time

import requests

MONOCLOUD_ISSUER = os.environ.get("MONOCLOUD_ISSUER_URL", "")
AGENT_CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "")
AGENT_CLIENT_SECRET = os.environ.get("AGENT_CLIENT_SECRET", "")
USER_JWT = os.environ.get("USER_JWT", "")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

CONSENT_POLL_SECONDS = 4          # never poll faster — Neon's free tier connection limit
CONSENT_MAX_WAIT_SECONDS = 300    # consent requests expire after 5 minutes


def get_m2m_token() -> str | None:
    """Step 1: Agent authenticates with MonoCloud using client credentials."""
    print("\n[1] Getting M2M token from MonoCloud...")
    resp = requests.post(
        f"{MONOCLOUD_ISSUER}/connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": AGENT_CLIENT_ID,
            "client_secret": AGENT_CLIENT_SECRET,
            "scope": "openid",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"    FAILED: {resp.status_code} {resp.text}")
        return None
    token = resp.json().get("access_token")
    print("    OK — got M2M token")
    return token


def get_delegation_jwt(user_jwt: str, m2m_jwt: str, consent_id: str | None = None) -> str | None:
    """Exchange user JWT + agent M2M JWT (+ optionally an approved consent) for a delegation JWT."""
    body = {
        "monocloud_user_jwt": user_jwt,
        "monocloud_agent_jwt": m2m_jwt,
        "monocloud_client_id": AGENT_CLIENT_ID,
    }
    if consent_id:
        body["consent_id"] = consent_id
    resp = requests.post(f"{BACKEND_URL}/auth/agent-token", json=body, timeout=60)
    if resp.status_code != 200:
        print(f"    FAILED: {resp.status_code} {resp.text}")
        return None
    data = resp.json()
    print(f"    OK — delegation JWT issued with scopes {data['scopes']}")
    return data["agent_delegation_jwt"]


def call_protected(delegation_jwt: str, method: str, label: str):
    print(f"    {label}")
    resp = requests.request(
        method,
        f"{BACKEND_URL}/api/protected/orders",
        headers={"Authorization": f"Bearer {delegation_jwt}"},
        timeout=30,
    )
    print(f"    -> {resp.status_code} {resp.text}")
    return resp.status_code


def request_consent(user_jwt: str) -> str | None:
    """Request consent for a destructive scope."""
    print("\n[5] Requesting consent for delete:orders scope...")
    resp = requests.post(
        f"{BACKEND_URL}/consent/request",
        json={"monocloud_client_id": AGENT_CLIENT_ID, "scope": "delete:orders"},
        headers={"Authorization": f"Bearer {user_jwt}"},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        print(f"    FAILED: {resp.status_code} {resp.text}")
        return None
    consent_id = resp.json()["id"]
    print(f"    OK — consent ID: {consent_id}")
    print("    Open the dashboard (http://localhost:5173) and approve the request.")
    return consent_id


def poll_consent(consent_id: str, m2m_jwt: str) -> str | None:
    """Poll every 4 seconds until approved, denied, or expired. Returns the final status.

    The status endpoint requires the agent's own M2M token."""
    print(f"    Polling every {CONSENT_POLL_SECONDS} seconds...")
    for attempt in range(CONSENT_MAX_WAIT_SECONDS // CONSENT_POLL_SECONDS):
        time.sleep(CONSENT_POLL_SECONDS)
        resp = requests.get(
            f"{BACKEND_URL}/consent/status/{consent_id}",
            headers={"Authorization": f"Bearer {m2m_jwt}"},
            timeout=30,
        )
        if resp.status_code == 410:
            print("    Consent expired.")
            return "expired"
        if resp.status_code != 200:
            print(f"    Error: {resp.status_code} {resp.text}")
            return None
        status = resp.json()["status"]
        print(f"    Attempt {attempt + 1}: status = {status}")
        if status in ("approved", "denied"):
            return status
    print("    Timed out waiting for consent.")
    return None


if __name__ == "__main__":
    required = {
        "MONOCLOUD_ISSUER_URL": MONOCLOUD_ISSUER,
        "AGENT_CLIENT_ID": AGENT_CLIENT_ID,
        "AGENT_CLIENT_SECRET": AGENT_CLIENT_SECRET,
        "USER_JWT": USER_JWT,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        print(f"ERROR: set these environment variables first: {', '.join(missing)}")
        print("See the docstring at the top of this file.")
        sys.exit(1)

    m2m_jwt = get_m2m_token()
    if not m2m_jwt:
        sys.exit(1)

    print("\n[2] Requesting read-only delegation JWT from backend...")
    read_jwt = get_delegation_jwt(USER_JWT, m2m_jwt)
    if not read_jwt:
        sys.exit(1)

    print("\n[3] Calling protected endpoint with the read-only token...")
    call_protected(read_jwt, "GET", "GET /api/protected/orders (expect 200)")

    print("\n[4] Trying a destructive call WITHOUT consent...")
    call_protected(read_jwt, "DELETE", "DELETE /api/protected/orders (expect 403)")

    consent_id = request_consent(USER_JWT)
    if not consent_id:
        sys.exit(1)

    outcome = poll_consent(consent_id, m2m_jwt)
    if outcome != "approved":
        print(f"\nStopping — consent outcome: {outcome}")
        sys.exit(0)

    print("\n[6] Redeeming the approved consent for a new delegation JWT...")
    consent_jwt = get_delegation_jwt(USER_JWT, m2m_jwt, consent_id=consent_id)
    if consent_jwt:
        call_protected(consent_jwt, "DELETE", "DELETE /api/protected/orders (expect 200)")
