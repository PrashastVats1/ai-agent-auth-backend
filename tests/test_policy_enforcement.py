"""Request-time enforcement on the delegation-JWT-protected demo endpoints."""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from conftest import bearer
from services.policy import IST

ORDERS = "/api/protected/orders"


@pytest.fixture
def agent_token(exchange, world):
    """A valid delegation JWT for agent1, minted while its policy was allow-all."""
    return exchange().json()["agent_delegation_jwt"]


def test_allowed_request_is_logged(client, agent_token, last_audit, world):
    resp = client.get(ORDERS, headers=bearer(agent_token))
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == str(world.agent1.id) and resp.json()["user_id"] == str(world.alice.id)
    row = last_audit()
    assert (row.action, row.endpoint, row.method) == ("allowed", ORDERS, "GET")
    assert row.agent_id == world.agent1.id and row.user_id == world.alice.id


class TestAuthentication:
    def test_missing_token(self, client, world):
        assert client.get(ORDERS).status_code in (401, 403)

    def test_a_monocloud_token_is_not_accepted_here(self, client, tokens, world):
        assert client.get(ORDERS, headers=bearer(tokens.user("sub-alice", "alice@example.com"))).status_code == 401

    def test_garbage(self, client, world):
        assert client.get(ORDERS, headers=bearer("nope")).status_code == 401


class TestPolicy:
    def test_policy_removed_after_issuance_means_denied(self, client, agent_token, db, last_audit, world):
        db.execute(text("DELETE FROM policies"))
        db.commit()
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 403
        assert last_audit().action == "rejected_no_policy"

    def test_endpoint_not_allowed(self, client, agent_token, set_policy, last_audit, world):
        set_policy(world.agent1, endpoints=["/api/other"])
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 403
        assert last_audit().action == "rejected_endpoint"

    def test_exact_endpoint_allowed(self, client, agent_token, set_policy, world):
        set_policy(world.agent1, endpoints=[ORDERS])
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 200

    def test_wildcard_endpoint_allowed(self, client, agent_token, set_policy, world):
        set_policy(world.agent1, endpoints=["/api/protected/*"])
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 200

    def test_method_not_allowed(self, client, agent_token, set_policy, last_audit, world):
        set_policy(world.agent1, methods=["POST"])
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 403
        assert last_audit().action == "rejected_method"

    def test_outside_time_window(self, client, agent_token, set_policy, last_audit, world):
        now = datetime.now(IST)
        set_policy(world.agent1, start=(now + timedelta(hours=2)).time(), end=(now + timedelta(hours=3)).time())
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 403
        assert last_audit().action == "rejected_time_window"

    def test_disallowed_day(self, client, agent_token, set_policy, last_audit, world):
        today = datetime.now(IST).strftime("%A").lower()
        days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        set_policy(world.agent1, days=[d for d in days if d != today])
        assert client.get(ORDERS, headers=bearer(agent_token)).status_code == 403
        assert last_audit().action == "rejected_day"

    def test_every_rejection_is_logged(self, client, agent_token, set_policy, audit_actions, world):
        set_policy(world.agent1, methods=["POST"])
        for _ in range(3):
            client.get(ORDERS, headers=bearer(agent_token))
        assert audit_actions().count("rejected_method") == 3


class TestScope:
    def test_delete_needs_the_consented_scope(self, client, agent_token, last_audit, world):
        assert client.delete(ORDERS, headers=bearer(agent_token)).status_code == 403
        row = last_audit()
        assert (row.action, row.consent_required, row.consent_given) == ("rejected_scope", True, False)

    def test_policy_still_applies_to_a_consented_token(self, client, exchange, tokens, set_policy, world):
        # Give the token the scope directly, then take away the method in the policy
        from services.delegation import issue_agent_jwt
        token = issue_agent_jwt(str(world.alice.id), "alice@example.com", str(world.agent1.id), "order-bot", ["read", "delete:orders"])
        assert client.delete(ORDERS, headers=bearer(token)).status_code == 200
        set_policy(world.agent1, methods=["GET"])
        assert client.delete(ORDERS, headers=bearer(token)).status_code == 403
