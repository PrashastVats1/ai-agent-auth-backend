"""POST /auth/agent-token: who may get a delegation JWT, and with what scopes."""
from datetime import datetime, timedelta

from services.delegation import validate_agent_jwt
from services.policy import IST


def test_owner_with_agent_credentials_gets_a_read_only_token(exchange, last_audit, world):
    resp = exchange()
    assert resp.status_code == 200
    body = resp.json()
    assert body["scopes"] == ["read"] and body["expires_in"] == 30 * 60
    claims = validate_agent_jwt(body["agent_delegation_jwt"])
    assert claims["user_email"] == "alice@example.com" and claims["agent_name"] == "order-bot"
    assert claims["user_id"] == str(world.alice.id) and claims["agent_id"] == str(world.agent1.id)
    assert last_audit().action == "token_issued"


class TestIdentity:
    def test_agent_token_issued_to_a_different_client(self, exchange, tokens, world):
        assert exchange(agent_token=tokens.agent("client-2")).status_code == 401

    def test_user_token_cannot_stand_in_for_the_agent_token(self, exchange, tokens, world):
        assert exchange(agent_token=tokens.user("sub-alice", "alice@example.com")).status_code == 401

    def test_garbage_agent_token(self, exchange, world):
        assert exchange(agent_token="nope").status_code == 401

    def test_expired_agent_token(self, exchange, tokens, world):
        assert exchange(agent_token=tokens.agent("client-1", expires_in=-60)).status_code == 401

    def test_expired_user_token(self, exchange, tokens, world):
        assert exchange(user_token=tokens.user("sub-alice", "alice@example.com", expires_in=-60)).status_code == 401

    def test_user_token_signed_by_another_key(self, exchange, tokens, world):
        assert exchange(user_token=tokens.signed_by_other_key("sub-alice")).status_code == 401

    def test_a_delegation_jwt_is_not_accepted_as_a_user_token(self, exchange, world):
        delegation = exchange().json()["agent_delegation_jwt"]
        assert exchange(user_token=delegation).status_code == 401

    def test_user_must_have_synced_first(self, exchange, world):
        assert exchange(user_sub="sub-stranger", email="s@example.com").status_code == 404


class TestOwnership:
    def test_cannot_mint_a_token_for_someone_elses_agent(self, exchange, set_policy, world):
        set_policy(world.agent2)
        # Alice holds valid credentials for agent2, but Bob owns it
        resp = exchange(client_id="client-2")
        assert resp.status_code == 404

    def test_unknown_agent_looks_the_same_as_someone_elses(self, exchange, world):
        assert exchange(client_id="no-such-client").status_code == 404


class TestPolicyAtIssuance:
    def test_no_policy_means_no_token(self, exchange, last_audit, world):
        resp = exchange(user_sub="sub-bob", email="bob@example.com", client_id="client-2")
        assert resp.status_code == 403 and "policy" in resp.json()["detail"].lower()
        row = last_audit()
        assert (row.action, row.endpoint, row.method) == ("rejected_no_policy", "/auth/agent-token", "POST")

    def test_outside_the_time_window(self, exchange, set_policy, last_audit, world):
        now = datetime.now(IST)
        set_policy(world.agent1, start=(now + timedelta(hours=2)).time(), end=(now + timedelta(hours=3)).time())
        resp = exchange()
        assert resp.status_code == 403
        assert last_audit().action == "rejected_time_window"

    def test_inside_the_time_window(self, exchange, set_policy, world):
        now = datetime.now(IST)
        set_policy(world.agent1, start=(now - timedelta(hours=1)).time(), end=(now + timedelta(hours=1)).time())
        # (skip the rare midnight-adjacent run where this window would wrap)
        if (now - timedelta(hours=1)).date() == (now + timedelta(hours=1)).date():
            assert exchange().status_code == 200

    def test_disallowed_day(self, exchange, set_policy, last_audit, world):
        today = datetime.now(IST).strftime("%A").lower()
        days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        set_policy(world.agent1, days=[d for d in days if d != today])
        assert exchange().status_code == 403
        assert last_audit().action == "rejected_day"

    def test_allowed_day(self, exchange, set_policy, world):
        set_policy(world.agent1, days=[datetime.now(IST).strftime("%A").lower()])
        assert exchange().status_code == 200

    def test_endpoint_and_method_rules_do_not_block_issuance(self, exchange, set_policy, world):
        # They can't be evaluated until the agent calls something.
        set_policy(world.agent1, endpoints=["/api/only-this"], methods=["GET"])
        assert exchange().status_code == 200
