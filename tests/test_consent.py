"""Consent lifecycle: request -> approve/deny -> redeem, expiry, and polling auth."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from conftest import bearer


@pytest.fixture
def request_consent(client, tokens):
    def _request(scope="delete:orders", sub="sub-alice", email="alice@example.com", client_id="client-1"):
        return client.post(
            "/consent/request",
            json={"monocloud_client_id": client_id, "scope": scope},
            headers=bearer(tokens.user(sub, email)),
        )
    return _request


@pytest.fixture
def resolve(client, tokens):
    def _resolve(consent_id, approved, sub="sub-alice", email="alice@example.com"):
        return client.post(
            "/consent/approve",
            json={"consent_id": str(consent_id), "approved": approved},
            headers=bearer(tokens.user(sub, email)),
        )
    return _resolve


@pytest.fixture
def poll(client, tokens):
    def _poll(consent_id, client_id="client-1"):
        return client.get(f"/consent/status/{consent_id}", headers=bearer(tokens.agent(client_id)))
    return _poll


@pytest.fixture
def age(db):
    """Make a consent look older: age(id, created_minutes=6) / age(id, resolved_minutes=6)."""
    def _age(consent_id, created_minutes=None, resolved_minutes=None):
        if created_minutes:
            db.execute(text("UPDATE consent_requests SET created_at = :t WHERE id = :i"),
                       {"t": datetime.now(timezone.utc) - timedelta(minutes=created_minutes), "i": consent_id})
        if resolved_minutes:
            db.execute(text("UPDATE consent_requests SET resolved_at = :t WHERE id = :i"),
                       {"t": datetime.now(timezone.utc) - timedelta(minutes=resolved_minutes), "i": consent_id})
        db.commit()
    return _age


class TestRequesting:
    def test_creates_a_pending_record_and_logs_it(self, request_consent, last_audit, world):
        resp = request_consent()
        assert resp.status_code == 201 and resp.json()["status"] == "pending"
        row = last_audit()
        assert (row.action, row.consent_required, row.consent_given) == ("consent_requested", True, None)

    @pytest.mark.parametrize("scope", ["delete:orders", "write:orders", "admin:users", "DELETE:orders"])
    def test_destructive_scopes_accepted(self, request_consent, world, scope):
        assert request_consent(scope=scope).status_code == 201

    @pytest.mark.parametrize("scope", ["read", "read:orders", "orders"])
    def test_non_destructive_scopes_refused(self, request_consent, world, scope):
        assert request_consent(scope=scope).status_code == 400

    def test_cannot_request_for_someone_elses_agent(self, request_consent, world):
        assert request_consent(client_id="client-2").status_code == 404

    def test_needs_a_user_token(self, client, world):
        resp = client.post("/consent/request", json={"monocloud_client_id": "client-1", "scope": "delete:orders"})
        assert resp.status_code in (401, 403)


class TestDecision:
    def test_approve_is_logged(self, request_consent, resolve, last_audit, world):
        cid = request_consent().json()["id"]
        assert resolve(cid, True).json() == {"status": "approved"}
        row = last_audit()
        assert (row.action, row.consent_given) == ("consent_approved", True)

    def test_deny_is_logged(self, request_consent, resolve, last_audit, world):
        cid = request_consent().json()["id"]
        assert resolve(cid, False).json() == {"status": "denied"}
        row = last_audit()
        assert (row.action, row.consent_given) == ("consent_denied", False)

    def test_only_the_owner_can_decide(self, request_consent, resolve, world):
        cid = request_consent().json()["id"]
        assert resolve(cid, True, sub="sub-bob", email="bob@example.com").status_code == 404

    def test_cannot_decide_twice(self, request_consent, resolve, world):
        cid = request_consent().json()["id"]
        resolve(cid, True)
        assert resolve(cid, False).status_code == 409

    def test_unknown_id(self, resolve, world):
        assert resolve(uuid.uuid4(), True).status_code == 404

    def test_pending_list_shows_only_my_pending_requests(self, client, tokens, request_consent, resolve, world):
        first = request_consent().json()["id"]
        second = request_consent(scope="write:orders").json()["id"]
        resolve(second, True)
        mine = client.get("/consent/pending", headers=bearer(tokens.user("sub-alice", "alice@example.com"))).json()
        assert [c["id"] for c in mine] == [first]
        theirs = client.get("/consent/pending", headers=bearer(tokens.user("sub-bob", "bob@example.com"))).json()
        assert theirs == []


class TestPolling:
    def test_owning_agent_sees_status(self, request_consent, poll, resolve, world):
        cid = request_consent().json()["id"]
        assert poll(cid).json()["status"] == "pending"
        resolve(cid, True)
        assert poll(cid).json()["status"] == "approved"

    def test_requires_agent_credentials(self, client, request_consent, world):
        cid = request_consent().json()["id"]
        assert client.get(f"/consent/status/{cid}").status_code in (401, 403)

    def test_rejects_an_invalid_token(self, client, request_consent, world):
        cid = request_consent().json()["id"]
        assert client.get(f"/consent/status/{cid}", headers=bearer("junk")).status_code == 401

    def test_another_agent_cannot_read_it(self, poll, request_consent, world):
        cid = request_consent().json()["id"]
        assert poll(cid, client_id="client-2").status_code == 404

    def test_a_user_token_cannot_read_it(self, client, tokens, request_consent, world):
        cid = request_consent().json()["id"]
        resp = client.get(f"/consent/status/{cid}", headers=bearer(tokens.user("sub-alice", "alice@example.com")))
        assert resp.status_code == 404

    def test_malformed_id_is_a_422_not_a_crash(self, client, tokens, world):
        assert client.get("/consent/status/not-a-uuid", headers=bearer(tokens.agent("client-1"))).status_code == 422

    def test_stale_pending_request_is_410_gone(self, request_consent, poll, age, world):
        cid = request_consent().json()["id"]
        age(cid, created_minutes=6)
        assert poll(cid).status_code == 410

    def test_a_fresh_request_is_not_expired(self, request_consent, poll, age, world):
        cid = request_consent().json()["id"]
        age(cid, created_minutes=4)
        assert poll(cid).status_code == 200

    def test_expiry_is_logged_exactly_once(self, request_consent, poll, age, audit_actions, world):
        cid = request_consent().json()["id"]
        age(cid, created_minutes=6)
        poll(cid)
        poll(cid)
        assert audit_actions().count("consent_expired") == 1

    def test_expired_request_cannot_be_approved(self, request_consent, resolve, age, world):
        cid = request_consent().json()["id"]
        age(cid, created_minutes=6)
        assert resolve(cid, True).status_code == 409


class TestRedemption:
    """An approved consent is what puts a destructive scope into a token."""

    def test_full_flow_ends_in_a_token_that_can_delete(self, client, exchange, request_consent, resolve, audit_actions, last_audit, world):
        read_token = exchange().json()["agent_delegation_jwt"]
        assert client.delete("/api/protected/orders", headers=bearer(read_token)).status_code == 403

        cid = request_consent().json()["id"]
        resolve(cid, True)
        resp = exchange(consent_id=cid)
        assert resp.status_code == 200 and resp.json()["scopes"] == ["read", "delete:orders"]
        row = last_audit()
        assert (row.action, row.consent_required, row.consent_given) == ("token_issued_with_consent", True, True)

        consent_token = resp.json()["agent_delegation_jwt"]
        assert client.delete("/api/protected/orders", headers=bearer(consent_token)).status_code == 200

    def test_pending_consent_cannot_be_redeemed(self, exchange, request_consent, last_audit, world):
        cid = request_consent().json()["id"]
        assert exchange(consent_id=cid).status_code == 403
        assert last_audit().action == "rejected_consent"

    def test_denied_consent_cannot_be_redeemed(self, exchange, request_consent, resolve, world):
        cid = request_consent().json()["id"]
        resolve(cid, False)
        assert exchange(consent_id=cid).status_code == 403

    def test_each_approval_works_once(self, exchange, request_consent, resolve, world):
        cid = request_consent().json()["id"]
        resolve(cid, True)
        assert exchange(consent_id=cid).status_code == 200
        assert exchange(consent_id=cid).status_code == 403

    def test_an_approval_goes_stale_after_five_minutes(self, exchange, request_consent, resolve, age, world):
        cid = request_consent().json()["id"]
        resolve(cid, True)
        age(cid, resolved_minutes=6)
        assert exchange(consent_id=cid).status_code == 403

    def test_a_consent_cannot_be_redeemed_by_another_agent_or_user(self, exchange, request_consent, resolve, set_policy, world):
        set_policy(world.agent2)
        cid = request_consent().json()["id"]
        resolve(cid, True)
        resp = exchange(user_sub="sub-bob", email="bob@example.com", client_id="client-2", consent_id=cid)
        assert resp.status_code == 403

    def test_unknown_consent_id(self, exchange, world):
        assert exchange(consent_id=uuid.uuid4()).status_code == 403

    def test_a_rejected_issuance_does_not_burn_the_approval(self, exchange, request_consent, resolve, set_policy, world):
        cid = request_consent().json()["id"]
        resolve(cid, True)
        # a policy that forbids today: the exchange is refused before the consent is consumed
        set_policy(world.agent1, days=["nonexistentday"])  # matches no real day
        assert exchange(consent_id=cid).status_code == 403
        set_policy(world.agent1)
        assert exchange(consent_id=cid).status_code == 200
