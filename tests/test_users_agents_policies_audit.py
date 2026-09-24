"""The dashboard-facing CRUD endpoints (all authenticated with a MonoCloud user JWT)."""
import pytest

from conftest import bearer


@pytest.fixture
def alice_headers(tokens):
    return bearer(tokens.user("sub-alice", "alice@example.com"))


@pytest.fixture
def bob_headers(tokens):
    return bearer(tokens.user("sub-bob", "bob@example.com"))


class TestUserSync:
    def test_creates_the_user_once(self, client, tokens, db):
        headers = bearer(tokens.user("sub-new", "new@example.com"))
        first = client.post("/api/users/sync", headers=headers)
        second = client.post("/api/users/sync", headers=headers)
        assert first.status_code == second.status_code == 200
        assert first.json()["id"] == second.json()["id"]
        assert first.json()["email"] == "new@example.com"

    def test_identity_comes_from_the_token(self, client, tokens):
        resp = client.post("/api/users/sync", json={"email": "spoof@example.com", "monocloud_user_id": "sub-boss"},
                           headers=bearer(tokens.user("sub-new", "new@example.com")))
        assert resp.json()["monocloud_user_id"] == "sub-new" and resp.json()["email"] == "new@example.com"

    def test_token_without_email_is_a_clear_400(self, client, tokens):
        resp = client.post("/api/users/sync", headers=bearer(tokens.user("sub-noemail")))
        assert resp.status_code == 400 and "email" in resp.json()["detail"]

    def test_email_already_used_by_another_user_is_409(self, client, tokens, world):
        resp = client.post("/api/users/sync", headers=bearer(tokens.user("sub-other", "alice@example.com")))
        assert resp.status_code == 409

    def test_existing_user_without_email_claim_still_syncs(self, client, tokens, world):
        assert client.post("/api/users/sync", headers=bearer(tokens.user("sub-alice"))).status_code == 200

    def test_invalid_token(self, client):
        assert client.post("/api/users/sync", headers=bearer("junk")).status_code == 401


class TestAuthRequired:
    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/agents"), ("GET", "/api/audit"), ("GET", "/consent/pending"),
        ("GET", "/api/policies/00000000-0000-0000-0000-000000000000"),
    ])
    def test_endpoints_reject_anonymous_and_junk(self, client, world, method, path):
        assert client.request(method, path).status_code in (401, 403)
        assert client.request(method, path, headers=bearer("junk")).status_code == 401

    def test_unsynced_user_is_told_to_sync(self, client, tokens):
        resp = client.get("/api/agents", headers=bearer(tokens.user("sub-stranger", "s@example.com")))
        assert resp.status_code == 404 and "sync" in resp.json()["detail"]


class TestAgents:
    def test_list_shows_only_my_agents(self, client, world, alice_headers, bob_headers):
        assert [a["name"] for a in client.get("/api/agents", headers=alice_headers).json()] == ["order-bot"]
        assert [a["name"] for a in client.get("/api/agents", headers=bob_headers).json()] == ["bobs-bot"]

    def test_create(self, client, world, alice_headers):
        resp = client.post("/api/agents", json={"name": "new-bot", "monocloud_client_id": "client-9"}, headers=alice_headers)
        assert resp.status_code == 201
        assert resp.json()["owner_id"] == str(world.alice.id)  # owner comes from the token, not the body

    def test_duplicate_client_id_is_409(self, client, world, alice_headers):
        resp = client.post("/api/agents", json={"name": "dup", "monocloud_client_id": "client-2"}, headers=alice_headers)
        assert resp.status_code == 409

    def test_delete_own(self, client, world, alice_headers):
        assert client.delete(f"/api/agents/{world.agent1.id}", headers=alice_headers).status_code == 204
        assert client.get("/api/agents", headers=alice_headers).json() == []

    def test_cannot_delete_someone_elses(self, client, world, alice_headers, bob_headers):
        assert client.delete(f"/api/agents/{world.agent2.id}", headers=alice_headers).status_code == 404
        assert len(client.get("/api/agents", headers=bob_headers).json()) == 1


class TestPolicies:
    def test_upsert_normalises_and_reads_back(self, client, world, bob_headers):
        url = f"/api/policies/{world.agent2.id}"
        body = {"allowed_endpoints": ["/api/orders/*"], "allowed_methods": ["post"], "allowed_days": ["Monday"],
                "time_window_start": "09:00", "time_window_end": "18:00"}
        saved = client.put(url, json=body, headers=bob_headers)
        assert saved.status_code == 200
        assert saved.json()["allowed_methods"] == ["POST"] and saved.json()["allowed_days"] == ["monday"]
        assert client.get(url, headers=bob_headers).json()["time_window_start"] == "09:00:00"

        # second PUT updates the same row
        client.put(url, json={"allowed_methods": ["GET"]}, headers=bob_headers)
        again = client.get(url, headers=bob_headers).json()
        assert again["id"] == saved.json()["id"] and again["allowed_methods"] == ["GET"] and again["time_window_start"] is None

        assert client.delete(url, headers=bob_headers).status_code == 204
        assert client.get(url, headers=bob_headers).status_code == 404

    @pytest.mark.parametrize("body", [
        {"allowed_methods": ["FETCH"]}, {"allowed_endpoints": ["nope"]}, {"allowed_days": ["funday"]},
        {"time_window_start": "09:00"},
    ])
    def test_invalid_policy_is_a_422(self, client, world, bob_headers, body):
        assert client.put(f"/api/policies/{world.agent2.id}", json=body, headers=bob_headers).status_code == 422

    def test_cannot_touch_someone_elses_policy(self, client, world, alice_headers):
        url = f"/api/policies/{world.agent2.id}"
        assert client.put(url, json={}, headers=alice_headers).status_code == 404
        assert client.get(url, headers=alice_headers).status_code == 404
        assert client.delete(url, headers=alice_headers).status_code == 404


class TestAuditFeed:
    def test_shows_only_my_agents_activity_newest_first(self, client, exchange, set_policy, world, alice_headers, bob_headers):
        exchange()  # alice's agent: token_issued
        set_policy(world.agent2)
        exchange(user_sub="sub-bob", email="bob@example.com", client_id="client-2")  # bob's agent
        mine = client.get("/api/audit", headers=alice_headers).json()
        assert [r["action"] for r in mine] == ["token_issued"]
        assert mine[0]["agent_id"] == str(world.agent1.id)
        assert len(client.get("/api/audit", headers=bob_headers).json()) == 1

    def test_pagination(self, client, exchange, world, alice_headers):
        for _ in range(3):
            exchange()
        assert len(client.get("/api/audit?limit=2", headers=alice_headers).json()) == 2
        assert len(client.get("/api/audit?limit=2&offset=2", headers=alice_headers).json()) == 1
        assert client.get("/api/audit?limit=999", headers=alice_headers).status_code == 422

    def test_user_with_no_agents_gets_an_empty_feed(self, client, make_user, tokens):
        make_user("sub-loner", "loner@example.com")
        assert client.get("/api/audit", headers=bearer(tokens.user("sub-loner", "loner@example.com"))).json() == []


def test_cors_allows_the_configured_dashboard_origin(client):
    ok = client.options("/api/agents", headers={"Origin": "https://dashboard.test", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://dashboard.test"
    local = client.options("/api/agents", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert local.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/api/agents", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers
