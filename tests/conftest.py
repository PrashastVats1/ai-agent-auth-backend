"""Test setup.

Database tests run against a real PostgreSQL given by TEST_DATABASE_URL and are
skipped when it isn't set. Each session creates a throwaway schema, applies
schema.sql to it, and drops it afterwards, so it is safe to point at any
Postgres you can create schemas in. Use a scratch database, not your real one;
this file refuses to run against the NEON_DATABASE_URL in your .env unless you set
ALLOW_TEST_ON_REAL_DB=1 (safe: all tests run inside their own throwaway schema).

MonoCloud is replaced by a throwaway RSA key: tests mint real RS256 tokens and the
JWKS lookup returns the matching public key, so the real validate_monocloud_jwt()
runs (signature, issuer, audience and expiry are all checked).
"""
import os
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import dotenv_values
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parent.parent

ISSUER = "https://issuer.test"
AUDIENCE = "https://api.test"
JWT_SECRET = "test-secret-" + "x" * 40

# The app reads its config when its modules are imported, so set it first.
os.environ["MONOCLOUD_ISSUER_URL"] = ISSUER
os.environ["MONOCLOUD_AUDIENCE"] = AUDIENCE
os.environ["JWT_SECRET"] = JWT_SECRET
os.environ["CORS_ALLOWED_ORIGINS"] = "https://dashboard.test"

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
SCHEMA_NAME = f"test_{uuid.uuid4().hex[:10]}"


def _setup_database() -> None:
    if not TEST_DATABASE_URL:
        # Never connected to: database tests are skipped without TEST_DATABASE_URL.
        os.environ["NEON_DATABASE_URL"] = "postgresql://unused:unused@localhost:1/unused"
        return

    real_url = dotenv_values(BACKEND_DIR / ".env").get("NEON_DATABASE_URL")
    if TEST_DATABASE_URL in (real_url, os.getenv("NEON_DATABASE_URL")) and os.getenv("ALLOW_TEST_ON_REAL_DB") != "1":
        raise pytest.UsageError(
            "TEST_DATABASE_URL is your real NEON_DATABASE_URL. The tests only touch their own throwaway "
            "schema, so this is safe, but set ALLOW_TEST_ON_REAL_DB=1 to confirm you want it."
        )

    base = make_url(TEST_DATABASE_URL)
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE SCHEMA "{SCHEMA_NAME}"'))
    admin.dispose()

    scoped = base.update_query_pairs([("options", f"-csearch_path={SCHEMA_NAME}")])
    engine = create_engine(scoped)
    raw = engine.raw_connection()
    try:
        with raw.cursor() as cur:
            cur.execute((BACKEND_DIR / "schema.sql").read_text())
        raw.commit()
    finally:
        raw.close()
    engine.dispose()

    os.environ["NEON_DATABASE_URL"] = scoped.render_as_string(hide_password=False)


_setup_database()


def pytest_sessionfinish(session, exitstatus):
    if not TEST_DATABASE_URL:
        return
    admin = create_engine(make_url(TEST_DATABASE_URL), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{SCHEMA_NAME}" CASCADE'))
    admin.dispose()


# ---------------------------------------------------------------- fake MonoCloud

@pytest.fixture(scope="session")
def _rsa():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk

    def make_key():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return private_pem, public_pem

    private_pem, public_pem = make_key()
    public_jwk = jwk.construct(public_pem, "RS256").to_dict()
    public_jwk.update(kid="test-key", use="sig", alg="RS256")
    return SimpleNamespace(private_pem=private_pem, jwks={"keys": [public_jwk]}, make_key=make_key)


class TokenFactory:
    """Mints tokens the way MonoCloud would. Override any claim with keyword args."""

    def __init__(self, private_pem: str, make_key):
        self._private_pem = private_pem
        self._make_key = make_key

    def _sign(self, claims: dict, key_pem: str | None = None) -> str:
        from jose import jwt
        return jwt.encode(claims, key_pem or self._private_pem, algorithm="RS256", headers={"kid": "test-key"})

    def _base(self, expires_in: int) -> dict:
        now = int(time.time())
        return {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + expires_in}

    def user(self, sub: str, email: str | None = None, expires_in: int = 3600, **overrides) -> str:
        claims = {**self._base(expires_in), "sub": sub}
        if email is not None:
            claims["email"] = email
        return self._sign({**claims, **overrides})

    def agent(self, client_id: str, expires_in: int = 3600, **overrides) -> str:
        """An M2M (client credentials) token: sub is the client itself."""
        return self._sign({**self._base(expires_in), "client_id": client_id, "sub": client_id, **overrides})

    def signed_by_other_key(self, sub: str) -> str:
        other_private, _ = self._make_key()
        return self._sign({**self._base(3600), "sub": sub, "email": "x@example.com"}, key_pem=other_private)


@pytest.fixture
def tokens(_rsa, monkeypatch):
    import services.monocloud as monocloud
    monkeypatch.setattr(monocloud, "_get_monocloud_jwks", lambda: _rsa.jwks)
    return TokenFactory(_rsa.private_pem, _rsa.make_key)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------- database

@pytest.fixture
def clean_db():
    if not TEST_DATABASE_URL:
        pytest.skip("set TEST_DATABASE_URL to run database tests")
    from database import SessionLocal
    with SessionLocal() as session:
        session.execute(text(
            "TRUNCATE audit_logs, consent_requests, policies, agents, users RESTART IDENTITY CASCADE"
        ))
        session.commit()


@pytest.fixture
def db(clean_db):
    from database import SessionLocal
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client(clean_db, tokens):
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


@pytest.fixture
def make_user(db):
    from models.tables import User

    def _make(sub: str, email: str) -> SimpleNamespace:
        user = User(monocloud_user_id=sub, email=email)
        db.add(user)
        db.commit()
        return SimpleNamespace(id=user.id, sub=sub, email=email)
    return _make


@pytest.fixture
def make_agent(db):
    from models.tables import Agent

    def _make(owner, name: str, client_id: str) -> SimpleNamespace:
        agent = Agent(name=name, monocloud_client_id=client_id, owner_id=owner.id)
        db.add(agent)
        db.commit()
        return SimpleNamespace(id=agent.id, name=name, client_id=client_id, owner_id=owner.id)
    return _make


@pytest.fixture
def set_policy(db):
    from models.tables import Policy

    def _set(agent, endpoints=(), methods=(), days=(), start=None, end=None) -> None:
        db.query(Policy).filter(Policy.agent_id == agent.id).delete()
        db.add(Policy(
            agent_id=agent.id, allowed_endpoints=list(endpoints), allowed_methods=list(methods),
            allowed_days=list(days), time_window_start=start, time_window_end=end,
        ))
        db.commit()
    return _set


@pytest.fixture
def world(make_user, make_agent, set_policy):
    """Alice owns agent1 (with an allow-all policy); Bob owns agent2 (no policy)."""
    alice = make_user("sub-alice", "alice@example.com")
    bob = make_user("sub-bob", "bob@example.com")
    agent1 = make_agent(alice, "order-bot", "client-1")
    agent2 = make_agent(bob, "bobs-bot", "client-2")
    set_policy(agent1)
    return SimpleNamespace(alice=alice, bob=bob, agent1=agent1, agent2=agent2)


@pytest.fixture
def audit_actions(db):
    """Callable returning every audit action so far, oldest first."""
    from models.tables import AuditLog

    def _actions() -> list[str]:
        db.expire_all()
        return [row.action for row in db.query(AuditLog).order_by(AuditLog.timestamp).all()]
    return _actions


@pytest.fixture
def last_audit(db):
    from models.tables import AuditLog

    def _last():
        db.expire_all()
        return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
    return _last


@pytest.fixture
def exchange(client, tokens):
    """POST /auth/agent-token with sensible defaults; returns the response."""
    def _exchange(user_sub="sub-alice", email="alice@example.com", client_id="client-1", consent_id=None,
                  user_token=None, agent_token=None):
        body = {
            "monocloud_user_jwt": user_token or tokens.user(user_sub, email),
            "monocloud_agent_jwt": agent_token or tokens.agent(client_id),
            "monocloud_client_id": client_id,
        }
        if consent_id is not None:
            body["consent_id"] = str(consent_id)
        return client.post("/auth/agent-token", json=body)
    return _exchange
