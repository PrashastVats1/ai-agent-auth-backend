"""The two JWT families must never be interchangeable."""
import os
import time

import jwt as pyjwt
import pytest

from services.delegation import EXPIRY_MINUTES, issue_agent_jwt, validate_agent_jwt
from services.monocloud import client_id_from_monocloud_claims, validate_monocloud_jwt


def delegation_jwt(**kw):
    args = dict(user_id="u1", user_email="a@example.com", agent_id="a1", agent_name="bot", scopes=["read"])
    return issue_agent_jwt(**{**args, **kw})


class TestMonocloudValidation:
    def test_valid_user_token(self, tokens):
        claims = validate_monocloud_jwt(tokens.user("sub-1", "a@example.com"))
        assert claims["sub"] == "sub-1"

    def test_valid_agent_token(self, tokens):
        assert client_id_from_monocloud_claims(validate_monocloud_jwt(tokens.agent("client-1"))) == "client-1"

    @pytest.mark.parametrize("overrides", [
        {"aud": "https://someone-else"},
        {"iss": "https://evil.test"},
    ])
    def test_wrong_audience_or_issuer(self, tokens, overrides):
        with pytest.raises(ValueError):
            validate_monocloud_jwt(tokens.user("sub-1", "a@example.com", **overrides))

    def test_expired(self, tokens):
        with pytest.raises(ValueError):
            validate_monocloud_jwt(tokens.user("sub-1", "a@example.com", expires_in=-60))

    def test_signed_by_an_unknown_key(self, tokens):
        with pytest.raises(ValueError):
            validate_monocloud_jwt(tokens.signed_by_other_key("sub-1"))

    def test_garbage(self, tokens):
        with pytest.raises(ValueError):
            validate_monocloud_jwt("not-a-jwt")

    def test_our_delegation_jwt_is_not_a_monocloud_token(self, tokens):
        with pytest.raises(ValueError):
            validate_monocloud_jwt(delegation_jwt())

    def test_client_id_falls_back_to_azp(self):
        assert client_id_from_monocloud_claims({"azp": "c"}) == "c"
        assert client_id_from_monocloud_claims({"client_id": "x", "azp": "c"}) == "x"
        assert client_id_from_monocloud_claims({"sub": "s"}) is None


class TestDelegationJwt:
    def test_carries_both_identities(self):
        claims = validate_agent_jwt(delegation_jwt(scopes=["read", "delete:orders"]))
        assert claims["user_id"] == "u1" and claims["user_email"] == "a@example.com"
        assert claims["agent_id"] == "a1" and claims["agent_name"] == "bot"
        assert claims["scopes"] == ["read", "delete:orders"]
        assert claims["token_type"] == "agent_delegation"

    def test_lifetime_is_at_most_30_minutes(self):
        claims = validate_agent_jwt(delegation_jwt())
        assert claims["exp"] - claims["iat"] <= 30 * 60
        assert EXPIRY_MINUTES <= 30

    def test_expired(self):
        expired = pyjwt.encode({"agent_id": "a1", "exp": int(time.time()) - 10}, os.environ["JWT_SECRET"], algorithm="HS256")
        with pytest.raises(ValueError, match="expired"):
            validate_agent_jwt(expired)

    def test_wrong_secret(self):
        forged = pyjwt.encode({"agent_id": "a1", "exp": int(time.time()) + 60}, "another-secret-" + "y" * 40, algorithm="HS256")
        with pytest.raises(ValueError):
            validate_agent_jwt(forged)

    def test_a_monocloud_token_is_not_a_delegation_jwt(self, tokens):
        with pytest.raises(ValueError):
            validate_agent_jwt(tokens.user("sub-1", "a@example.com"))

    def test_alg_none_is_rejected(self):
        unsigned = pyjwt.encode({"agent_id": "a1", "exp": int(time.time()) + 60}, None, algorithm="none")
        with pytest.raises(ValueError):
            validate_agent_jwt(unsigned)
