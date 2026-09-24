import pytest
from pydantic import ValidationError

from models.schemas import PolicyCreate


def test_normalises_input():
    p = PolicyCreate(
        allowed_endpoints=[" /a/* ", ""], allowed_methods=["get", "Post"], allowed_days=["Monday", " FRIDAY "],
        time_window_start="22:00", time_window_end="06:00",
    )
    assert p.allowed_endpoints == ["/a/*"]
    assert p.allowed_methods == ["GET", "POST"]
    assert p.allowed_days == ["monday", "friday"]


def test_all_empty_is_valid():
    p = PolicyCreate()
    assert p.allowed_endpoints == [] and p.time_window_start is None


@pytest.mark.parametrize("kwargs", [
    {"allowed_endpoints": ["api/orders"]},            # no leading slash
    {"allowed_endpoints": ["/a/*/b"]},                # wildcard not at the end
    {"allowed_methods": ["FETCH"]},
    {"allowed_days": ["funday"]},
    {"time_window_start": "09:00"},                   # only one bound
    {"time_window_end": "09:00"},
    {"time_window_start": "09:00", "time_window_end": "09:00"},
    {"time_window_start": "25:00", "time_window_end": "26:00"},
])
def test_rejects_bad_input(kwargs):
    with pytest.raises(ValidationError):
        PolicyCreate(**kwargs)
