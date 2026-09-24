from datetime import datetime, time
from types import SimpleNamespace

from services.policy import IST, check_request, check_schedule, endpoint_matches, within_time_window


def policy(**kw):
    defaults = dict(allowed_endpoints=[], allowed_methods=[], allowed_days=[], time_window_start=None, time_window_end=None)
    return SimpleNamespace(**{**defaults, **kw})


def at(hour, minute=0, day=1):
    """An IST datetime. 2026-06-01 is a Monday."""
    return datetime(2026, 6, day, hour, minute, tzinfo=IST)


class TestEndpointMatching:
    def test_exact(self):
        assert endpoint_matches("/api/orders", ["/api/orders"])
        assert not endpoint_matches("/api/orders/1", ["/api/orders"])

    def test_wildcard_is_a_prefix_match(self):
        assert endpoint_matches("/api/orders/123", ["/api/orders/*"])
        assert endpoint_matches("/api/orders/123/items", ["/api/orders/*"])

    def test_wildcard_does_not_match_parent_or_lookalike(self):
        assert not endpoint_matches("/api/orders", ["/api/orders/*"])
        assert not endpoint_matches("/api/ordersX/1", ["/api/orders/*"])

    def test_any_pattern_may_match(self):
        assert endpoint_matches("/b", ["/a", "/b"])
        assert not endpoint_matches("/c", ["/a", "/b"])


class TestTimeWindow:
    def test_daytime_window_is_inclusive(self):
        assert within_time_window(time(9), time(18), time(9, 0))
        assert within_time_window(time(9), time(18), time(18, 0))
        assert not within_time_window(time(9), time(18), time(18, 1))
        assert not within_time_window(time(9), time(18), time(8, 59))

    def test_window_crossing_midnight(self):
        for t in (time(22), time(23, 30), time(0), time(5, 59), time(6)):
            assert within_time_window(time(22), time(6), t)
        for t in (time(6, 1), time(12), time(21, 59)):
            assert not within_time_window(time(22), time(6), t)


class TestSchedule:
    def test_missing_policy_is_denied(self):
        assert check_schedule(None) == "rejected_no_policy"

    def test_empty_policy_allows_any_time(self):
        assert check_schedule(policy(), at(3)) is None

    def test_time_window(self):
        p = policy(time_window_start=time(9), time_window_end=time(18))
        assert check_schedule(p, at(12)) is None
        assert check_schedule(p, at(20)) == "rejected_time_window"

    def test_time_window_uses_ist_whatever_the_input_zone(self):
        from zoneinfo import ZoneInfo
        p = policy(time_window_start=time(9), time_window_end=time(18))
        # 04:30 UTC is 10:00 IST
        assert check_schedule(p, datetime(2026, 6, 1, 4, 30, tzinfo=ZoneInfo("UTC"))) is None
        # 12:30 UTC is 18:00 IST (edge), 13:00 UTC is 18:30 IST
        assert check_schedule(p, datetime(2026, 6, 1, 13, 0, tzinfo=ZoneInfo("UTC"))) == "rejected_time_window"

    def test_days_are_case_insensitive(self):
        p = policy(allowed_days=["Monday"])
        assert check_schedule(p, at(12, day=1)) is None          # Monday
        assert check_schedule(p, at(12, day=2)) == "rejected_day"  # Tuesday

    def test_a_half_set_window_is_ignored(self):
        assert check_schedule(policy(time_window_start=time(9)), at(23)) is None


class TestRequest:
    def test_missing_policy_is_denied(self):
        assert check_request(None, "/a", "GET") == "rejected_no_policy"

    def test_empty_lists_mean_no_restriction(self):
        assert check_request(policy(), "/anything", "DELETE", at(12)) is None

    def test_endpoint_then_method_then_schedule(self):
        p = policy(allowed_endpoints=["/a/*"], allowed_methods=["GET"], allowed_days=["monday"])
        assert check_request(p, "/a/1", "GET", at(12, day=1)) is None
        assert check_request(p, "/b", "GET", at(12, day=1)) == "rejected_endpoint"
        assert check_request(p, "/a/1", "POST", at(12, day=1)) == "rejected_method"
        assert check_request(p, "/a/1", "GET", at(12, day=2)) == "rejected_day"
