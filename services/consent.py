from datetime import datetime, timedelta, timezone
from models.tables import ConsentRequest

CONSENT_EXPIRY_MINUTES = 5


def expire_stale_consents(db) -> None:
    """Flip any pending consent requests older than 5 minutes to 'expired'.

    Called at poll time (GET /consent/status/{id}) so no background thread
    is needed on the free Render tier.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=CONSENT_EXPIRY_MINUTES)
    db.query(ConsentRequest).filter(
        ConsentRequest.status == "pending",
        ConsentRequest.created_at < cutoff,
    ).update(
        {"status": "expired", "resolved_at": datetime.now(timezone.utc)},
        synchronize_session=False,
    )
    db.commit()


def is_destructive_scope(scope: str) -> bool:
    """Returns True if the requested scope requires user consent."""
    destructive_prefixes = ("delete:", "write:", "admin:")
    return any(scope.lower().startswith(p) for p in destructive_prefixes)
