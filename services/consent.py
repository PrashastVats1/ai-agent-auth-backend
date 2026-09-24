from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from models.tables import ConsentRequest
from services.audit import add_audit_log

CONSENT_EXPIRY_MINUTES = 5
CONSENT_REDEEM_MINUTES = 5  # an approval must be redeemed for a token within this long


def expire_stale_consents(db) -> None:
    """Flip any pending consent requests older than 5 minutes to 'expired'.

    Called at poll time (GET /consent/status/{id}) so no background thread
    is needed on the free Render tier. Each request that this call expires is
    written to the audit log; RETURNING means a request is only logged by the
    one caller whose UPDATE actually flipped it.
    """
    now = datetime.now(timezone.utc)
    expired = db.execute(
        update(ConsentRequest)
        .where(
            ConsentRequest.status == "pending",
            ConsentRequest.created_at < now - timedelta(minutes=CONSENT_EXPIRY_MINUTES),
        )
        .values(status="expired", resolved_at=now)
        .returning(ConsentRequest.agent_id, ConsentRequest.user_id)
        .execution_options(synchronize_session=False)
    ).all()
    for agent_id, user_id in expired:
        add_audit_log(
            db, agent_id=agent_id, user_id=user_id, endpoint="/consent/request", method="POST",
            action="consent_expired", consent_required=True, consent_given=False,
        )
    db.commit()


def is_destructive_scope(scope: str) -> bool:
    """Returns True if the requested scope requires user consent."""
    destructive_prefixes = ("delete:", "write:", "admin:")
    return any(scope.lower().startswith(p) for p in destructive_prefixes)


def redeem_consent(db, consent_id, user_id, agent_id) -> str | None:
    """Atomically consume an approved consent and return the scope it grants.

    Returns None if the consent doesn't exist, belongs to a different user or
    agent, isn't approved, was already redeemed, or was approved too long ago.
    The caller commits, so a failure after this call rolls the redemption back.
    """
    now = datetime.now(timezone.utc)
    redeemed = db.query(ConsentRequest).filter(
        ConsentRequest.id == consent_id,
        ConsentRequest.user_id == user_id,
        ConsentRequest.agent_id == agent_id,
        ConsentRequest.status == "approved",
        ConsentRequest.consumed_at.is_(None),
        ConsentRequest.resolved_at >= now - timedelta(minutes=CONSENT_REDEEM_MINUTES),
    ).update({"consumed_at": now}, synchronize_session=False)
    if redeemed != 1:
        return None
    return db.query(ConsentRequest.scope).filter(ConsentRequest.id == consent_id).scalar()
