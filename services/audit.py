from models.tables import AuditLog


def add_audit_log(
    db,
    *,
    agent_id,
    user_id,
    endpoint: str,
    method: str,
    action: str,
    consent_required: bool = False,
    consent_given: bool | None = None,
) -> None:
    """Stage an audit row on the session. The caller commits, so the entry lands
    in the same transaction as the change it describes."""
    db.add(AuditLog(
        agent_id=agent_id,
        user_id=user_id,
        endpoint=endpoint,
        method=method,
        action=action,
        consent_required=consent_required,
        consent_given=consent_given,
    ))
