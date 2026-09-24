from pydantic import BaseModel, EmailStr, field_validator, model_validator
from typing import Optional
from datetime import datetime, time
import uuid


# --- Auth ---

class AgentTokenRequest(BaseModel):
    monocloud_user_jwt: str   # the human's MonoCloud access token
    monocloud_agent_jwt: str  # the agent's own MonoCloud M2M access token (client credentials)
    monocloud_client_id: str
    consent_id: Optional[uuid.UUID] = None  # an approved consent to redeem for its destructive scope

class AgentTokenResponse(BaseModel):
    agent_delegation_jwt: str
    expires_in: int  # seconds
    scopes: list[str]


# --- Users ---

class UserSync(BaseModel):
    email: str
    monocloud_user_id: str

class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    monocloud_user_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Agents ---

class AgentCreate(BaseModel):
    name: str
    monocloud_client_id: str

class AgentOut(BaseModel):
    id: uuid.UUID
    name: str
    monocloud_client_id: str
    owner_id: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Policies ---

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
WEEKDAYS = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}


class PolicyCreate(BaseModel):
    allowed_endpoints: list[str] = []  # exact paths, or a prefix ending in "*" (e.g. "/api/orders/*")
    allowed_methods: list[str] = []
    time_window_start: Optional[time] = None  # IST; start > end means the window crosses midnight
    time_window_end: Optional[time] = None
    allowed_days: list[str] = []

    @field_validator("allowed_endpoints")
    @classmethod
    def _endpoints(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip() for v in values if v.strip()]
        for v in cleaned:
            if not v.startswith("/"):
                raise ValueError(f"endpoint '{v}' must start with '/'")
            if "*" in v[:-1]:
                raise ValueError(f"endpoint '{v}': '*' is only allowed at the end")
        return cleaned

    @field_validator("allowed_methods")
    @classmethod
    def _methods(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().upper() for v in values if v.strip()]
        bad = [v for v in cleaned if v not in HTTP_METHODS]
        if bad:
            raise ValueError(f"unknown HTTP method(s): {', '.join(bad)}")
        return cleaned

    @field_validator("allowed_days")
    @classmethod
    def _days(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().lower() for v in values if v.strip()]
        bad = [v for v in cleaned if v not in WEEKDAYS]
        if bad:
            raise ValueError(f"unknown day(s): {', '.join(bad)} (use monday..sunday)")
        return cleaned

    @model_validator(mode="after")
    def _time_window(self):
        start, end = self.time_window_start, self.time_window_end
        if (start is None) != (end is None):
            raise ValueError("set both time_window_start and time_window_end, or neither")
        if start is not None and start == end:
            raise ValueError("time window start and end must differ")
        return self

class PolicyOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    allowed_endpoints: list[str]
    allowed_methods: list[str]
    time_window_start: Optional[time]
    time_window_end: Optional[time]
    allowed_days: list[str]

    model_config = {"from_attributes": True}


# --- Consent ---

class ConsentRequestCreate(BaseModel):
    monocloud_client_id: str
    scope: str  # e.g. "delete:orders"

class ConsentStatusOut(BaseModel):
    id: uuid.UUID
    status: str  # pending | approved | denied | expired
    scope: str
    created_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}

class ConsentApprove(BaseModel):
    consent_id: uuid.UUID
    approved: bool  # true = approve, false = deny


# --- Audit ---

class AuditLogOut(BaseModel):
    id: uuid.UUID
    agent_id: Optional[uuid.UUID]
    user_id: Optional[uuid.UUID]
    endpoint: str
    method: str
    action: str
    timestamp: datetime
    consent_required: bool
    consent_given: Optional[bool]

    model_config = {"from_attributes": True}
