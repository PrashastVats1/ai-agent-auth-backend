from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, time
import uuid


# --- Auth ---

class AgentTokenRequest(BaseModel):
    monocloud_user_jwt: str
    monocloud_client_id: str

class AgentTokenResponse(BaseModel):
    agent_delegation_jwt: str
    expires_in: int  # seconds


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

class PolicyCreate(BaseModel):
    allowed_endpoints: list[str] = []
    allowed_methods: list[str] = []
    time_window_start: Optional[time] = None
    time_window_end: Optional[time] = None
    allowed_days: list[str] = []

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
