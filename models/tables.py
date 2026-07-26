import uuid
from datetime import datetime, time
from sqlalchemy import (
    Column, String, Text, Boolean, DateTime, Time, ForeignKey, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(Text, nullable=False, unique=True)
    monocloud_user_id = Column(Text, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    agents = relationship("Agent", back_populates="owner", cascade="all, delete")
    consent_requests = relationship("ConsentRequest", back_populates="user")


class Agent(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    monocloud_client_id = Column(Text, nullable=False, unique=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    owner = relationship("User", back_populates="agents")
    policy = relationship("Policy", back_populates="agent", uselist=False, cascade="all, delete")
    consent_requests = relationship("ConsentRequest", back_populates="agent")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, unique=True)
    allowed_endpoints = Column(ARRAY(Text), nullable=False, default=list)
    allowed_methods = Column(ARRAY(Text), nullable=False, default=list)
    time_window_start = Column(Time, nullable=True)
    time_window_end = Column(Time, nullable=True)
    allowed_days = Column(ARRAY(Text), nullable=False, default=list)

    agent = relationship("Agent", back_populates="policy")


class ConsentRequest(Base):
    __tablename__ = "consent_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scope = Column(Text, nullable=False)
    status = Column(Text, nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    agent = relationship("Agent", back_populates="consent_requests")
    user = relationship("User", back_populates="consent_requests")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    endpoint = Column(Text, nullable=False)
    method = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow)
    consent_required = Column(Boolean, nullable=False, default=False)
    consent_given = Column(Boolean, nullable=True)
