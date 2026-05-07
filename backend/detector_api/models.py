from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, Text
from sqlalchemy.sql import func

from detector_api.database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source = Column(String(64), nullable=False, default="nginx", index=True)
    ip = Column(String(128), nullable=False, index=True)
    method = Column(String(16), nullable=True)
    path = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    event_type = Column(String(64), nullable=False, default="http_access", index=True)
    raw_data = Column(JSON, nullable=False, default=dict)


class AuthEvent(Base):
    __tablename__ = "auth_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    ip = Column(String(128), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    success = Column(Boolean, nullable=False, default=False, index=True)
    reason = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=False, default=dict)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    alert_type = Column(String(128), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    ip = Column(String(128), nullable=True, index=True)
    path = Column(Text, nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False, default=dict)
    recommendation = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="open", index=True)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    alert_type = Column(String(128), nullable=False, index=True)
    severity = Column(String(16), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    description = Column(Text, nullable=False)
