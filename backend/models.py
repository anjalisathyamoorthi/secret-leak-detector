"""SQLAlchemy models for database entities."""

import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    role = Column(String(50), default="developer")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    audit_logs = relationship("AuditLog", back_populates="user")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    owner = Column(String(100), default="team")
    provider = Column(String(50), default="github")
    last_scan_at = Column(DateTime, nullable=True)
    compliance_status = Column(String(50), default="compliant")

    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    scan_type = Column(String(50), default="pre-commit")  # pre-commit, cli, scheduled
    files_scanned = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, default=datetime.datetime.utcnow)

    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    rule_id = Column(String(100), nullable=False)
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    masked_value = Column(String(100), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)
    status = Column(String(50), default="open")  # open, resolved, false_positive
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    audit_logs = relationship("AuditLog", back_populates="finding")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # bypass_commit, resolve_finding, false_positive_finding
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")
    finding = relationship("Finding", back_populates="audit_logs")
