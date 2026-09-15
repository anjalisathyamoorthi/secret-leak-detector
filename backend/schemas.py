"""Pydantic request and response schemas for validation."""

import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


# Auth Schemas
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# User Schemas
class UserBase(BaseModel):
    name: str
    email: str
    role: str = "developer"


class UserCreate(UserBase):
    pass


class UserResponse(UserBase):
    id: int
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# Repository Schemas
class RepositoryBase(BaseModel):
    name: str
    owner: str = "team"
    provider: str = "github"


class RepositoryCreate(RepositoryBase):
    pass


class RepositoryResponse(RepositoryBase):
    id: int
    last_scan_at: Optional[datetime.datetime] = None
    compliance_status: str = "compliant"

    class Config:
        from_attributes = True


# Finding Schemas
class FindingCreate(BaseModel):
    rule_id: str
    file_path: str
    line_number: int
    severity: str
    masked_value: str
    fingerprint: str
    description: Optional[str] = None
    recommendation: Optional[str] = None


class FindingUpdate(BaseModel):
    status: str  # open, resolved, false_positive
    reason: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    rule_id: str
    file_path: str
    line_number: int
    severity: str
    masked_value: str
    fingerprint: str
    status: str
    created_at: datetime.datetime
    resolved_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


# Scan Schemas
class ScanCreate(BaseModel):
    repository_name: str = "default-repo"
    scan_type: str = "pre-commit"
    files_scanned: int = 0
    findings: List[FindingCreate] = []


class ScanResponse(BaseModel):
    id: int
    repository_id: int
    scan_type: str
    files_scanned: int
    findings_count: int
    started_at: datetime.datetime
    completed_at: datetime.datetime
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True


# Bypass Schemas
class BypassCreate(BaseModel):
    user_email: str
    repository_name: str
    reason: str = "no reason provided"
    timestamp: Optional[datetime.datetime] = None


class BypassResponse(BaseModel):
    id: int
    action: str
    reason: Optional[str]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# Metric Response Schema
class MetricResponse(BaseModel):
    repositories_scanned: int
    total_scans: int
    open_findings: int
    critical_findings: int
    blocked_commits: int
    resolved_findings: int
    compliance_percentage: float
    bypasses_count: int
