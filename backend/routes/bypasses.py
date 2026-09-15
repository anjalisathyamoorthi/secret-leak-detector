"""Bypass logging endpoints."""

import datetime
from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import AuditLog, User
from backend.schemas import BypassCreate, BypassResponse

router = APIRouter(prefix="/api/bypasses", tags=["bypasses"])


@router.post("", response_model=BypassResponse, status_code=status.HTTP_201_CREATED)
def log_bypass(bypass_in: BypassCreate, db: Session = Depends(get_db)):
    """Log a git commit --no-verify bypass event."""
    user = db.query(User).filter(User.email == bypass_in.user_email).first()
    if not user:
        user = User(name=bypass_in.user_email.split("@")[0], email=bypass_in.user_email, role="developer")
        db.add(user)
        db.commit()
        db.refresh(user)

    audit = AuditLog(
        user_id=user.id,
        action="bypass_commit",
        reason=f"Repo: {bypass_in.repository_name} | Reason: {bypass_in.reason}",
        created_at=bypass_in.timestamp or datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)

    return BypassResponse(
        id=audit.id,
        action=audit.action,
        reason=audit.reason,
        created_at=audit.created_at
    )


@router.get("", response_model=List[BypassResponse])
def list_bypasses(db: Session = Depends(get_db)):
    """List all bypass log entries."""
    logs = db.query(AuditLog).filter(AuditLog.action == "bypass_commit").order_by(AuditLog.id.desc()).all()
    return [
        BypassResponse(
            id=log.id,
            action=log.action,
            reason=log.reason,
            created_at=log.created_at
        ) for log in logs
    ]
