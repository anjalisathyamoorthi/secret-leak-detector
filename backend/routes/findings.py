"""Finding management endpoints."""

import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Finding, Scan, Repository, AuditLog
from backend.schemas import FindingResponse, FindingUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=List[FindingResponse])
def list_findings(
    status: Optional[str] = Query(None, description="Filter by status (open/resolved/false_positive)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical/high/medium/low)"),
    repository_id: Optional[int] = Query(None, description="Filter by repository ID"),
    db: Session = Depends(get_db)
):
    """List findings with optional filters."""
    query = db.query(Finding)

    if repository_id is not None:
        query = query.join(Scan).filter(Scan.repository_id == repository_id)

    if status:
        query = query.filter(Finding.status == status.lower())

    if severity:
        query = query.filter(Finding.severity == severity.lower())

    return query.order_by(Finding.id.desc()).all()


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: int,
    update_in: FindingUpdate,
    db: Session = Depends(get_db)
):
    """Update finding status (open, resolved, false_positive)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    new_status = update_in.status.lower()
    if new_status not in ["open", "resolved", "false_positive"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'open', 'resolved', or 'false_positive'")

    finding.status = new_status
    if new_status in ["resolved", "false_positive"]:
        finding.resolved_at = datetime.datetime.utcnow()

    # Log audit entry
    audit = AuditLog(
        action=f"update_status_{new_status}",
        finding_id=finding.id,
        reason=update_in.reason or f"Updated status to {new_status}"
    )
    db.add(audit)

    # Re-check repository compliance
    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    if scan:
        repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
        if repo:
            remaining_open_critical = db.query(Finding).join(Scan).filter(
                Scan.repository_id == repo.id,
                Finding.status == "open",
                Finding.severity.in_(["high", "critical"])
            ).count()
            if remaining_open_critical == 0:
                repo.compliance_status = "compliant"
            else:
                repo.compliance_status = "non-compliant"

    db.commit()
    db.refresh(finding)
    return finding
