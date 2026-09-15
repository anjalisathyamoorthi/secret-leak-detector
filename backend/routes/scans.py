"""Scan submission and retrieval endpoints."""

import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Repository, Scan, Finding
from backend.schemas import ScanCreate, ScanResponse

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def submit_scan(scan_in: ScanCreate, db: Session = Depends(get_db)):
    """Submit scan results from CLI or pre-commit hook."""
    # 1. Get or create Repository
    repo = db.query(Repository).filter(Repository.name == scan_in.repository_name).first()
    if not repo:
        repo = Repository(
            name=scan_in.repository_name,
            owner="team",
            provider="github",
            compliance_status="compliant"
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)

    now = datetime.datetime.utcnow()
    repo.last_scan_at = now

    # 2. Create Scan record
    db_scan = Scan(
        repository_id=repo.id,
        scan_type=scan_in.scan_type,
        files_scanned=scan_in.files_scanned,
        findings_count=len(scan_in.findings),
        started_at=now,
        completed_at=now
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 3. Create Findings records
    has_high_or_critical = False
    for f in scan_in.findings:
        if f.severity.lower() in ["high", "critical"]:
            has_high_or_critical = True

        db_finding = Finding(
            scan_id=db_scan.id,
            rule_id=f.rule_id,
            file_path=f.file_path,
            line_number=f.line_number,
            severity=f.severity.lower(),
            masked_value=f.masked_value,
            fingerprint=f.fingerprint,
            status="open",
            created_at=now
        )
        db.add(db_finding)

    # Update repo compliance status based on findings
    if has_high_or_critical:
        repo.compliance_status = "non-compliant"
    else:
        # Check if there are remaining open high/critical findings across repo
        open_critical = db.query(Finding).join(Scan).filter(
            Scan.repository_id == repo.id,
            Finding.status == "open",
            Finding.severity.in_(["high", "critical"])
        ).count()
        if open_critical == 0:
            repo.compliance_status = "compliant"

    db.commit()
    db.refresh(db_scan)
    return db_scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """List all scans."""
    return db.query(Scan).all()
