"""Metrics and reports endpoints."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import Repository, Scan, Finding, AuditLog
from backend.schemas import MetricResponse

router = APIRouter(tags=["metrics"])


@router.get("/api/metrics", response_model=MetricResponse)
def get_metrics(db: Session = Depends(get_db)):
    """Calculate aggregated metrics and compliance score."""
    repos_count = db.query(Repository).count()
    total_scans = db.query(Scan).count()

    open_findings = db.query(Finding).filter(Finding.status == "open").count()
    critical_findings = db.query(Finding).filter(
        Finding.status == "open",
        Finding.severity.in_(["critical", "high"])
    ).count()

    resolved_findings = db.query(Finding).filter(
        Finding.status.in_(["resolved", "false_positive"])
    ).count()

    # Blocked commits: scans that contained high or critical findings
    scans_with_threats = db.query(Scan.id).join(Finding).filter(
        Finding.severity.in_(["critical", "high"])
    ).distinct().count()

    clean_scans = total_scans - scans_with_threats
    if clean_scans < 0:
        clean_scans = 0

    compliance_pct = (clean_scans / total_scans * 100.0) if total_scans > 0 else 100.0

    bypasses_count = db.query(AuditLog).filter(
        AuditLog.action == "bypass_commit"
    ).count()

    return MetricResponse(
        repositories_scanned=repos_count,
        total_scans=total_scans,
        open_findings=open_findings,
        critical_findings=critical_findings,
        blocked_commits=scans_with_threats,
        resolved_findings=resolved_findings,
        compliance_percentage=round(compliance_pct, 1),
        bypasses_count=bypasses_count
    )


@router.get("/api/reports")
def get_reports_data(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Retrieve raw findings data suitable for report/CSV export."""
    results = db.query(
        Finding.id,
        Repository.name.label("repository"),
        Finding.file_path,
        Finding.line_number,
        Finding.rule_id,
        Finding.severity,
        Finding.masked_value,
        Finding.fingerprint,
        Finding.status,
        Finding.created_at,
        Finding.resolved_at
    ).join(Scan, Finding.scan_id == Scan.id)\
     .join(Repository, Scan.repository_id == Repository.id)\
     .order_by(Finding.id.desc()).all()

    report_list = []
    for r in results:
        report_list.append({
            "id": r.id,
            "repository": r.repository,
            "file_path": r.file_path,
            "line_number": r.line_number,
            "rule_id": r.rule_id,
            "severity": r.severity,
            "masked_value": r.masked_value,
            "fingerprint": r.fingerprint,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else "",
        })

    return report_list
