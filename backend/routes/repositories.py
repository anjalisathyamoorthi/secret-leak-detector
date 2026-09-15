"""Repository management endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Repository
from backend.schemas import RepositoryCreate, RepositoryResponse

router = APIRouter(prefix="/api/repositories", tags=["repositories"])


@router.post("", response_model=RepositoryResponse)
def create_repository(repo: RepositoryCreate, db: Session = Depends(get_db)):
    """Register or return an existing repository."""
    existing = db.query(Repository).filter(Repository.name == repo.name).first()
    if existing:
        return existing
    db_repo = Repository(
        name=repo.name,
        owner=repo.owner,
        provider=repo.provider,
        compliance_status="compliant"
    )
    db.add(db_repo)
    db.commit()
    db.refresh(db_repo)
    return db_repo


@router.get("", response_model=List[RepositoryResponse])
def list_repositories(db: Session = Depends(get_db)):
    """List all registered repositories."""
    return db.query(Repository).all()
