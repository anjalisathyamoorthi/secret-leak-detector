"""Authentication endpoints."""

from fastapi import APIRouter, HTTPException, status
from backend.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    """Simple prototype authentication endpoint."""
    if request.username and request.password:
        return TokenResponse(
            access_token=f"fake-jwt-token-for-{request.username}",
            token_type="bearer"
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )
