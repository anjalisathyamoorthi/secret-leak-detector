"""FastAPI application initialization and router assembly."""

import os
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database import engine, Base
from backend.routes import auth, repositories, scans, findings, metrics, bypasses

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secret Leak Detector API",
    description="Backend API for Secret Leak Detector compliance and audit tracking",
    version="1.0.0"
)

# Enable CORS for Streamlit dashboard and local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router)
app.include_router(repositories.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(metrics.router)
app.include_router(bypasses.router)


@app.get("/")
def root():
    return {
        "status": "healthy",
        "service": "Secret Leak Detector API",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
