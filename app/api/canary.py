"""Canary experiment API routes for ScopeSentry-R.
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel
from app.canary.engine import build_canary_family
from app.canary.models import CanaryTopology


router = APIRouter(prefix="/canary", tags=["canary"])


class CanaryExperimentRequest(BaseModel):
    provider: str
    target_scopes: List[str]
    parent_scopes: Optional[List[str]] = None
    sibling_scopes: Optional[List[str]] = None


@router.post("/experiment", response_model=CanaryTopology)
def run_canary_experiment(req: CanaryExperimentRequest) -> CanaryTopology:
    """Builds a dependency-equivalent canary credential family with deterministic topology hashing."""
    return build_canary_family(
        provider=req.provider,
        target_scopes=req.target_scopes,
        parent_scopes=req.parent_scopes,
        sibling_scopes=req.sibling_scopes,
    )


@router.get("/experiment", response_model=CanaryTopology)
def run_canary_experiment_get(
    provider: str = "mock_enterprise",
    scopes: str = "read:data",
) -> CanaryTopology:
    """GET query alternative for canary experiment."""
    target_scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    return build_canary_family(
        provider=provider,
        target_scopes=target_scopes,
    )
