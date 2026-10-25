"""Migration verification API routes for ScopeSentry-R.
"""
from __future__ import annotations

from fastapi import APIRouter
from app.migration.gate import MigrationGate
from app.migration.models import MigrationVerificationRequest, MigrationVerificationResponse


router = APIRouter(prefix="/migration", tags=["migration"])
_gate = MigrationGate()


@router.post("/verify", response_model=MigrationVerificationResponse)
def verify_migration_endpoint(req: MigrationVerificationRequest) -> MigrationVerificationResponse:
    """Verifies a credential migration safety using calibrated canary evidence and invariant witnesses."""
    return _gate.verify_migration(req)


@router.get("/verify", response_model=MigrationVerificationResponse)
def verify_migration_get_endpoint(
    provider: str = "mock_enterprise",
    version: str = "v1",
    scopes: str = "read:data",
    inject_fault: bool = False,
) -> MigrationVerificationResponse:
    """GET query alternative for migration verification with optional fault injection."""
    target_scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    req = MigrationVerificationRequest(
        provider=provider,
        provider_config_version=version,
        target_scopes=target_scopes,
        require_calibration=True,
    )
    forced_outcomes = None
    if inject_fault:
        forced_outcomes = {
            "parent": "revoked",
            "child": "invalidated",
            "sibling": "active",
            "replacement": "revoked",
        }
    return _gate.verify_migration(req, force_simulator_outcomes=forced_outcomes)
