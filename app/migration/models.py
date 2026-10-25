"""Migration gate models and schemas for ScopeSentry-R.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from app.calibration.models import CalibrationResult
from app.witness.models import WitnessBundle


MigrationDecision = Literal["approved", "rejected", "indeterminate"]


class MigrationVerificationRequest(BaseModel):
    """Request to verify an OAuth migration using calibrated canary evidence."""
    provider: str
    target_scopes: List[str]
    parent_scopes: Optional[List[str]] = None
    sibling_scopes: Optional[List[str]] = None
    provider_config_version: str = "v1"
    contract_id: Optional[str] = None
    require_calibration: bool = True


class MigrationVerificationResponse(BaseModel):
    """Response containing migration verification decision, witness bundle, and audit hashes."""
    verification_id: str
    decision: MigrationDecision
    explanation: str
    witness_bundle: WitnessBundle
    calibration_result: Optional[CalibrationResult] = None
    canary_family_id: str
    topology_hash: str
    evidence_provenance: str = "unavailable"
    recorded_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
