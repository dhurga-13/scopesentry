"""Calibration models and schemas for ScopeSentry-R.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


CalibrationVerdict = Literal["calibrated", "miscalibrated", "unsupported", "divergent"]


class ProviderGroundTruthFixture(BaseModel):
    """Recorded, cryptographically verifiable ground truth of provider revocation behavior."""
    fixture_id: str
    provider: str
    provider_config_version: str
    recorded_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    topology_hash: str
    revoked_role: str
    expected_surviving_roles: List[str]
    expected_invalidated_roles: List[str]
    propagation_delay_ms: int = 0
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: Literal["synthetic_reference", "provider_documented", "observed_test_tenant"] = "synthetic_reference"
    signature: str = ""

    def compute_signature(self) -> str:
        """Computes deterministic digest of the fixture contents."""
        payload = {
            "fixture_id": self.fixture_id,
            "provider": self.provider,
            "provider_config_version": self.provider_config_version,
            "topology_hash": self.topology_hash,
            "revoked_role": self.revoked_role,
            "expected_surviving_roles": sorted(self.expected_surviving_roles),
            "expected_invalidated_roles": sorted(self.expected_invalidated_roles),
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CalibrationResult(BaseModel):
    """Evaluation result comparing simulated canary results against ground truth."""
    calibration_id: str
    provider: str
    provider_config_version: str
    verdict: CalibrationVerdict
    confidence: float
    discrepancies: List[str] = Field(default_factory=list)
    fixture_id: Optional[str] = None
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
