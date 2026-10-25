"""Witness models and schemas for ScopeSentry-R.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


WitnessType = Literal[
    "intent_locked",
    "dependency_preserved",
    "canary_validated",
    "evidence_calibrated",
]


class InvariantWitness(BaseModel):
    """Cryptographic or deterministic witness verifying that a security invariant holds."""
    witness_id: str
    witness_type: WitnessType
    description: str
    passed: bool
    status: Literal["supported", "contradicted", "unknown"] = "unknown"
    evidence_digest: str
    details: Dict[str, Any] = Field(default_factory=dict)
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class WitnessBundle(BaseModel):
    """Aggregate set of invariant witnesses required for migration verification."""
    bundle_id: str
    witnesses: List[InvariantWitness]
    all_passed: bool
    bundle_digest: str = ""

    def compute_bundle_digest(self) -> str:
        """Computes deterministic digest over sorted witness digests."""
        sorted_digests = sorted([w.evidence_digest for w in self.witnesses])
        raw = json.dumps(sorted_digests)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
