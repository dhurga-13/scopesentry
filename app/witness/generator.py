"""Invariant witness generation for ScopeSentry-R.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List
from app.calibration.models import CalibrationResult
from app.witness.models import InvariantWitness, WitnessBundle, WitnessType


def _make_digest(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_intent_witness(
    excessive_scopes: List[str],
    intent_valid: bool,
) -> InvariantWitness:
    passed = intent_valid and len(excessive_scopes) == 0
    payload = {
        "type": "intent_locked",
        "excessive_scopes": sorted(excessive_scopes),
        "intent_valid": intent_valid,
    }
    return InvariantWitness(
        witness_id=f"wit-intent-{uuid.uuid4().hex[:8]}",
        witness_type="intent_locked",
        description="Verifies that no excessive scopes beyond user intent are requested",
        passed=passed,
        evidence_digest=_make_digest(payload),
        details=payload,
    )


def generate_dependency_witness(
    surviving_roles: List[str],
    invalidated_roles: List[str],
    expected_replacement_alive: bool = True,
) -> InvariantWitness:
    replacement_survived = "replacement" in surviving_roles
    passed = replacement_survived == expected_replacement_alive
    payload = {
        "type": "dependency_preserved",
        "surviving_roles": sorted(surviving_roles),
        "invalidated_roles": sorted(invalidated_roles),
        "replacement_survived": replacement_survived,
    }
    return InvariantWitness(
        witness_id=f"wit-dep-{uuid.uuid4().hex[:8]}",
        witness_type="dependency_preserved",
        description="Verifies candidate replacement survives parent identity revocation",
        passed=passed,
        evidence_digest=_make_digest(payload),
        details=payload,
    )


def generate_canary_witness(
    experiment_success: bool,
    experiment_id: str,
) -> InvariantWitness:
    payload = {
        "type": "canary_validated",
        "experiment_id": experiment_id,
        "experiment_success": experiment_success,
    }
    return InvariantWitness(
        witness_id=f"wit-canary-{uuid.uuid4().hex[:8]}",
        witness_type="canary_validated",
        description="Verifies synthetic canary family execution executed successfully",
        passed=experiment_success,
        evidence_digest=_make_digest(payload),
        details=payload,
    )


def generate_calibration_witness(
    calibration_result: CalibrationResult,
) -> InvariantWitness:
    passed = calibration_result.verdict == "calibrated"
    payload = {
        "type": "evidence_calibrated",
        "verdict": calibration_result.verdict,
        "confidence": calibration_result.confidence,
        "fixture_id": calibration_result.fixture_id,
        "discrepancies": calibration_result.discrepancies,
    }
    return InvariantWitness(
        witness_id=f"wit-calib-{uuid.uuid4().hex[:8]}",
        witness_type="evidence_calibrated",
        description="Verifies simulator matches empirical provider ground-truth calibration",
        passed=passed,
        evidence_digest=_make_digest(payload),
        details=payload,
    )
