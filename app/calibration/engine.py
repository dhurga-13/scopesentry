"""Calibration engine comparing simulator outcomes to ground truth.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional
from app.calibration.models import CalibrationResult, CalibrationVerdict, ProviderGroundTruthFixture
from app.calibration.registry import FixtureRegistry, get_fixture_registry


def evaluate_calibration(
    provider: str,
    provider_config_version: str,
    topology_hash: str,
    simulator_outcomes: Dict[str, str],
    revoked_role: str = "parent",
    registry: Optional[FixtureRegistry] = None,
) -> CalibrationResult:
    """Evaluates whether the simulator's predicted outcomes match ground truth.
    
    Returns:
      - calibrated: outcomes match fixture expectations perfectly
      - divergent: fixture exists but simulator outcomes conflict
      - unsupported: no ground-truth fixture found for provider/version
    """
    reg = registry or get_fixture_registry()
    fixture = reg.find_applicable(
        provider=provider,
        provider_config_version=provider_config_version,
        topology_hash=topology_hash,
        revoked_role=revoked_role,
    )

    calibration_id = f"calib-{uuid.uuid4().hex[:8]}"

    if fixture is None:
        return CalibrationResult(
            calibration_id=calibration_id,
            provider=provider,
            provider_config_version=provider_config_version,
            verdict="unsupported",
            confidence=0.0,
            discrepancies=["No ground-truth calibration fixture found for provider/version/topology"],
            fixture_id=None,
        )

    discrepancies: List[str] = []

    # Verify surviving roles
    for role in fixture.expected_surviving_roles:
        status = simulator_outcomes.get(role)
        if status != "active":
            discrepancies.append(
                f"Role '{role}' was expected to survive ('active') but is '{status}'"
            )

    # Verify invalidated roles
    for role in fixture.expected_invalidated_roles:
        status = simulator_outcomes.get(role)
        if status not in ("revoked", "invalidated"):
            discrepancies.append(
                f"Role '{role}' was expected to be invalidated but is '{status}'"
            )

    if not discrepancies:
        return CalibrationResult(
            calibration_id=calibration_id,
            provider=provider,
            provider_config_version=provider_config_version,
            verdict="calibrated",
            confidence=fixture.confidence_score,
            discrepancies=[],
            fixture_id=fixture.fixture_id,
        )
    else:
        return CalibrationResult(
            calibration_id=calibration_id,
            provider=provider,
            provider_config_version=provider_config_version,
            verdict="divergent",
            confidence=0.2,
            discrepancies=discrepancies,
            fixture_id=fixture.fixture_id,
        )
