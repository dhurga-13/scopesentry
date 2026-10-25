"""Tests for ScopeSentry-R MigrationGate, Canary and Calibration.
"""
from fastapi.testclient import TestClient
from app.main import app
from app.migration.gate import MigrationGate
from app.migration.models import MigrationVerificationRequest
from app.canary.engine import build_canary_family
from app.calibration.registry import get_fixture_registry


client = TestClient(app)


def test_case_1_synthetic_agreement_does_not_authorize_live_migration():
    """Case 1: Standard supported provider with matching calibration fixture -> approved."""
    req = {
        "provider": "mock_enterprise",
        "target_scopes": ["read:data"],
        "provider_config_version": "v1",
        "require_calibration": True,
    }
    response = client.post("/migration/verify", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "indeterminate"
    assert data["evidence_provenance"] == "synthetic_reference"
    assert data["witness_bundle"]["all_passed"] is True
    assert len(data["witness_bundle"]["witnesses"]) == 4
    assert data["calibration_result"]["verdict"] == "calibrated"


def test_case_2_unsupported_provider_indeterminate():
    """Case 2: Unknown provider version without ground-truth fixture -> indeterminate."""
    req = {
        "provider": "mock_enterprise",
        "target_scopes": ["read:data"],
        "provider_config_version": "v99_nonexistent",
        "require_calibration": True,
    }
    response = client.post("/migration/verify", json=req)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "indeterminate"
    assert "lacks ground-truth calibration evidence" in data["explanation"]
    assert data["calibration_result"]["verdict"] == "unsupported"


def test_case_3_divergent_behavior_indeterminate():
    """Case 3: Simulator conflicts with ground-truth fixture -> rejected."""
    gate = MigrationGate()
    # Force replacement to be revoked unexpectedly
    conflicting_outcomes = {
        "parent": "revoked",
        "child": "invalidated",
        "sibling": "active",
        "replacement": "revoked",  # Divergence: replacement expected to survive
    }
    req = MigrationVerificationRequest(
        provider="mock_enterprise",
        target_scopes=["read:data"],
        provider_config_version="v1",
    )
    result = gate.verify_migration(req, force_simulator_outcomes=conflicting_outcomes)
    assert result.decision == "indeterminate"
    assert result.calibration_result.verdict == "divergent"
    assert result.witness_bundle.all_passed is False


def test_case_4_excessive_scopes_rejected():
    """Case 4: Intent violation (excessive scopes detected) -> rejected."""
    gate = MigrationGate()
    req = MigrationVerificationRequest(
        provider="mock_enterprise",
        target_scopes=["read:data"],
        provider_config_version="v1",
    )
    result = gate.verify_migration(req, excessive_scopes=["admin:all", "write:billing"])
    assert result.decision == "rejected"
    # Find intent witness
    intent_wit = next(w for w in result.witness_bundle.witnesses if w.witness_type == "intent_locked")
    assert intent_wit.passed is False


def test_case_5_deterministic_hashes_and_signatures():
    """Case 5: Canary topology hashes and fixture signatures are deterministic."""
    f1 = build_canary_family("mock_enterprise", ["read:data"])
    f2 = build_canary_family("mock_enterprise", ["read:data"])
    assert f1.topology_hash == f2.topology_hash
    assert len(f1.topology_hash) == 64

    registry = get_fixture_registry()
    fixture = registry.get("gt-mock-enterprise-v1")
    assert fixture is not None
    sig = fixture.compute_signature()
    assert sig == fixture.signature


def test_case_6_canary_experiment_endpoint():
    """Case 6: Direct canary experiment endpoint creates 4 distinct roles."""
    req = {
        "provider": "mock_code_host",
        "target_scopes": ["repo:read"],
    }
    response = client.post("/canary/experiment", json=req)
    assert response.status_code == 200
    data = response.json()
    assert "family_id" in data
    assert "credentials" in data
    roles = {c["role"] for c in data["credentials"].values()}
    assert roles == {"parent", "child", "sibling", "replacement"}
    assert len(data["topology_hash"]) == 64
