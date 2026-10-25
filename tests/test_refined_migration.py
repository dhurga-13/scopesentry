"""Regression cases for evidence provenance, mismatch and witness decisions."""
from pathlib import Path
from app.calibration.models import ProviderGroundTruthFixture
from app.calibration.registry import FixtureRegistry
from app.migration.gate import MigrationGate
from app.migration.models import MigrationVerificationRequest


def request(version="v1"):
    return MigrationVerificationRequest(provider="mock_enterprise", target_scopes=["read:data"], provider_config_version=version)


def test_synthetic_match_not_live_approved():
    r = MigrationGate().verify_migration(request())
    assert r.decision == "indeterminate"
    assert r.calibration_result.verdict == "calibrated"
    assert r.witness_bundle.all_passed


def test_reference_disagreement_withholds_approval():
    r = MigrationGate().verify_migration(request(), force_simulator_outcomes={"parent":"revoked", "child":"invalidated", "sibling":"active", "replacement":"revoked"})
    assert r.decision == "indeterminate"
    assert r.calibration_result.verdict == "divergent"
    assert any(w.status == "unknown" for w in r.witness_bundle.witnesses)


def test_missing_version_withholds_approval():
    assert MigrationGate().verify_migration(request("v404")).decision == "indeterminate"


def test_excess_scopes_are_rejected():
    r = MigrationGate().verify_migration(request(), excessive_scopes=["admin:all"])
    assert r.decision == "rejected"
    assert any(w.status == "contradicted" for w in r.witness_bundle.witnesses)


def test_structural_delegation_cascade():
    from app.canary.engine import build_canary_family
    gate = MigrationGate()
    topo = build_canary_family("mock_enterprise", ["read:data"])
    topo.edges.append({"from":"child", "to":"sibling", "type":"delegation"})
    result = gate._derive_simulator_outcomes(topo)
    assert result["sibling"] == "invalidated"
    assert result["replacement"] == "active"


def test_independent_reference_allows_modeled_approval(tmp_path: Path):
    reg = FixtureRegistry(fixtures_dir=tmp_path)
    fixture = ProviderGroundTruthFixture(fixture_id="test-tenant-reference", provider="mock_enterprise",
        provider_config_version="v1", topology_hash="__placeholder__", revoked_role="parent",
        expected_surviving_roles=["sibling","replacement"], expected_invalidated_roles=["child"],
        provenance="observed_test_tenant")
    reg.register(fixture)
    r = MigrationGate(reg).verify_migration(request())
    assert r.decision == "approved"
    assert r.evidence_provenance == "observed_test_tenant"
