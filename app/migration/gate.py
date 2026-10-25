"""Fail-closed, evidence-aware migration verification (local simulation PoC)."""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional
from app.canary.engine import build_canary_family
from app.calibration.engine import evaluate_calibration
from app.calibration.registry import FixtureRegistry, get_fixture_registry
from app.migration.models import MigrationDecision, MigrationVerificationRequest, MigrationVerificationResponse
from app.witness.generator import generate_calibration_witness, generate_canary_witness, generate_dependency_witness, generate_intent_witness
from app.witness.evaluator import evaluate_witness_bundle


class MigrationGate:
    def __init__(self, registry: Optional[FixtureRegistry] = None):
        self.registry = registry if registry is not None else get_fixture_registry()

    def _derive_simulator_outcomes(self, topology) -> Dict[str, str]:
        """Local structural model, NOT an observation of real OAuth provider behaviour.

        Only delegation edges imply a cascade in this deliberately narrow model.
        Parallel-authority and candidate-successor edges do not imply revocation.
        """
        invalid = {"parent"}
        changed = True
        while changed:
            before = len(invalid)
            invalid.update(e["to"] for e in topology.edges if e.get("type") == "delegation" and e.get("from") in invalid)
            changed = len(invalid) != before
        return {role: ("revoked" if role == "parent" else "invalidated" if role in invalid else "active") for role in topology.credentials}

    def verify_migration(self, request: MigrationVerificationRequest,
                         excessive_scopes: Optional[List[str]] = None,
                         force_simulator_outcomes: Optional[Dict[str, str]] = None) -> MigrationVerificationResponse:
        verification_id = f"mig-verif-{uuid.uuid4().hex[:8]}"
        topology = build_canary_family(request.provider, request.target_scopes, request.parent_scopes, request.sibling_scopes)
        outcomes = force_simulator_outcomes if force_simulator_outcomes is not None else self._derive_simulator_outcomes(topology)
        calibration = evaluate_calibration(request.provider, request.provider_config_version,
                                           topology.topology_hash, outcomes, registry=self.registry)
        fixture = self.registry.get(calibration.fixture_id) if calibration.fixture_id else None
        provenance = fixture.provenance if fixture else "unavailable"
        # A synthetic fixture is useful for validating algorithms, never a live-provider safety approval.
        independently_grounded = provenance in {"observed_test_tenant", "provider_documented"}
        scopes = excessive_scopes or []
        witnesses = [
            generate_intent_witness(scopes, not scopes),
            generate_dependency_witness([r for r, s in outcomes.items() if s == "active"],
                                        [r for r, s in outcomes.items() if s in ("revoked", "invalidated")]),
            generate_canary_witness(True, topology.family_id),
            generate_calibration_witness(calibration),
        ]
        # The original witness types remain stable for the existing dashboard/API.
        # Three-state results distinguish unresolved evidence from demonstrated violations.
        for w in witnesses:
            if w.witness_type == "intent_locked":
                w.status = "supported" if w.passed else "contradicted"
            elif w.witness_type == "dependency_preserved":
                # A simulated failure cannot alone establish actual provider behaviour.
                w.status = "supported" if w.passed and calibration.verdict == "calibrated" else "unknown"
            elif w.witness_type == "canary_validated":
                w.status = "supported" if w.passed else "unknown"
            else:
                w.status = "supported" if calibration.verdict == "calibrated" else "unknown"
            w.passed = w.status == "supported"
        bundle = evaluate_witness_bundle(witnesses)
        if any(w.status == "contradicted" for w in witnesses):
            decision: MigrationDecision = "rejected"
            explanation = "Migration rejected: a verified authorization-policy invariant was violated."
        elif calibration.verdict == "unsupported":
            decision = "indeterminate"
            explanation = (f"Migration cannot be verified: provider '{request.provider}' version "
                           f"'{request.provider_config_version}' lacks ground-truth calibration evidence.")
        elif calibration.verdict == "divergent":
            decision = "indeterminate"
            explanation = "Canary and reference observations disagree; actual provider behaviour is unresolved."
        elif not bundle.all_passed:
            decision = "indeterminate"
            explanation = "At least one mandatory dependency witness is unresolved."
        elif not independently_grounded:
            decision = "indeterminate"
            explanation = "Synthetic reference agrees with simulation, but independent provider evidence is absent; live migration is not approved."
        else:
            decision = "approved"
            explanation = "All modeled safety witnesses supported by applicable, non-synthetic reference evidence; subject to reference trust and scope limitations."
        return MigrationVerificationResponse(
            verification_id=verification_id, decision=decision, explanation=explanation,
            witness_bundle=bundle, calibration_result=calibration,
            canary_family_id=topology.family_id, topology_hash=topology.topology_hash,
            evidence_provenance=provenance,
        )
