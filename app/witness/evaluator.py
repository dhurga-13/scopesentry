"""Witness evaluator for ScopeSentry-R.
"""
from __future__ import annotations

import uuid
from typing import List
from app.witness.models import InvariantWitness, WitnessBundle


def evaluate_witness_bundle(witnesses: List[InvariantWitness]) -> WitnessBundle:
    """Combines individual witnesses into an evaluated WitnessBundle."""
    bundle_id = f"bundle-{uuid.uuid4().hex[:8]}"
    all_passed = all(w.status == "supported" for w in witnesses) and len(witnesses) > 0
    bundle = WitnessBundle(
        bundle_id=bundle_id,
        witnesses=witnesses,
        all_passed=all_passed,
    )
    bundle.bundle_digest = bundle.compute_bundle_digest()
    return bundle
