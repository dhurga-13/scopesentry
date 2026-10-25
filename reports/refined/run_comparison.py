"""Reproducible *synthetic* comparison, not evidence of real OAuth-provider safety.
Run from project root: python reports/refined/run_comparison.py
"""
import csv
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from app.migration.gate import MigrationGate
from app.migration.models import MigrationVerificationRequest

GATE = MigrationGate()
GOOD = {"parent":"revoked", "child":"invalidated", "sibling":"active", "replacement":"active"}
BAD = {**GOOD, "replacement":"revoked"}
CASES = [
    ("matching_synthetic", "v1", GOOD, []),
    ("contradictory_simulator", "v1", BAD, []),
    ("missing_reference", "v404", GOOD, []),
    ("excess_authority", "v1", GOOD, ["admin:all"]),
]
rows=[]
for label, version, outcome, excess in CASES:
    req=MigrationVerificationRequest(provider="mock_enterprise",target_scopes=["read:data"],provider_config_version=version)
    # Uncalibrated structural baseline: only checks predicted replacement survival and scopes.
    baseline="approved" if outcome["replacement"]=="active" and not excess else "rejected"
    refined=GATE.verify_migration(req,excessive_scopes=excess,force_simulator_outcomes=outcome)
    rows.append({"case":label,"baseline_decision":baseline,"refined_decision":refined.decision,
                 "calibration":refined.calibration_result.verdict,"provenance":refined.evidence_provenance})
path=Path('reports/refined/synthetic_comparison.csv')
with path.open('w',newline='',encoding='utf-8') as f:
    writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
print(path)
for row in rows:print(row)
