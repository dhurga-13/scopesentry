# ScopeSentry-R refined migration verification: research notes

This is a **local simulation proof of concept**, not an independent provider validation or proof of patent novelty.

## Changes
- Structural revocation model follows explicit `delegation` edges; other edge types do not imply cascading revocation.
- Calibration disagreements yield `indeterminate`, not `rejected` by default.
- Witnesses expose `supported`, `contradicted`, or `unknown` while retaining legacy `passed` for dashboard compatibility.
- Fixtures have a provenance field. Bundled fixtures are explicitly `synthetic_reference` and cannot authorize live migrations.
- `evidence_provenance` appears in migration API responses.

## How to verify

```bash
python -m pytest -q tests/test_migration_gate.py tests/test_refined_migration.py
python reports/refined/run_comparison.py
```

The comparison CSV is **illustrative synthetic data**; it measures decision behaviour on selected fixtures, not false-safe rates on real OAuth providers. `observed_test_tenant` fixture provenance is only metadata; the registry does not independently authenticate that claim. Any actual provider-safety claims require authenticated test-tenant observations, configuration matching, freshness, operation-continuity tests and a trusted evidence ingestion mechanism. A declared provenance label alone is not proof.

## Remaining work before a research-paper claim

1. Add explicit mandatory operation-continuity, authorization independence, child invalidation, and propagation-time witnesses (currently the four legacy witness types remain).
2. Enforce evidence freshness and cryptographically verified provenance, not just a provenance label.
3. Validate topology equivalence beyond a four-role structural hash (including scopes and configuration).
4. Add fault-injection scenarios, baseline comparisons, repeated latency trials, and statistical summaries.
5. Avoid calling hash-chain files immutable; tamper detection needs a protected external checkpoint.
6. Treat all current approvals as **modeled** decisions, not authorization to perform real provider migration.

## Research-paper integrity

Do not describe the bundled synthetic fixtures as empirical ground truth, or this toy comparison as a measured production false-safe approval rate. The `confidence_score` fixture value is user-supplied, not a statistically calibrated probability.
