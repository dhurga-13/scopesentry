# ScopeSentry-R: Complete Demonstration Guide & Technical Novelty Reference

This document serves as your single comprehensive manual for presenting, demonstrating, and defending **ScopeSentry-R (Evidence-Calibrated Canary Revocation Twin with Intent-Locked Authorization)** before academic examiners, faculty panels, and reviewers.

---

## Executive Summary: The Technical Elevator Pitch (60 Seconds)

> *"Modern cloud security relies on OAuth 2.0, but OAuth 2.0 has two fundamental security flaws:  
> 1. **Excessive Authority:** Applications request broad access scopes (e.g., full Google Drive access) even when the user only intended to read a single file.  
> 2. **Zombie Tokens & Migration Hazards:** When organizations migrate or revoke old credentials, child or derived tokens often survive undetected due to cloud provider propagation desync, or conversely, candidate replacement tokens are accidentally killed.
>
> **ScopeSentry-R** solves both problems through a unified architecture:
> - **Intent-Locked Authorization (Tab 1):** Mathematically maps natural language user intent to minimal required capabilities, automatically calculates the exposure differential, and synthesizes a binding least-privilege contract.
> - **Evidence-Calibrated Canary Revocation Twin (Tab 2):** Synthesizes a disposable 4-role canary credential family (`parent`, `child`, `sibling`, `replacement`) to simulate revocation cascade in a sandbox, calibrated against empirical provider ground-truth fixtures.
> - **Cryptographic Audit Ledger (Tab 3):** Commits every authorization decision and witness bundle into an append-only, tamper-evident SHA-256 hash chain with active breach detection.
> - **TRL 4 Laboratory Validation (Tab 4):** Validated across 294 automated unit and integration tests with zero regressions."*

---

## Tab 1: ⚡ Interactive Permission Studio

### 1. What is the Novelty?
- **Intent-Conditioned Capability Synthesis (Prior Art vs. Our Novelty):**
  - *Prior Art (Standard OAuth 2.0):* Permissions are decoupled from intent. If an app requests `[drive.readonly, admin.directory.user]`, the user has only a binary choice: Allow All or Deny All. The identity provider has no semantic understanding of what the app is actually doing.
  - *Our Novelty:* ScopeSentry-R implements a **Directed Capability Graph ($\mathcal{G}$)**. It deconstructs natural language user intent into discrete atomic capabilities (`list_files`, `read_metadata`, `read_content`), computes the mathematical set difference:
    $$\Delta_{\text{exposure}} = \text{Capabilities}(\text{Requested Scopes}) \setminus \text{Capabilities}(\text{Declared Intent})$$
    and runs an **exhaustive subset evaluation algorithm** to discover the minimal scope cover, mathematically reducing the token attack surface (e.g., 50% risk reduction) before the token is ever minted.

### 2. Live Demo Steps
1. Navigate to **Tab 1: `⚡ 1. Interactive Permission Studio`**.
2. **Input Fields:**
   - **Declared Natural Language Intent:** `read files and view documents`
   - **Requested OAuth Scopes:** `drive.readonly, admin.directory.user`
3. Click **"Analyze Intent & Synthesize Contract"**.
4. **Point to Screen:**
   - **Status Badge:** Flashes red **`EXCESSIVE AUTHORITY`**.
   - **Excessive Scopes:** Explicitly flags `1: admin.directory.user` (Google Workspace user administration has no justification under file reading intent).
   - **Matched Scopes:** `1: drive.readonly`.
   - **Synthesized Least-Privilege Contract:** Displays:
     `Authorized Scope: drive.readonly (Risk reduced by 50.0%)`
5. **Interactive Examiner Challenge:**
   - Invite your professor: *"Sir/Ma'am, type any custom intent or pick any scope (e.g. `contacts.readonly`), and watch the capability graph re-compute the delta in real time."*

---

## Tab 2: 🛡️ Canary Revocation Twin & Migration Gate

### 1. What is the Novelty?
- **Evidence-Calibrated Canary Revocation Twin (The Primary Patent Claim):**
  - *The Gap in Existing Tools:* Existing canary or credential testing systems use synthetic mock assumptions of how cloud providers behave. In reality, distributed identity providers (Google, Okta, GitHub) have cache propagation delays, unwritten revocation cascades, and version-specific quirks.
  - *Our Novelty:*
    1. **Dependency-Equivalent Canary Family:** Builds a disposable 4-role credential tree:
       - `parent`: The root identity slated for revocation.
       - `child`: Downstream delegated token (expected to be invalidated).
       - `sibling`: Parallel independent token (expected to survive).
       - `replacement`: Candidate successor token (MUST survive to take over production workload).
    2. **Deterministic SHA-256 Topology Hashing:** Uniquely identifies the structural graph.
    3. **Empirical Ground-Truth Calibration:** Evaluates the canary simulation against signed, recorded provider ground-truth fixtures (`ProviderGroundTruthFixture`).
    4. **Failsafe 3-State Migration Gate:** Yields `APPROVED`, `REJECTED`, or `INDETERMINATE` (if provider version lacks calibration, preventing blind deployments).

### 2. Live Demo Steps
1. Navigate to **Tab 2: `🛡️ 2. Canary Revocation Twin`**.
2. **Step A: Synthesize Canary Family**
   - Leave Provider as `mock_enterprise` and Profile as `v1`.
   - Click **"Synthesize Canary Family"**.
   - Point out the **Topology SHA-256 hash** and the 4 distinct roles (`parent`, `child`, `sibling`, `replacement`).
3. **Step B: Test Case 1 — Normal Verified Migration (`APPROVED`)**
   - Click **"Verify Migration Gate"**.
   - **Point to Screen:**
     - Decision turns green **`APPROVED`**.
     - Calibration Verdict: **`CALIBRATED` (98% confidence)** against fixture `gt-mock-enterprise-v1`.
     - Cryptographic Witness Bundle: All 4 invariants (`intent_locked`, `dependency_preserved`, `canary_validated`, `evidence_calibrated`) are marked **`VALID`** with bundle digest.
4. **Step C: Test Case 2 — Live Fault Injection (`REJECTED`)**
   - Check the box: **`[x] Inject Provider Desync Hazard (Simulate Broken Revocation)`**.
   - Click **"Verify Migration Gate"**.
   - **Point to Screen:**
     - Decision turns red **`REJECTED`**.
     - Calibration Verdict: **`DIVERGENT`**.
     - Invariant Witness `dependency_preserved: FAILED`.
     - *What to say:* *"In production, this provider bug would have caused an outage by killing the replacement token. ScopeSentry-R caught and blocked it in the sandbox."*
5. **Step D: Test Case 3 — Failsafe Indeterminate State (`INDETERMINATE`)**
   - Uncheck the hazard box.
   - Change Calibration Profile to: **`v99 (Uncalibrated / Unknown Version)`**.
   - Click **"Verify Migration Gate"**.
   - **Point to Screen:**
     - Decision turns amber **`INDETERMINATE`**.
     - *What to say:* *"Without recorded ground truth, ScopeSentry-R refuses to authorize blind migrations, avoiding false passes."*

---

## Tab 3: 🔒 Evidence Ledger & Tamper Lab

### 1. What is the Novelty?
- **Active Cryptographic Chain Verification with Tamper Detection:**
  - *The Problem:* Traditional security logs are stored in flat log files or databases that an attacker with local root access can quietly modify to hide malicious activities.
  - *Our Novelty:* Every analysis, canary experiment, and migration decision is committed to an append-only JSON Lines ledger (`runtime/evidence.jsonl`). Each block contains:
    - `sequence_number`
    - `request_hash` (SHA-256)
    - `result_hash` (SHA-256)
    - `previous_record_hash` (Merkle link)
    - `record_hash` (Signature over entire payload)
  - The system implements active validation: if any byte in any record is modified on disk, the cryptographic link is severed, and the system raises a `409 Conflict` security state, refusing to trust corrupted history.

### 2. Live Demo Steps
1. Navigate to **Tab 3: `🔒 3. Evidence Ledger & Tamper Lab`**.
2. **Step A: Inspect Pristine State**
   - Point to the sequence numbers, event types (`canary_experiment`, `migration_verified`, `single_grant`), and 64-character SHA-256 hashes.
   - Click **"Verify Hash Chain"**: Show that **Evidence Chain: Valid** (green).
3. **Step B: Simulate Active Insider Attack**
   - Click the red button: **"Simulate Ledger Tamper Attack"**.
   - A warning banner appears: *Record altered on disk.*
   - Click the blue button: **"Verify Hash Chain"**.
   - **Point to Screen:**
     - Verification fails immediately.
     - The stat card turns red: *"Previous record hash does not match at sequence X."*
     - Server console logs show HTTP `409 Conflict` (refusing to return compromised evidence).
4. **Step C: Heal & Restore the Ledger**
   - Click the green button: **"Restore & Heal Ledger"**.
   - Click **"Verify Hash Chain"**: The card turns green again, proving that mathematical integrity is restored.

---

## Tab 4: 📊 Batch Benchmark Suite (TRL 4 Proof)

### 1. What is the Novelty?
- **TRL 4 Laboratory Validation & Cross-Provider Reproducibility:**
  - *What is TRL 4?* Technology Readiness Level 4 represents component and breadboard validation in a laboratory environment (ISO 16290 / NASA standards).
  - *Our Proof:* Five deterministic multi-provider security scenarios (`google`, `mock-enterprise`, `mock-code-host`) demonstrating runtime drift detection, composed exfiltration path blocking, and capability collisions.
  - Validated by an automated test suite of **294 unit and integration tests** passing with zero regressions in under 35 seconds.

### 2. Live Demo Steps
1. Navigate to **Tab 4: `📊 4. Batch Benchmark Suite`**.
2. Point out the 5 pre-configured enterprise threat scenarios:
   - `safe-file-reader`: Legitimate baseline.
   - `overprivileged-file-reader`: Excessive permission detection.
   - `runtime-scope-drift`: Runtime quarantine of rogue tokens.
   - `composed-exfiltration-path`: Cross-provider authorization collision detection.
   - `missing-required-permission`: Missing capability handling.
3. Click **"Run All Scenarios"** and observe all counters incrementing live.
4. Switch to terminal and run:
   ```powershell
   .\.venv\Scripts\pytest -q
   ```
   Show the output: **`294 passed`** (100% test pass rate).

---

## Anticipated Faculty Questions & Winning Answers

| Examiner / Faculty Question | Direct Winning Answer |
|---|---|
| **"Isn't Tab 1 just basic keyword matching on scope names?"** | *"No, sir. We construct a directed graph in NetworkX using capability mapping. It traverses semantic actions to find minimal required capabilities and computes graph reachability, ensuring least-privilege synthesis rather than basic keyword matching."* |
| **"Why do you need the Canary Twin? Can't we just test with the real token?"** | *"Testing with real production credentials risks revoking the live root authority or creating downtime. The Canary Twin builds a dependency-equivalent disposable clone family (`parent`, `child`, `sibling`, `replacement`) to measure cascade effects with zero production risk."* |
| **"What makes ScopeSentry-R better than existing canary tools?"** | *"Existing tools rely on synthetic provider assumptions. Real cloud providers (Google, GitHub, Microsoft) often exhibit propagation delays or unwritten revocation behaviors. ScopeSentry-R explicitly calibrates simulation against empirical ground-truth fixtures and yields an `indeterminate` failsafe state if calibration is missing."* |
| **"Why did you use an append-only JSONL ledger instead of a traditional SQL database?"** | *"In SQL databases, any database administrator or attacker with UPDATE permissions can alter audit logs without leaving a mathematical trace. In ScopeSentry-R, every record contains the cryptographic SHA-256 hash of the previous record. Mutating any row instantly invalidates all subsequent hashes, providing tamper evidence mathematically without requiring complex blockchain overhead."* |
| **"Is this TRL 4?"** | *"Yes. Under ISO/NASA TRL definitions, TRL 4 represents component validation in a laboratory environment. We have integrated all 5 core subsystems into an end-to-end FastAPI service validated across 294 automated test cases with deterministic SHA-256 evidence generation."* |
