# 🛡️ Software Supply Chain Security & SBOM Attestation Sentinel

[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level_3_Provenance-darkgreen.svg?logo=security&logoColor=white)](https://slsa.dev/)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX_2.3_%7C_CycloneDX-blue.svg)](https://spdx.dev/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Cosign / in-toto](https://img.shields.io/badge/Signature-in--toto_Attestation-purple.svg)](https://in-toto.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise **Software Supply Chain Security & Attestation Mesh** providing cryptographic verification of software artifacts, validating **SLSA Level 3 build provenance**, auditing **Software Bill of Materials (SBOMs)** in SPDX and CycloneDX formats, and blocking tainted or license-violating dependencies before production admission.

---

## 🎯 Executive Highlights & Problem Solved

- **Zero-Trust Supply Chain Verification**: Prevents SolarWinds and Codecov-style build tampering by cryptographically binding binary digests to immutable in-toto provenance statements.
- **SLSA Level 3 Provenance Attestation**: Validates that artifacts were compiled on hermetic, isolated, and authorized build runners (e.g., GitHub Actions isolated runners) pinned to immutable Git commit hashes.
- **SBOM Ingestion & Policy Auditing**: Ingests SPDX 2.3 and CycloneDX formats to audit component licenses (flagging aggressive copyleft like GPL-3.0/AGPL-3.0) and unapproved third-party dependencies.
- **Post-Build Tamper Detection**: Compares raw binary SHA-256 hashes against attestation subject digests, immediately blocking deployments if artifact tampering occurs between CI build and container runtime.
- **Zero-Cloud-Cost Local Audit**: Completely self-contained engine capable of local CLI execution, CI/CD pipeline integration, and automated verification without cloud spend.

---

## 🏛️ Verification Pipeline Architecture

```text
       Developer Commit (Signed Git SHA)
                       │
                       ▼
         ┌───────────────────────────┐
         │ Hermetic CI/CD Runner     │ (Isolated GitHub Actions / Tekton)
         │  • Build Binary Artifact  │
         │  • Generate SPDX SBOM     │
         │  • Generate in-toto SLSA  │
         └─────────────┬─────────────┘
                       │
                       ▼ Artifact + SBOM + SLSA Statement
         ┌───────────────────────────┐
         │ Supply Chain Sentinel     │
         │  (Verification Mesh)      │
         └─────────────┬─────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌──────────────────┐        ┌──────────────────┐
│ SBOM License     │        │ SLSA Provenance  │
│ & Dependency     │        │ & Binary Digest  │
│ Audit Check      │        │ Verification     │
└────────┬─────────┘        └────────┬─────────┘
         │                           │
         └──────────────┬────────────┘
                        ▼
         ┌───────────────────────────┐
         │ Admission Gate Verdict    │
         │  • 200 OK: Production     │
         │  • 403: Block & Alert     │
         └───────────────────────────┘
```

---

## 📋 Security Standards & Verifications

| Check ID | Verification Category | Enforcement Rule | Remediation Action |
| :--- | :--- | :--- | :--- |
| **`SLSA-PROV-01`** | Builder Authenticity | Rejects builds originating from unapproved or self-hosted rogue runners. | Build strictly on attested enterprise CI runners. |
| **`SLSA-PROV-02`** | Cryptographic Digest Integrity | Rejects deployments where the binary SHA-256 does not match the signed attestation subject. | Abort deployment; initiate security breach investigation. |
| **`SLSA-PROV-03`** | Source Material Immutability | Enforces that source repository URIs are pinned to immutable commit SHAs. | Configure CI provenance to stamp exact commit SHAs. |
| **`SC-LIC-01`** | Banned License Ingestion | Blocks aggressive copyleft licenses (`GPL-3.0`, `AGPL-3.0`) in production binaries. | Replace with permissively licensed alternatives (`MIT`, `Apache-2.0`). |
| **`SC-LIC-02`** | Whitelist Governance | Flags unapproved licenses not registered in the corporate catalog. | Submit package to open-source governance board. |

---

## ⚡ Quickstart & Local Execution (Zero Cloud Spend)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Full Supply Chain Verification
Audit mock microservice binaries, SPDX SBOMs, and SLSA provenance statements:

```bash
python main.py
```

**Expected Terminal Output:**
```text
================================================================================
 🛡️ SOFTWARE SUPPLY CHAIN SECURITY & SBOM ATTESTATION SENTINEL
================================================================================
[*] Step 1: Parsing & Auditing SBOM Dependencies (tests/mock_artifacts/sample_spdx_sbom.json)...
    • SBOM Standard: SPDX
    • Total Components Cataloged: 3
    ⚠️ LICENSE VIOLATIONS DETECTED: 1
       • [SC-LIC-01] HIGH - Banned Copyleft License in 'rogue-gpl-library'

[*] Step 2: Validating SLSA Level 3 Provenance Attestation (tests/mock_artifacts/sample_slsa_attestation.json)...
    • Calculated Binary SHA-256 : 1e8ae0f847a22a790e6e43b948900b114f26279c32c4abe2c9cd408ae1e7c1d5
    ✅ Cryptographic Attestation Verified: Matches trusted builder & exact binary hash.

--------------------------------------------------------------------------------
 📊 SUPPLY CHAIN ADMISSION VERDICT
--------------------------------------------------------------------------------
 🔴 VERDICT: BLOCKED (1 supply-chain security gate violations)
================================================================================
```

### 3. Run Automated Unit Tests
```bash
pytest -v
```

---

## 📜 License
Distributed under the **MIT License**.
