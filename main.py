"""CLI Runner for Software Supply Chain Security & SBOM Attestation Mesh."""

import argparse
import hashlib
import json
import logging
import os
import sys
import yaml

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.sbom.parser import SBOMParser
from src.attestation.verifier import AttestationVerifier

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SupplyChainCLI")


def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def audit_supply_chain(sbom_file: str, attestation_file: str, artifact_file: str, policy_file: str):
    """Executes full supply chain verification pipeline."""
    print("\n" + "=" * 80)
    print(" 🛡️ SOFTWARE SUPPLY CHAIN SECURITY & SBOM ATTESTATION SENTINEL")
    print("=" * 80 + "\n")

    with open(policy_file, "r", encoding="utf-8") as f:
        policy_cfg = yaml.safe_load(f)

    # 1. Audit SBOM Dependencies & Licenses
    print(f"[*] Step 1: Parsing & Auditing SBOM Dependencies ({sbom_file})...")
    parser = SBOMParser(
        allowed_licenses=policy_cfg.get("allowed_licenses"),
        disallowed_licenses=policy_cfg.get("disallowed_licenses")
    )
    parsed_sbom = parser.parse_sbom_file(sbom_file)
    print(f"    • SBOM Standard: {parsed_sbom['format']}")
    print(f"    • Total Components Cataloged: {parsed_sbom['total_packages']}")

    license_violations = parser.audit_licenses(parsed_sbom)
    if license_violations:
        print(f"    ⚠️ LICENSE VIOLATIONS DETECTED: {len(license_violations)}")
        for v in license_violations:
            print(f"       • [{v['rule_id']}] {v['severity']} - {v['title']}")
    else:
        print("    ✅ All dependency licenses comply with open-source policy.\n")

    # 2. Audit Cryptographic Attestation & SLSA Provenance
    print(f"[*] Step 2: Validating SLSA Level 3 Provenance Attestation ({attestation_file})...")
    with open(attestation_file, "r", encoding="utf-8") as f:
        attestation_data = json.load(f)

    artifact_hash = compute_sha256(artifact_file)
    print(f"    • Calculated Binary SHA-256 : {artifact_hash}")

    verifier = AttestationVerifier(policy_cfg)
    is_valid, prov_violations = verifier.verify_provenance(attestation_data, artifact_hash)

    total_violations = license_violations + prov_violations

    if is_valid:
        print("    ✅ Cryptographic Attestation Verified: Matches trusted builder & exact binary hash.")
    else:
        print(f"    ❌ PROVENANCE ATTESTATION FAILED: {len(prov_violations)} Critical Integrity Breaches.")
        for v in prov_violations:
            print(f"       • [{v['rule_id']}] {v['severity']} - {v['title']}: {v['description']}")

    # 3. Decision Gate Summary
    print("\n" + "-" * 80)
    print(" 📊 SUPPLY CHAIN ADMISSION VERDICT")
    print("-" * 80)
    if not total_violations:
        print(" 🟢 VERDICT: PASSED (Artifact certified for production deployment)")
    else:
        print(f" 🔴 VERDICT: BLOCKED ({len(total_violations)} supply-chain security gate violations)")

    if total_violations and HAS_TABULATE:
        table_rows = []
        for v in total_violations:
            table_rows.append([
                v.get("rule_id"),
                v.get("severity"),
                v.get("title")[:36],
                v.get("remediation")[:45]
            ])
        print("\n" + tabulate(table_rows, headers=["Rule ID", "Severity", "Violation Title", "Remediation Action"], tablefmt="rounded_grid"))

    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Software Supply Chain Security & SBOM Attestation Mesh")
    parser.add_argument("--sbom", type=str, default="tests/mock_artifacts/sample_spdx_sbom.json", help="Path to SPDX/CycloneDX SBOM JSON")
    parser.add_argument("--attestation", type=str, default="tests/mock_artifacts/sample_slsa_attestation.json", help="Path to in-toto SLSA attestation JSON")
    parser.add_argument("--artifact", type=str, default="tests/mock_artifacts/sample_microservice_binary.bin", help="Path to compiled binary/container tar")
    parser.add_argument("--policy", type=str, default="policies/slsa_policy.yaml", help="Path to SLSA policy YAML")

    args = parser.parse_args()
    audit_supply_chain(args.sbom, args.attestation, args.artifact, args.policy)


if __name__ == "__main__":
    main()
