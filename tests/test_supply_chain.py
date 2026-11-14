"""Unit tests for Supply Chain Security & Attestation Mesh."""

import os
import sys
import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.sbom.parser import SBOMParser
from src.attestation.verifier import AttestationVerifier


@pytest.fixture
def policy_config():
    policy_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policies", "slsa_policy.yaml"))
    with open(policy_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_sbom_parsing_and_banned_license(policy_config):
    sbom_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "mock_artifacts", "sample_spdx_sbom.json"))
    parser = SBOMParser(
        allowed_licenses=policy_config.get("allowed_licenses"),
        disallowed_licenses=policy_config.get("disallowed_licenses")
    )
    parsed = parser.parse_sbom_file(sbom_path)
    assert parsed["format"] == "SPDX"
    assert parsed["total_packages"] == 3

    violations = parser.audit_licenses(parsed)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "SC-LIC-01"
    assert "GPL-3.0" in violations[0]["license"]


def test_slsa_attestation_verification_success(policy_config):
    verifier = AttestationVerifier(policy_config)
    attestation = {
        "subject": [
            {"digest": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}}
        ],
        "predicate": {
            "builder": {"id": "https://github.com/KoshaG0hil/trusted-builder"},
            "materials": [
                {"uri": "git+repo", "digest": {"sha1": "commit12345"}}
            ]
        }
    }
    is_valid, violations = verifier.verify_provenance(
        attestation,
        expected_artifact_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )
    assert is_valid is True
    assert len(violations) == 0


def test_slsa_attestation_tampered_digest_fails(policy_config):
    verifier = AttestationVerifier(policy_config)
    attestation = {
        "subject": [
            {"digest": {"sha256": "real-original-hash"}}
        ],
        "predicate": {
            "builder": {"id": "https://github.com/KoshaG0hil/trusted-builder"},
            "materials": []
        }
    }
    is_valid, violations = verifier.verify_provenance(
        attestation,
        expected_artifact_sha256="tampered-malicious-hash"
    )
    assert is_valid is False
    assert any(v["rule_id"] == "SLSA-PROV-02" for v in violations)
