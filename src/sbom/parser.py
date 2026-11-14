"""Software Bill of Materials (SBOM) Parser & License Compliance Evaluator."""

import json
import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class SBOMParser:
    """Parses and audits SPDX 2.3 & CycloneDX SBOM specifications."""

    def __init__(self, allowed_licenses: List[str] = None, disallowed_licenses: List[str] = None):
        self.allowed_licenses = set(allowed_licenses or ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"])
        self.disallowed_licenses = set(disallowed_licenses or ["GPL-3.0", "AGPL-3.0"])

    def parse_sbom_file(self, sbom_path: str) -> Dict[str, Any]:
        """Loads and normalizes an SBOM JSON file."""
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        packages = []
        # Detect SPDX vs CycloneDX
        if "spdxVersion" in data:
            format_type = "SPDX"
            raw_pkgs = data.get("packages", [])
            for p in raw_pkgs:
                packages.append({
                    "name": p.get("name"),
                    "version": p.get("versionInfo", "unknown"),
                    "license": p.get("licenseConcluded") or p.get("licenseDeclared") or "NOASSERTION",
                    "supplier": p.get("supplier", "unknown"),
                    "checksum": p.get("checksums", [{}])[0].get("checksumValue", "")
                })
        else:
            format_type = "CycloneDX"
            raw_pkgs = data.get("components", [])
            for p in raw_pkgs:
                lic_str = "NOASSERTION"
                if p.get("licenses"):
                    lic_str = p["licenses"][0].get("license", {}).get("id", "NOASSERTION")
                packages.append({
                    "name": p.get("name"),
                    "version": p.get("version", "unknown"),
                    "license": lic_str,
                    "supplier": p.get("publisher", "unknown"),
                    "checksum": p.get("hashes", [{}])[0].get("content", "")
                })

        return {
            "format": format_type,
            "document_name": data.get("name", "unnamed-artifact"),
            "total_packages": len(packages),
            "packages": packages
        }

    def audit_licenses(self, parsed_sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audits package licenses against corporate open-source policies."""
        violations = []
        for pkg in parsed_sbom.get("packages", []):
            pkg_name = pkg.get("name")
            pkg_lic = pkg.get("license")

            if pkg_lic in self.disallowed_licenses:
                violations.append({
                    "rule_id": "SC-LIC-01",
                    "severity": "HIGH",
                    "package": pkg_name,
                    "license": pkg_lic,
                    "title": f"Banned Copyleft License in '{pkg_name}'",
                    "description": f"Package '{pkg_name}' uses disallowed copyleft license '{pkg_lic}', risking intellectual property contamination.",
                    "remediation": f"Replace dependency '{pkg_name}' with a permissively licensed alternative (e.g. Apache-2.0 or MIT)."
                })
            elif pkg_lic not in self.allowed_licenses and pkg_lic != "NOASSERTION":
                violations.append({
                    "rule_id": "SC-LIC-02",
                    "severity": "MEDIUM",
                    "package": pkg_name,
                    "license": pkg_lic,
                    "title": f"Unapproved License in '{pkg_name}'",
                    "description": f"License '{pkg_lic}' is not in approved organizational whitelist.",
                    "remediation": "Submit license review request to corporate legal or switch to approved dependency."
                })

        return violations
