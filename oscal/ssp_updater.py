"""
FedCloud OSCAL SSP Updater

Injects formal verification results into an OSCAL System Security Plan (SSP).
Updates component definitions with verification timestamps, status indicators,
and links to proof artifacts.

Target OSCAL version: 1.1.2
Profile: FedRAMP Moderate Baseline
"""

import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Mapping from verification clusters to OSCAL control families
CLUSTER_CONTROL_MAP = {
    "identity": {
        "controls": ["AC-2", "AC-3", "AC-6", "AC-7", "IA-2", "IA-5", "IA-8"],
        "component_title": "Identity and Access Management Verification Engine",
        "description_template": "Formal verification of identity controls via Lean 4 proof engine. "
                                "Validates privileged session MFA enforcement and token lifetime constraints. "
                                "Status: {status}. Last verified: {timestamp}.",
    },
    "crypto": {
        "controls": ["SC-8", "SC-12", "SC-13", "SC-28"],
        "component_title": "Cryptographic Protection Verification Engine",
        "description_template": "Formal verification of cryptographic controls via Lean 4 proof engine. "
                                "Validates FIPS-140-3 encryption-at-rest for all federal data stores. "
                                "Status: {status}. Last verified: {timestamp}.",
    },
    "architecture": {
        "controls": ["CM-2", "CM-3", "CM-6", "CM-7", "SC-7", "SI-7"],
        "component_title": "Architecture Immutability Verification Engine",
        "description_template": "Formal verification of architecture controls via Lean 4 proof engine. "
                                "Validates image immutability, shell access prohibition, and network isolation. "
                                "Status: {status}. Last verified: {timestamp}.",
    },
    "monitoring": {
        "controls": ["AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-11", "AU-12", "SI-4"],
        "component_title": "Continuous Monitoring Verification Engine",
        "description_template": "Formal verification of monitoring controls via Lean 4 proof engine. "
                                "Validates active log streaming, tamper-evident destinations, and 365-day retention. "
                                "Status: {status}. Last verified: {timestamp}.",
    },
}


def update_ssp(
    ssp_path: str,
    receipt: dict,
    output_path: Optional[str] = None,
) -> dict:
    """
    Update an OSCAL SSP with verification results from a receipt.

    Finds or creates component definitions for each verification cluster
    and updates their descriptions with current verification status.
    """
    with open(ssp_path, "r") as f:
        ssp = json.load(f)

    ssp_data = ssp.get("system-security-plan", ssp)
    impl = ssp_data.setdefault("system-implementation", {})
    components = impl.setdefault("components", [])

    timestamp = receipt.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    receipt_id = receipt.get("receipt_id", "unknown")

    for cluster_name, cluster_result in receipt.get("clusters", {}).items():
        mapping = CLUSTER_CONTROL_MAP.get(cluster_name)
        if not mapping:
            continue

        status = cluster_result.get("status", "UNKNOWN")
        detail = cluster_result.get("detail", "")

        # Find existing component or create new one
        component = None
        for c in components:
            if c.get("title") == mapping["component_title"]:
                component = c
                break

        if component is None:
            component = {
                "type": "software",
                "title": mapping["component_title"],
                "status": {"state": "operational"},
                "props": [],
                "responsible-roles": [],
            }
            components.append(component)

        # Update component description
        component["description"] = mapping["description_template"].format(
            status=status,
            timestamp=timestamp,
        )

        # Update properties
        props = component.setdefault("props", [])

        # Remove old verification props
        props[:] = [p for p in props if not p.get("name", "").startswith("verification-")]

        # Add current verification properties
        props.extend([
            {"name": "verification-status", "value": status},
            {"name": "verification-timestamp", "value": timestamp},
            {"name": "verification-receipt-id", "value": receipt_id},
            {"name": "verification-engine", "value": "FedCloud Lean4 Gateway v0.1.0"},
            {"name": "verification-detail", "value": detail},
        ])

        # Add control implementation references
        for control_id in mapping["controls"]:
            existing_controls = [p.get("value") for p in props if p.get("name") == "implemented-control"]
            if control_id not in existing_controls:
                props.append({"name": "implemented-control", "value": control_id})

    # Write output
    dest = output_path or ssp_path
    output = Path(dest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w") as f:
        json.dump(ssp, f, indent=2)

    print(f"OSCAL SSP updated: {dest}")
    print(f"  Overall status: {receipt.get('status', 'UNKNOWN')}")
    print(f"  Receipt ID: {receipt_id}")
    print(f"  Clusters updated: {len(receipt.get('clusters', {}))}")

    return ssp


def main():
    """CLI: inject verification receipt into an OSCAL SSP."""
    if len(sys.argv) < 3:
        print("Usage: python ssp_updater.py <receipt.json> <ssp.json> [output_ssp.json]")
        sys.exit(1)

    receipt_path = sys.argv[1]
    ssp_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None

    with open(receipt_path) as f:
        receipt = json.load(f)

    update_ssp(ssp_path, receipt, output_path)


if __name__ == "__main__":
    main()
