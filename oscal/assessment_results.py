"""
FedCloud OSCAL Assessment Results Generator

Generates OSCAL Assessment Results documents from formal verification runs.
Each assessment result captures the findings, observations, and risk
determinations from a complete verification cycle.

Target OSCAL version: 1.1.2
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def generate_assessment_results(
    receipt: dict,
    ssp_reference: str = "fedcloud-ssp-v1",
) -> dict:
    """
    Generate an OSCAL Assessment Results document from a verification receipt.

    Maps each cluster's verification result to OSCAL findings with
    appropriate observation types and risk levels.
    """
    timestamp = receipt.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ar_uuid = str(uuid.uuid4())

    findings = []
    observations = []

    cluster_control_map = {
        "identity": ["AC-2", "AC-3", "AC-6", "IA-2", "IA-5"],
        "crypto": ["SC-8", "SC-12", "SC-13", "SC-28"],
        "architecture": ["CM-2", "CM-6", "CM-7", "SC-7", "SI-7"],
        "monitoring": ["AU-2", "AU-6", "AU-9", "AU-11", "SI-4"],
    }

    for cluster_name, cluster_result in receipt.get("clusters", {}).items():
        status = cluster_result.get("status", "UNKNOWN")
        detail = cluster_result.get("detail", "")
        controls = cluster_control_map.get(cluster_name, [])

        obs_uuid = str(uuid.uuid4())
        finding_uuid = str(uuid.uuid4())

        # Create observation
        observation = {
            "uuid": obs_uuid,
            "title": f"Formal Verification: {cluster_name.title()} Cluster",
            "description": f"Automated formal verification of {cluster_name} security controls "
                           f"using Lean 4 theorem prover. {detail}",
            "methods": ["TEST"],
            "types": ["finding"],
            "collected": timestamp,
            "props": [
                {"name": "verification-method", "value": "formal-proof"},
                {"name": "verification-engine", "value": "Lean4-FedCloud-Gateway"},
                {"name": "verification-status", "value": status},
                {"name": "receipt-id", "value": receipt.get("receipt_id", "unknown")},
            ],
        }
        observations.append(observation)

        # Create finding
        target_status = "satisfied" if status == "VERIFIED" else "not-satisfied"
        finding = {
            "uuid": finding_uuid,
            "title": f"{cluster_name.title()} Cluster Verification",
            "description": detail,
            "target": {
                "type": "objective-id",
                "target-id": f"fedcloud-{cluster_name}-invariant",
                "status": {"state": target_status},
            },
            "related-observations": [{"observation-uuid": obs_uuid}],
            "props": [
                {"name": "cluster", "value": cluster_name},
            ],
        }

        # Add control references
        for ctrl in controls:
            finding.setdefault("related-controls", []).append({
                "control-id": ctrl,
            })

        findings.append(finding)

    # Assemble the complete Assessment Results document
    assessment_results = {
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title": "FedCloud Formal Verification Assessment Results",
                "last-modified": timestamp,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "roles": [
                    {
                        "id": "assessor",
                        "title": "Automated Formal Verification Engine",
                    }
                ],
                "parties": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "type": "organization",
                        "name": "FedCloud Formal Verification Gateway",
                    }
                ],
                "props": [
                    {"name": "assessment-type", "value": "continuous-formal-verification"},
                    {"name": "verification-receipt-id", "value": receipt.get("receipt_id", "unknown")},
                    {"name": "input-state-hash", "value": receipt.get("input_state_hash", "unknown")},
                    {"name": "receipt-signature", "value": receipt.get("signature", "unsigned")},
                ],
            },
            "import-ap": {
                "href": f"#{ssp_reference}",
            },
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": f"Verification Run — {timestamp}",
                    "description": f"Formal verification assessment with overall status: {receipt.get('status', 'UNKNOWN')}.",
                    "start": timestamp,
                    "end": timestamp,
                    "observations": observations,
                    "findings": findings,
                    "props": [
                        {"name": "overall-status", "value": receipt.get("status", "UNKNOWN")},
                    ],
                }
            ],
        }
    }

    return assessment_results


def write_assessment_results(ar: dict, output_path: str) -> None:
    """Write assessment results to a JSON file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(ar, f, indent=2)

    findings = ar["assessment-results"]["results"][0]["findings"]
    satisfied = sum(1 for f in findings if f["target"]["status"]["state"] == "satisfied")
    print(f"Assessment results written to {output_path}")
    print(f"  Findings: {len(findings)} ({satisfied} satisfied, {len(findings) - satisfied} not satisfied)")


def main():
    """CLI: generate assessment results from a verification receipt."""
    if len(sys.argv) < 2:
        print("Usage: python assessment_results.py <receipt.json> [output.json]")
        sys.exit(1)

    receipt_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output/assessment_results.json"

    with open(receipt_path) as f:
        receipt = json.load(f)

    ar = generate_assessment_results(receipt)
    write_assessment_results(ar, output_path)


if __name__ == "__main__":
    main()
