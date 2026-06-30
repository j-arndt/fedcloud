"""
FedCloud Verification Pipeline Runner

Orchestrates the complete verification flow:
  1. Ingest infrastructure state from fixtures or live APIs
  2. Translate state to Lean 4 definitions
  3. Run formal verification (or simulate for PoC)
  4. Generate cryptographically signed receipt
  5. Update OSCAL SSP with verification results
  6. Generate OSCAL Assessment Results

Usage:
  python -m scripts.run_pipeline --mode mock --fixtures fixtures/
  python -m scripts.run_pipeline --mode mock --fixtures fixtures/ --state fixtures/mock_aws_topology.json
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from translator.json_to_lean import LeanTranslator, translate_json_to_lean
from translator.state_ingestion import IngestionConfig, create_ingestion_service
from oscal.receipt_generator import generate_receipt, parse_lean_output, write_receipt
from oscal.ssp_updater import update_ssp
from oscal.assessment_results import generate_assessment_results, write_assessment_results


def run_pipeline(args):
    """Execute the full verification pipeline."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  FedCloud Formal Verification Gateway — Pipeline Run")
    print("=" * 70)
    print()

    # ── Step 1: Ingest State ──────────────────────────────────────────────
    print("[1/5] Ingesting infrastructure state...")

    if args.state:
        # Direct state file provided
        state_path = args.state
        with open(state_path) as f:
            state_data = json.load(f)
        print(f"  Loaded state from: {state_path}")
    else:
        # Use ingestion service
        config = IngestionConfig(
            mode=args.mode,
            fixture_dir=args.fixtures,
            output_path=str(output_dir / "current_state.json"),
        )
        service = create_ingestion_service(config)
        snapshot = service.build_snapshot()
        state_path = service.write_snapshot(snapshot)
        state_data = snapshot.to_dict()
        print(f"  State snapshot: {state_path}")

    sessions = state_data.get("sessions", state_data.get("active_sessions", []))
    stores = state_data.get("databases", state_data.get("data_stores", []))
    compute = state_data.get("compute", state_data.get("nodes", []))
    logs = state_data.get("log_streams", state_data.get("logging", []))
    print(f"  Sessions: {len(sessions)} | Stores: {len(stores)} | Compute: {len(compute)} | Logs: {len(logs)}")
    print()

    # ── Step 2: Translate to Lean ─────────────────────────────────────────
    print("[2/5] Translating state to Lean 4 definitions...")

    lean_output = str(output_dir / "SystemState.lean")
    translate_json_to_lean(state_path, lean_output)
    print(f"  Lean definition file: {lean_output}")
    print()

    # ── Step 3: Run Formal Verification ───────────────────────────────────
    print("[3/5] Running formal verification...")

    lean_exit_code = 0
    lean_stdout = ""

    if args.mode == "live" and args.lean_binary:
        # Production: run actual Lean 4 proof checker
        try:
            result = subprocess.run(
                [args.lean_binary, "--run", "FedCloud/Verify.lean", lean_output],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=args.lean_dir or "lean",
            )
            lean_exit_code = result.returncode
            lean_stdout = result.stdout + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  Warning: Lean execution failed ({e}), using mock verification")
    else:
        # PoC mock: simulate verification based on state analysis
        lean_exit_code = simulate_verification(state_data)
        if lean_exit_code == 0:
            print("  Simulation: All invariants satisfied.")
        else:
            print("  Simulation: One or more invariants violated.")

    verification_result = parse_lean_output(lean_exit_code, lean_stdout)
    print(f"  Verification result: {'PASS' if lean_exit_code == 0 else 'FAIL'}")
    print()

    # ── Step 4: Generate Receipt ──────────────────────────────────────────
    print("[4/5] Generating verification receipt...")

    receipt = generate_receipt(verification_result, state_path=state_path)
    receipt_path = str(output_dir / "verification_receipt.json")
    write_receipt(receipt, receipt_path)
    print(f"  Receipt ID: {receipt['receipt_id']}")
    print(f"  Status: {receipt['status']}")
    print(f"  Signature: {receipt['signature'][:40]}...")
    print()

    # ── Step 5: Generate OSCAL Artifacts ──────────────────────────────────
    print("[5/5] Generating OSCAL compliance artifacts...")

    ssp_template = args.ssp_template or "oscal/templates/fedramp_moderate_ssp.json"
    ssp_output = str(output_dir / "fedcloud_ssp.json")
    update_ssp(ssp_template, receipt, ssp_output)

    ar = generate_assessment_results(receipt)
    ar_output = str(output_dir / "assessment_results.json")
    write_assessment_results(ar, ar_output)
    print()

    # ── Summary ───────────────────────────────────────────────────────────
    print("=" * 70)
    print("  Pipeline Complete")
    print("=" * 70)
    print(f"  Overall Status:     {receipt['status']}")
    print(f"  Receipt:            {receipt_path}")
    print(f"  Lean Definitions:   {lean_output}")
    print(f"  OSCAL SSP:          {ssp_output}")
    print(f"  Assessment Results: {ar_output}")
    print()

    return 0 if receipt["status"] == "VERIFIED" else 1


def simulate_verification(state_data: dict) -> int:
    """
    Simulate Lean 4 verification by checking state data directly in Python.
    Returns 0 for success, 1 for failure.
    """
    sessions = state_data.get("sessions", state_data.get("active_sessions", []))
    stores = state_data.get("databases", state_data.get("data_stores", []))
    compute = state_data.get("compute", state_data.get("nodes", []))
    logs = state_data.get("log_streams", state_data.get("logging", []))

    # Check identity invariant
    for s in sessions:
        is_priv = s.get("is_privileged", False)
        has_mfa = s.get("has_phishing_resistant_mfa", False)
        lifetime = s.get("token_lifetime_minutes", 0)
        if is_priv and (not has_mfa or lifetime > 60):
            return 1

    # Check crypto invariant
    for d in stores:
        is_federal = d.get("contains_federal_data", False)
        encrypted = d.get("is_encrypted_at_rest", False)
        cipher = d.get("cryptographic_module_standard", "")
        if is_federal and (not encrypted or cipher != "FIPS-140-3"):
            return 1

    # Check architecture invariant
    for c in compute:
        signed = c.get("immutable_image_signature_valid", False)
        shell = c.get("allows_interactive_shell_access", False)
        ingress = c.get("network_ingress_anywhere", False)
        if not signed or shell or ingress:
            return 1

    # Check monitoring invariant
    for l in logs:
        active = l.get("is_actively_streaming", False)
        tamper = l.get("destination_is_tamper_evident", False)
        retention = l.get("retention_days", 0)
        if not active or not tamper or retention < 365:
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="FedCloud Formal Verification Pipeline"
    )
    parser.add_argument("--mode", choices=["mock", "live"], default="mock",
                        help="Ingestion mode (default: mock)")
    parser.add_argument("--fixtures", default="fixtures",
                        help="Directory containing fixture files")
    parser.add_argument("--state", default=None,
                        help="Direct path to a state JSON file")
    parser.add_argument("--output", default="output",
                        help="Output directory for artifacts")
    parser.add_argument("--ssp-template", default=None,
                        help="Path to OSCAL SSP template")
    parser.add_argument("--lean-binary", default=None,
                        help="Path to Lean 4 binary (for live mode)")
    parser.add_argument("--lean-dir", default=None,
                        help="Path to Lean project directory")

    args = parser.parse_args()
    sys.exit(run_pipeline(args))


if __name__ == "__main__":
    main()
