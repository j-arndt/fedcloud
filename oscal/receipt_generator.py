"""
FedCloud Verification Receipt Generator

Produces cryptographically signed JSON verification receipts from
the Lean 4 proof checker output. Each receipt captures the verification
status, timestamp, input state hash, and a signature for tamper evidence.

Output format:
{
  "receipt_id": "uuid",
  "status": "VERIFIED" | "VIOLATED",
  "timestamp": "ISO-8601",
  "clusters": { ... per-cluster results ... },
  "input_state_hash": "sha256:...",
  "signature": "hmac-sha256:..."
}
"""

import hashlib
import hmac
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Default HMAC key for PoC — in production, sourced from AWS Secrets Manager / KMS
_DEFAULT_HMAC_KEY = b"fedcloud-poc-verification-key-2026"


def compute_state_hash(state_path: str) -> str:
    """Compute SHA-256 hash of the input state file."""
    h = hashlib.sha256()
    with open(state_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def sign_receipt(receipt_data: dict, key: bytes = _DEFAULT_HMAC_KEY) -> str:
    """Generate HMAC-SHA256 signature over the receipt payload."""
    canonical = json.dumps(receipt_data, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{sig}"


def generate_receipt(
    verification_result: dict,
    state_path: Optional[str] = None,
    hmac_key: bytes = _DEFAULT_HMAC_KEY,
) -> dict:
    """
    Generate a complete verification receipt.

    Args:
        verification_result: Dict with per-cluster verification results.
            Expected keys: identity, crypto, architecture, monitoring
            Each value: {"status": "VERIFIED"|"VIOLATED", "detail": "..."}
        state_path: Path to the input state JSON (for hashing).
        hmac_key: HMAC signing key.

    Returns:
        Complete signed verification receipt dict.
    """
    receipt_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Determine overall status
    all_verified = all(
        c.get("status") == "VERIFIED"
        for c in verification_result.values()
    )

    state_hash = compute_state_hash(state_path) if state_path else "sha256:none"

    receipt = {
        "receipt_id": receipt_id,
        "status": "VERIFIED" if all_verified else "VIOLATED",
        "timestamp": timestamp,
        "clusters": verification_result,
        "input_state_hash": state_hash,
        "verification_engine": "FedCloud Lean4 Gateway v0.1.0",
        "lean_version": "leanprover/lean4:v4.28.0",
    }

    receipt["signature"] = sign_receipt(receipt, hmac_key)

    return receipt


def write_receipt(receipt: dict, output_path: str) -> None:
    """Write receipt to a JSON file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"Verification receipt written to {output_path}")


def parse_lean_output(lean_exit_code: int, lean_stdout: str = "") -> dict:
    """
    Parse Lean 4 compiler output into structured cluster results.

    In PoC mode, the exit code determines pass/fail.
    In production, structured output from the Lean engine would be parsed.
    """
    if lean_exit_code == 0:
        return {
            "identity": {"status": "VERIFIED", "detail": "All privileged sessions use phishing-resistant MFA with ≤60min tokens."},
            "crypto": {"status": "VERIFIED", "detail": "All federal data stores encrypted with FIPS-140-3 modules."},
            "architecture": {"status": "VERIFIED", "detail": "All compute nodes use signed immutable images, no shell access, no open ingress."},
            "monitoring": {"status": "VERIFIED", "detail": "All log streams active, tamper-evident, ≥365-day retention."},
        }
    else:
        # Parse which cluster failed from Lean output (simplified for PoC)
        return {
            "identity": {"status": "VIOLATED", "detail": lean_stdout or "Invariant check failed."},
            "crypto": {"status": "VIOLATED", "detail": lean_stdout or "Invariant check failed."},
            "architecture": {"status": "VIOLATED", "detail": lean_stdout or "Invariant check failed."},
            "monitoring": {"status": "VIOLATED", "detail": lean_stdout or "Invariant check failed."},
        }


def main():
    """CLI: generate a receipt from a Lean exit code and state file."""
    if len(sys.argv) < 3:
        print("Usage: python receipt_generator.py <lean_exit_code> <state.json> [output.json]")
        sys.exit(1)

    exit_code = int(sys.argv[1])
    state_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "output/verification_receipt.json"

    result = parse_lean_output(exit_code)
    receipt = generate_receipt(result, state_path=state_path)
    write_receipt(receipt, output_path)


if __name__ == "__main__":
    main()
