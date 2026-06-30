"""
End-to-end tests for the FedCloud OSCAL pipeline.

Validates the complete flow:
  Mock state → Translator → Receipt → SSP Update → Assessment Results
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from translator.json_to_lean import LeanTranslator
from oscal.receipt_generator import (
    generate_receipt,
    parse_lean_output,
    compute_state_hash,
    sign_receipt,
)
from oscal.ssp_updater import update_ssp, CLUSTER_CONTROL_MAP
from oscal.assessment_results import generate_assessment_results


class TestReceiptGenerator(unittest.TestCase):

    def test_parse_lean_success(self):
        result = parse_lean_output(0)
        for cluster in ["identity", "crypto", "architecture", "monitoring"]:
            self.assertEqual(result[cluster]["status"], "VERIFIED")

    def test_parse_lean_failure(self):
        result = parse_lean_output(1, "Invariant violated")
        for cluster in ["identity", "crypto", "architecture", "monitoring"]:
            self.assertEqual(result[cluster]["status"], "VIOLATED")

    def test_generate_receipt_verified(self):
        result = parse_lean_output(0)
        receipt = generate_receipt(result)
        self.assertEqual(receipt["status"], "VERIFIED")
        self.assertIn("receipt_id", receipt)
        self.assertIn("timestamp", receipt)
        self.assertIn("signature", receipt)
        self.assertTrue(receipt["signature"].startswith("hmac-sha256:"))

    def test_generate_receipt_violated(self):
        result = parse_lean_output(1)
        receipt = generate_receipt(result)
        self.assertEqual(receipt["status"], "VIOLATED")

    def test_receipt_with_state_hash(self):
        # Write a temp state file and verify hash is computed
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": "data"}, f)
            state_path = f.name
        try:
            result = parse_lean_output(0)
            receipt = generate_receipt(result, state_path=state_path)
            self.assertTrue(receipt["input_state_hash"].startswith("sha256:"))
            self.assertNotEqual(receipt["input_state_hash"], "sha256:none")
        finally:
            os.unlink(state_path)

    def test_signature_deterministic(self):
        data = {"test": "value"}
        sig1 = sign_receipt(data)
        sig2 = sign_receipt(data)
        self.assertEqual(sig1, sig2)

    def test_signature_varies_with_data(self):
        sig1 = sign_receipt({"a": "1"})
        sig2 = sign_receipt({"a": "2"})
        self.assertNotEqual(sig1, sig2)


class TestSSPUpdater(unittest.TestCase):

    def setUp(self):
        self.ssp_template_path = str(
            Path(__file__).resolve().parent.parent / "templates" / "fedramp_moderate_ssp.json"
        )

    def test_update_ssp_verified(self):
        receipt = {
            "receipt_id": "test-receipt-001",
            "status": "VERIFIED",
            "timestamp": "2026-06-29T12:00:00Z",
            "clusters": {
                "identity": {"status": "VERIFIED", "detail": "All checks passed."},
                "crypto": {"status": "VERIFIED", "detail": "All checks passed."},
                "architecture": {"status": "VERIFIED", "detail": "All checks passed."},
                "monitoring": {"status": "VERIFIED", "detail": "All checks passed."},
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            ssp = update_ssp(self.ssp_template_path, receipt, output_path)
            components = ssp["system-security-plan"]["system-implementation"]["components"]

            # Should have original 3 + 4 new verification components
            self.assertGreaterEqual(len(components), 4)

            # Check that verification components exist
            titles = [c["title"] for c in components]
            for mapping in CLUSTER_CONTROL_MAP.values():
                self.assertIn(mapping["component_title"], titles)

            # Check verification properties
            for c in components:
                if "Verification Engine" in c.get("title", ""):
                    props = {p["name"]: p["value"] for p in c.get("props", [])}
                    self.assertEqual(props.get("verification-status"), "VERIFIED")
                    self.assertEqual(props.get("verification-receipt-id"), "test-receipt-001")
        finally:
            os.unlink(output_path)

    def test_update_ssp_violated(self):
        receipt = {
            "receipt_id": "test-receipt-002",
            "status": "VIOLATED",
            "timestamp": "2026-06-29T12:00:00Z",
            "clusters": {
                "identity": {"status": "VIOLATED", "detail": "MFA not enforced."},
                "crypto": {"status": "VERIFIED", "detail": "All checks passed."},
                "architecture": {"status": "VERIFIED", "detail": "All checks passed."},
                "monitoring": {"status": "VERIFIED", "detail": "All checks passed."},
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            ssp = update_ssp(self.ssp_template_path, receipt, output_path)
            components = ssp["system-security-plan"]["system-implementation"]["components"]

            # Find the identity component and check it shows VIOLATED
            for c in components:
                if c.get("title") == CLUSTER_CONTROL_MAP["identity"]["component_title"]:
                    props = {p["name"]: p["value"] for p in c.get("props", [])}
                    self.assertEqual(props["verification-status"], "VIOLATED")
                    break
            else:
                self.fail("Identity verification component not found")
        finally:
            os.unlink(output_path)


class TestAssessmentResults(unittest.TestCase):

    def test_generate_assessment_results_verified(self):
        receipt = {
            "receipt_id": "test-001",
            "status": "VERIFIED",
            "timestamp": "2026-06-29T12:00:00Z",
            "input_state_hash": "sha256:abc123",
            "signature": "hmac-sha256:def456",
            "clusters": {
                "identity": {"status": "VERIFIED", "detail": "Passed."},
                "crypto": {"status": "VERIFIED", "detail": "Passed."},
                "architecture": {"status": "VERIFIED", "detail": "Passed."},
                "monitoring": {"status": "VERIFIED", "detail": "Passed."},
            },
        }

        ar = generate_assessment_results(receipt)
        self.assertIn("assessment-results", ar)

        results = ar["assessment-results"]["results"]
        self.assertEqual(len(results), 1)

        findings = results[0]["findings"]
        self.assertEqual(len(findings), 4)

        for finding in findings:
            self.assertEqual(finding["target"]["status"]["state"], "satisfied")

    def test_generate_assessment_results_violated(self):
        receipt = {
            "receipt_id": "test-002",
            "status": "VIOLATED",
            "timestamp": "2026-06-29T12:00:00Z",
            "clusters": {
                "identity": {"status": "VIOLATED", "detail": "MFA missing."},
                "crypto": {"status": "VERIFIED", "detail": "Passed."},
                "architecture": {"status": "VERIFIED", "detail": "Passed."},
                "monitoring": {"status": "VIOLATED", "detail": "Retention too short."},
            },
        }

        ar = generate_assessment_results(receipt)
        findings = ar["assessment-results"]["results"][0]["findings"]

        satisfied = [f for f in findings if f["target"]["status"]["state"] == "satisfied"]
        not_satisfied = [f for f in findings if f["target"]["status"]["state"] == "not-satisfied"]
        self.assertEqual(len(satisfied), 2)
        self.assertEqual(len(not_satisfied), 2)

    def test_assessment_results_metadata(self):
        receipt = {
            "receipt_id": "test-003",
            "status": "VERIFIED",
            "timestamp": "2026-06-29T12:00:00Z",
            "input_state_hash": "sha256:xyz",
            "signature": "hmac-sha256:abc",
            "clusters": {"identity": {"status": "VERIFIED", "detail": "OK"}},
        }

        ar = generate_assessment_results(receipt)
        metadata = ar["assessment-results"]["metadata"]
        self.assertEqual(metadata["oscal-version"], "1.1.2")

        props = {p["name"]: p["value"] for p in metadata["props"]}
        self.assertEqual(props["verification-receipt-id"], "test-003")
        self.assertEqual(props["input-state-hash"], "sha256:xyz")


class TestEndToEndPipeline(unittest.TestCase):
    """Test the complete flow: fixtures → translator → receipt → SSP → AR."""

    def test_full_pipeline(self):
        fixtures_dir = Path(__file__).resolve().parent.parent.parent / "fixtures"
        ssp_template = Path(__file__).resolve().parent.parent / "templates" / "fedramp_moderate_ssp.json"

        # Step 1: Load fixtures and translate
        with open(fixtures_dir / "mock_aws_topology.json") as f:
            aws_state = json.load(f)

        translator = LeanTranslator(source_label="e2e-test")
        lean_code = translator.translate_full_state(aws_state)
        self.assertIn("def currentState", lean_code)

        # Step 2: Simulate Lean verification success
        verification_result = parse_lean_output(0)

        # Step 3: Generate receipt
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(aws_state, f)
            state_path = f.name

        try:
            receipt = generate_receipt(verification_result, state_path=state_path)
            self.assertEqual(receipt["status"], "VERIFIED")
            self.assertTrue(receipt["signature"].startswith("hmac-sha256:"))

            # Step 4: Update SSP
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                ssp_output = f.name

            ssp = update_ssp(str(ssp_template), receipt, ssp_output)
            components = ssp["system-security-plan"]["system-implementation"]["components"]
            self.assertGreaterEqual(len(components), 4)

            # Step 5: Generate Assessment Results
            ar = generate_assessment_results(receipt)
            findings = ar["assessment-results"]["results"][0]["findings"]
            all_satisfied = all(
                f["target"]["status"]["state"] == "satisfied" for f in findings
            )
            self.assertTrue(all_satisfied)

            os.unlink(ssp_output)
        finally:
            os.unlink(state_path)


if __name__ == "__main__":
    unittest.main()
