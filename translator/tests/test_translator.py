"""
Tests for the FedCloud JSON-to-Lean translator.

Validates:
  - Session translation with various IAM formats
  - Data store translation with KMS normalization
  - Compute resource translation
  - Log stream translation
  - Full state translation (end-to-end)
  - Terraform plan parsing
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from translator.json_to_lean import LeanTranslator, translate_json_to_lean


class TestLeanTranslator(unittest.TestCase):

    def setUp(self):
        self.translator = LeanTranslator(source_label="test")

    # -- Session Translation --

    def test_translate_privileged_session_with_mfa(self):
        sessions = [{
            "user_id": "admin-001",
            "is_privileged": True,
            "has_phishing_resistant_mfa": True,
            "token_lifetime_minutes": 30,
        }]
        result = self.translator.translate_sessions(sessions)
        self.assertIn('user_id := "admin-001"', result)
        self.assertIn("is_privileged := true", result)
        self.assertIn("has_phishing_resistant_mfa := true", result)
        self.assertIn("token_lifetime_minutes := 30", result)

    def test_translate_session_with_seconds_conversion(self):
        sessions = [{"user_id": "svc", "token_lifetime_seconds": 1800}]
        result = self.translator.translate_sessions(sessions)
        self.assertIn("token_lifetime_minutes := 30", result)

    def test_translate_session_with_mfa_type_string(self):
        sessions = [{"user_id": "u1", "mfaType": "FIDO2"}]
        result = self.translator.translate_sessions(sessions)
        self.assertIn("has_phishing_resistant_mfa := true", result)

    def test_translate_session_without_mfa(self):
        sessions = [{"user_id": "u2", "mfaType": "TOTP"}]
        result = self.translator.translate_sessions(sessions)
        self.assertIn("has_phishing_resistant_mfa := false", result)

    # -- Data Store Translation --

    def test_translate_encrypted_federal_store(self):
        stores = [{
            "id": "rds-prod",
            "contains_federal_data": True,
            "is_encrypted_at_rest": True,
            "cryptographic_module_standard": "FIPS-140-3",
        }]
        result = self.translator.translate_data_stores(stores)
        self.assertIn('id := "rds-prod"', result)
        self.assertIn("contains_federal_data := true", result)
        self.assertIn('cryptographic_module_standard := "FIPS-140-3"', result)

    def test_kms_key_spec_normalization(self):
        stores = [{"id": "s3", "kmsKeySpec": "SYMMETRIC_DEFAULT", "encrypted": True, "classification": "federal"}]
        result = self.translator.translate_data_stores(stores)
        self.assertIn('"FIPS-140-3"', result)

    def test_unencrypted_store(self):
        stores = [{"id": "legacy", "encrypted": False, "classification": "federal"}]
        result = self.translator.translate_data_stores(stores)
        self.assertIn("is_encrypted_at_rest := false", result)

    # -- Compute Resource Translation --

    def test_translate_compliant_node(self):
        nodes = [{
            "id": "eks-node-1",
            "immutable_image_signature_valid": True,
            "allows_interactive_shell_access": False,
            "network_ingress_anywhere": False,
        }]
        result = self.translator.translate_compute_resources(nodes)
        self.assertIn("immutable_image_signature_valid := true", result)
        self.assertIn("allows_interactive_shell_access := false", result)
        self.assertIn("network_ingress_anywhere := false", result)

    def test_translate_violating_node(self):
        nodes = [{"id": "bastion", "sshEnabled": True, "openIngress": True}]
        result = self.translator.translate_compute_resources(nodes)
        self.assertIn("allows_interactive_shell_access := true", result)
        self.assertIn("network_ingress_anywhere := true", result)

    # -- Log Stream Translation --

    def test_translate_compliant_log_stream(self):
        streams = [{
            "source_id": "cloudtrail-main",
            "is_actively_streaming": True,
            "destination_is_tamper_evident": True,
            "retention_days": 730,
        }]
        result = self.translator.translate_log_streams(streams)
        self.assertIn("is_actively_streaming := true", result)
        self.assertIn("retention_days := 730", result)

    def test_translate_log_with_cloudwatch_fields(self):
        streams = [{"logGroupName": "/app/logs", "isLogging": True, "retentionInDays": 365}]
        result = self.translator.translate_log_streams(streams)
        self.assertIn('source_id := "/app/logs"', result)
        self.assertIn("retention_days := 365", result)

    # -- Full State Translation --

    def test_full_state_translation(self):
        state = {
            "sessions": [{"user_id": "admin", "is_privileged": True, "has_phishing_resistant_mfa": True, "token_lifetime_minutes": 30}],
            "databases": [{"id": "db1", "contains_federal_data": True, "is_encrypted_at_rest": True, "cryptographic_module_standard": "FIPS-140-3"}],
            "compute": [{"id": "node1", "immutable_image_signature_valid": True, "allows_interactive_shell_access": False, "network_ingress_anywhere": False}],
            "log_streams": [{"source_id": "trail", "is_actively_streaming": True, "destination_is_tamper_evident": True, "retention_days": 365}],
        }
        result = self.translator.translate_full_state(state)
        self.assertIn("def currentState", result)
        self.assertIn("import FedCloud.BaseModel", result)
        self.assertIn("security_context", result)
        self.assertIn("infrastructure", result)
        self.assertIn("topology", result)
        self.assertIn("logging", result)

    # -- Terraform Plan Translation --

    def test_terraform_plan_parsing(self):
        tfplan = {
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_rds_cluster.prod",
                            "type": "aws_rds_cluster",
                            "values": {"storage_encrypted": True, "kms_key_id": "arn:aws:kms:key"},
                        },
                        {
                            "address": "aws_cloudtrail.main",
                            "type": "aws_cloudtrail",
                            "values": {"is_multi_region_trail": True, "enable_log_file_validation": True},
                        },
                    ]
                }
            }
        }
        result = self.translator.translate_terraform_plan(tfplan)
        self.assertEqual(len(result["databases"]), 1)
        self.assertTrue(result["databases"][0]["is_encrypted_at_rest"])
        self.assertEqual(len(result["log_streams"]), 1)
        self.assertTrue(result["log_streams"][0]["is_actively_streaming"])

    # -- File I/O --

    def test_translate_json_to_lean_file(self):
        state = {
            "sessions": [{"user_id": "test", "is_privileged": False, "has_phishing_resistant_mfa": True, "token_lifetime_minutes": 60}],
            "databases": [],
            "compute": [],
            "log_streams": [],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as inp:
            json.dump(state, inp)
            inp_path = inp.name

        out_path = inp_path.replace(".json", ".lean")
        try:
            translate_json_to_lean(inp_path, out_path)
            with open(out_path) as f:
                content = f.read()
            self.assertIn("def currentState", content)
            self.assertIn('user_id := "test"', content)
        finally:
            os.unlink(inp_path)
            if os.path.exists(out_path):
                os.unlink(out_path)


class TestBoolConversion(unittest.TestCase):
    """Test the _to_lean_bool helper."""

    def test_python_bool(self):
        self.assertEqual(LeanTranslator._to_lean_bool(True), "true")
        self.assertEqual(LeanTranslator._to_lean_bool(False), "false")

    def test_string_bool(self):
        self.assertEqual(LeanTranslator._to_lean_bool("true"), "true")
        self.assertEqual(LeanTranslator._to_lean_bool("yes"), "true")
        self.assertEqual(LeanTranslator._to_lean_bool("false"), "false")
        self.assertEqual(LeanTranslator._to_lean_bool("no"), "false")

    def test_none_and_zero(self):
        self.assertEqual(LeanTranslator._to_lean_bool(None), "false")
        self.assertEqual(LeanTranslator._to_lean_bool(0), "false")
        self.assertEqual(LeanTranslator._to_lean_bool(1), "true")


if __name__ == "__main__":
    unittest.main()
