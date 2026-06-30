"""
Tests for FedCloud qualitative verification agents.

All tests run in mock mode — no Bedrock API calls required.
"""

import json
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from agents.config import AgentConfig
from agents.router import classify_event, route_and_evaluate, RoutingDecision
from agents.guardrails import validate_agent_output, enforce_json_schema, GuardrailError
from agents.clusters.personnel import PersonnelSecurityAgent
from agents.clusters.training import CybersecurityEducationAgent
from agents.clusters.incident_response import IncidentResponseAgent
from agents.clusters.recovery import RecoveryPlanningAgent
from agents.clusters.supply_chain import SupplyChainAgent
from oscal.narrative_generator import generate_cluster_narrative


FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "qualitative"


class TestRouter(unittest.TestCase):

    def test_route_deterministic_sessions(self):
        event = {"sessions": [{"user_id": "admin"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "lean")
        self.assertEqual(decision.cluster, "identity")

    def test_route_deterministic_databases(self):
        event = {"databases": [{"id": "db1"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "lean")
        self.assertEqual(decision.cluster, "crypto")

    def test_route_qualitative_personnel(self):
        event = {"background_checks": [{"employee_id": "E1"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.cluster, "personnel")

    def test_route_qualitative_training(self):
        event = {"training_records": [{"user_id": "u1"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.cluster, "training")

    def test_route_qualitative_incidents(self):
        event = {"incidents": [{"incident_id": "INC-1"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.cluster, "incident_response")

    def test_route_qualitative_recovery(self):
        event = {"dr_exercises": [{"exercise_id": "DR-1"}]}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.cluster, "recovery")

    def test_route_qualitative_supply_chain(self):
        event = {"sbom": {"components": []}}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.cluster, "supply_chain")

    def test_route_explicit_hint(self):
        event = {"metadata": {"engine": "bedrock", "cluster": "training"}, "data": {}}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "bedrock")
        self.assertEqual(decision.confidence, 1.0)

    def test_route_unknown_defaults_lean(self):
        event = {"random_field": 123}
        decision = classify_event(event)
        self.assertEqual(decision.engine, "lean")
        self.assertLess(decision.confidence, 0.5)


class TestPersonnelAgent(unittest.TestCase):

    def setUp(self):
        self.config = AgentConfig(mode="mock")
        self.agent = PersonnelSecurityAgent(self.config)

    def test_compliant_personnel(self):
        telemetry = {
            "background_checks": [
                {"employee_id": "E1", "status": "cleared", "date": "2026-01-10", "clearance_id": "BG-1"}
            ],
            "nda_records": [{"employee_id": "E1", "signed": True}],
            "iam_provisioning": [{"employee_id": "E1", "provisioned_date": "2026-01-11"}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(len(result.findings), 0)

    def test_pending_background_check(self):
        telemetry = {
            "background_checks": [{"employee_id": "E1", "status": "pending"}],
            "nda_records": [{"employee_id": "E1", "signed": True}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")
        self.assertTrue(any(f["control"] == "PS-3" for f in result.findings))

    def test_iam_before_clearance(self):
        telemetry = {
            "background_checks": [{"employee_id": "E1", "status": "cleared", "date": "2026-06-15"}],
            "nda_records": [{"employee_id": "E1", "signed": True}],
            "iam_provisioning": [{"employee_id": "E1", "provisioned_date": "2026-06-01"}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")
        self.assertTrue(any("BEFORE" in f["finding"] for f in result.findings))

    def test_from_fixture(self):
        with open(FIXTURES / "mock_personnel.json") as f:
            telemetry = json.load(f)
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")  # EMP-003 is pending
        self.assertGreater(len(result.findings), 0)


class TestTrainingAgent(unittest.TestCase):

    def setUp(self):
        self.config = AgentConfig(mode="mock")
        self.agent = CybersecurityEducationAgent(self.config)

    def test_all_trained(self):
        telemetry = {
            "training_records": [{"user_id": "admin", "covers_federal_privacy": True,
                                  "covers_security_fundamentals": True, "days_since_completion": 100}],
            "active_admins": [{"user_id": "admin"}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VERIFIED")

    def test_missing_training(self):
        telemetry = {
            "training_records": [],
            "active_admins": [{"user_id": "untrained-admin"}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")

    def test_expired_training(self):
        telemetry = {
            "training_records": [{"user_id": "admin", "covers_federal_privacy": True,
                                  "covers_security_fundamentals": True, "days_since_completion": 400}],
            "active_admins": [{"user_id": "admin"}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")
        self.assertTrue(any("expired" in f["finding"] for f in result.findings))


class TestIncidentResponseAgent(unittest.TestCase):

    def setUp(self):
        self.config = AgentConfig(mode="mock")
        self.agent = IncidentResponseAgent(self.config)

    def test_compliant_response(self):
        telemetry = {
            "incidents": [{"incident_id": "INC-1", "severity": "high",
                           "alert_time": "2026-06-15T14:00:00Z", "triage_time": "2026-06-15T14:30:00Z",
                           "time_to_triage_hours": 0.5, "requires_federal_report": False}],
            "post_mortems": [{"incident_id": "INC-1", "summary": "Handled."}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VERIFIED")

    def test_slow_triage(self):
        telemetry = {
            "incidents": [{"incident_id": "INC-1", "severity": "high",
                           "time_to_triage_hours": 2.5, "requires_federal_report": False}],
            "post_mortems": [],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")

    def test_unreported_federal_incident(self):
        telemetry = {
            "incidents": [{"incident_id": "INC-1", "severity": "critical",
                           "time_to_triage_hours": 0.2,
                           "requires_federal_report": True, "reported_to_federal": False}],
            "post_mortems": [{"incident_id": "INC-1", "summary": "Done."}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")
        self.assertTrue(any(f["control"] == "IR-6" for f in result.findings))


class TestRecoveryAgent(unittest.TestCase):

    def setUp(self):
        self.config = AgentConfig(mode="mock")
        self.agent = RecoveryPlanningAgent(self.config)

    def test_successful_drill(self):
        with open(FIXTURES / "mock_recovery.json") as f:
            telemetry = json.load(f)
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VERIFIED")

    def test_rto_exceeded(self):
        telemetry = {
            "dr_exercises": [{"exercise_id": "DR-1", "rto_target_hours": 4,
                              "rto_actual_hours": 6, "rpo_target_hours": 1,
                              "rpo_actual_hours": 0.5, "overall_success": True}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")


class TestSupplyChainAgent(unittest.TestCase):

    def setUp(self):
        self.config = AgentConfig(mode="mock")
        self.agent = SupplyChainAgent(self.config)

    def test_clean_sbom(self):
        with open(FIXTURES / "mock_sbom.json") as f:
            telemetry = json.load(f)
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VERIFIED")  # Critical CVE not reachable

    def test_critical_reachable_cve(self):
        telemetry = {
            "sbom": {"components": [{"name": "vuln-lib", "version": "1.0"}]},
            "vulnerabilities": [{"cve_id": "CVE-CRITICAL", "package": "vuln-lib",
                                 "cvss_score": 10.0, "mitigated": False,
                                 "reachable_in_architecture": True}],
        }
        result = self.agent.evaluate(telemetry)
        self.assertEqual(result.status, "VIOLATED")


class TestGuardrails(unittest.TestCase):

    def test_valid_output(self):
        output = {
            "status": "VERIFIED",
            "findings": [],
            "citations": [{"source": "doc.pdf", "excerpt": "All good."}],
            "narrative": "Assessment complete.",
        }
        warnings = validate_agent_output(output, strict=False)
        self.assertEqual(len(warnings), 0)

    def test_missing_fields(self):
        output = {"status": "VERIFIED"}
        warnings = validate_agent_output(output, strict=False)
        self.assertGreater(len(warnings), 0)

    def test_invalid_status(self):
        output = {"status": "MAYBE", "findings": [], "citations": [], "narrative": ""}
        warnings = validate_agent_output(output, strict=False)
        self.assertTrue(any("Invalid status" in w for w in warnings))

    def test_hallucination_detection(self):
        output = {
            "status": "VERIFIED", "findings": [], "citations": [],
            "narrative": "I think this is probably compliant.",
        }
        warnings = validate_agent_output(output, strict=False)
        self.assertTrue(any("hedging" in w for w in warnings))

    def test_json_schema_enforcement(self):
        data = enforce_json_schema('{"status": "VERIFIED"}')
        self.assertEqual(data["status"], "VERIFIED")

    def test_json_with_code_fences(self):
        data = enforce_json_schema('```json\n{"status": "OK"}\n```')
        self.assertEqual(data["status"], "OK")

    def test_invalid_json_raises(self):
        with self.assertRaises(GuardrailError):
            enforce_json_schema("not json at all")


class TestNarrativeGenerator(unittest.TestCase):

    def test_verified_narrative(self):
        narrative = generate_cluster_narrative(
            cluster="personnel", ksi="KSI-PS", status="VERIFIED",
            findings=[], citations=[{"source": "BG Report", "excerpt": "Cleared."}],
            evidence_summary={"records_checked": 5}, controls=["PS-1", "PS-3"],
        )
        self.assertIn("VERIFIED", narrative)
        self.assertIn("Personnel", narrative)
        self.assertIn("No findings", narrative)

    def test_violated_narrative(self):
        narrative = generate_cluster_narrative(
            cluster="incident_response", ksi="KSI-INR", status="VIOLATED",
            findings=[{"control": "IR-4", "severity": "high", "finding": "Slow triage"}],
            citations=[], evidence_summary={"incidents": 3}, controls=["IR-1", "IR-4"],
        )
        self.assertIn("VIOLATED", narrative)
        self.assertIn("Slow triage", narrative)
        self.assertIn("Remediation", narrative)


class TestRouteAndEvaluate(unittest.TestCase):

    def test_full_qualitative_flow(self):
        with open(FIXTURES / "mock_personnel.json") as f:
            event = json.load(f)
        result = route_and_evaluate(event, AgentConfig(mode="mock"))
        self.assertEqual(result["routing"]["engine"], "bedrock")
        self.assertEqual(result["routing"]["cluster"], "personnel")
        self.assertIn("evaluation", result)
        self.assertEqual(result["evaluation"]["cluster"], "personnel")

    def test_deterministic_deferred(self):
        event = {"sessions": [{"user_id": "admin"}]}
        result = route_and_evaluate(event, AgentConfig(mode="mock"))
        self.assertEqual(result["routing"]["engine"], "lean")
        self.assertEqual(result["evaluation"]["status"], "DEFERRED_TO_LEAN")


if __name__ == "__main__":
    unittest.main()
