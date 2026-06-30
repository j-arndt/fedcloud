"""
Recovery Planning Agent (KSI-RPL)

Evaluates disaster recovery drill results, validates actual RTO/RPO
against authorized thresholds, and structures exercise documentation
for 3PAO assessment.

Telemetry Sources:
  - DR simulation console logs
  - AWS Backup restore validation reports
  - Recovery exercise result summaries

Controls: CP-1, CP-2, CP-4, CP-6, CP-7, CP-9, CP-10
"""

from agents.base_agent import BaseVerificationAgent, AgentResult, Citation
from agents.config import AgentConfig


class RecoveryPlanningAgent(BaseVerificationAgent):

    @property
    def cluster_name(self) -> str:
        return "recovery"

    @property
    def ksi(self) -> str:
        return "KSI-RPL"

    @property
    def controls(self) -> list[str]:
        return ["CP-1", "CP-2", "CP-4", "CP-6", "CP-7", "CP-9", "CP-10"]

    def evaluate(self, telemetry: dict) -> AgentResult:
        exercises = telemetry.get("dr_exercises", [])
        backup_validations = telemetry.get("backup_validations", [])

        if self.config.mode == "mock":
            return self._mock_evaluate(exercises, backup_validations)

        prompt = self._build_prompt(exercises, backup_validations)
        response = self.invoke_bedrock(prompt, self.build_system_prompt())
        return self._parse_response(response)

    def _mock_evaluate(self, exercises: list, validations: list) -> AgentResult:
        findings = []
        citations = []
        all_compliant = True

        for ex in exercises:
            ex_id = ex.get("exercise_id", "unknown")
            ex_date = ex.get("date", "")
            rto_target_hours = ex.get("rto_target_hours", 4)
            rto_actual_hours = ex.get("rto_actual_hours", 0)
            rpo_target_hours = ex.get("rpo_target_hours", 1)
            rpo_actual_hours = ex.get("rpo_actual_hours", 0)
            success = ex.get("overall_success", True)
            components = ex.get("components_tested", [])

            # Check RTO
            if rto_actual_hours > rto_target_hours:
                findings.append({
                    "control": "CP-2",
                    "severity": "high",
                    "finding": f"Exercise {ex_id}: RTO actual ({rto_actual_hours}h) exceeded "
                               f"target ({rto_target_hours}h)",
                })
                all_compliant = False

            # Check RPO
            if rpo_actual_hours > rpo_target_hours:
                findings.append({
                    "control": "CP-9",
                    "severity": "high",
                    "finding": f"Exercise {ex_id}: RPO actual ({rpo_actual_hours}h) exceeded "
                               f"target ({rpo_target_hours}h)",
                })
                all_compliant = False

            if not success:
                findings.append({
                    "control": "CP-4",
                    "severity": "critical",
                    "finding": f"Exercise {ex_id} on {ex_date} did not complete successfully",
                })
                all_compliant = False
            else:
                citations.append(Citation(
                    source=f"DR Exercise Report — {ex_id}",
                    excerpt=f"Completed {ex_date}. RTO: {rto_actual_hours}h/{rto_target_hours}h target. "
                            f"RPO: {rpo_actual_hours}h/{rpo_target_hours}h target. "
                            f"Components: {', '.join(components)}. Result: SUCCESS.",
                ))

        for val in validations:
            val_id = val.get("backup_id", "unknown")
            restore_verified = val.get("restore_verified", False)
            integrity_check = val.get("integrity_check_passed", False)

            if not restore_verified:
                findings.append({
                    "control": "CP-9",
                    "severity": "high",
                    "finding": f"Backup {val_id}: restore not verified",
                })
                all_compliant = False

            if not integrity_check:
                findings.append({
                    "control": "CP-9",
                    "severity": "medium",
                    "finding": f"Backup {val_id}: integrity check failed",
                })
                all_compliant = False

            if restore_verified and integrity_check:
                citations.append(Citation(
                    source=f"Backup Validation — {val_id}",
                    excerpt="Restore verified. Integrity check passed.",
                ))

        status = "VERIFIED" if all_compliant else "VIOLATED"

        narrative = (
            f"## Recovery Planning Assessment ({self.ksi})\n\n"
            f"**Status: {status}**\n\n"
            f"Evaluated {len(exercises)} DR exercises and {len(validations)} backup validations.\n\n"
        )
        if findings:
            narrative += "### Findings\n" + "\n".join(
                f"- **[{f['control']}] {f['severity'].upper()}**: {f['finding']}" for f in findings
            )
        else:
            narrative += "All recovery objectives met. RTO/RPO within authorized thresholds."

        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi, status=status,
            controls_evaluated=self.controls, findings=findings,
            citations=citations, narrative=narrative,
            raw_evidence={"exercises": len(exercises), "validations": len(validations)},
        )

    def _build_prompt(self, exercises: list, validations: list) -> str:
        import json
        return f"""Evaluate recovery planning compliance:

DR EXERCISES: {json.dumps(exercises, indent=2)}
BACKUP VALIDATIONS: {json.dumps(validations, indent=2)}

Verify: 1) RTO actual <= target, 2) RPO actual <= target,
3) Exercises completed successfully, 4) Backup restores verified.
Output JSON: status, findings, citations, narrative."""

    def _parse_response(self, response: dict) -> AgentResult:
        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi,
            status=response.get("status", "UNKNOWN"),
            controls_evaluated=self.controls,
            findings=response.get("findings", []),
            citations=[Citation(source=c.get("source", ""), excerpt=c.get("excerpt", ""))
                       for c in response.get("citations", [])],
            narrative=response.get("narrative", ""),
        )
