"""
Cybersecurity Education Agent (KSI-CED)

Validates security awareness training compliance by checking LMS records,
certification validity, and recertification windows against active
administrator accounts.

Telemetry Sources:
  - LMS completion exports (JSON/CSV)
  - Training certificate PDFs
  - Active IAM administrator account lists

Controls: AT-1 through AT-4
"""

from agents.base_agent import BaseVerificationAgent, AgentResult, Citation
from agents.config import AgentConfig


class CybersecurityEducationAgent(BaseVerificationAgent):

    RECERT_WINDOW_DAYS = 365

    @property
    def cluster_name(self) -> str:
        return "training"

    @property
    def ksi(self) -> str:
        return "KSI-CED"

    @property
    def controls(self) -> list[str]:
        return ["AT-1", "AT-2", "AT-3", "AT-4"]

    def evaluate(self, telemetry: dict) -> AgentResult:
        training_records = telemetry.get("training_records", [])
        active_admins = telemetry.get("active_admins", [])

        if self.config.mode == "mock":
            return self._mock_evaluate(training_records, active_admins)

        prompt = self._build_prompt(training_records, active_admins)
        response = self.invoke_bedrock(prompt, self.build_system_prompt())
        return self._parse_response(response)

    def _mock_evaluate(self, records: list, admins: list) -> AgentResult:
        findings = []
        citations = []
        all_compliant = True

        trained_users = {r.get("user_id"): r for r in records}

        for admin in admins:
            admin_id = admin.get("user_id", admin.get("arn", "unknown"))
            record = trained_users.get(admin_id)

            if not record:
                findings.append({
                    "control": "AT-2",
                    "severity": "high",
                    "finding": f"Active admin {admin_id} has no training record",
                })
                all_compliant = False
                continue

            completion_date = record.get("completion_date", "")
            course_id = record.get("course_id", "unknown")
            covers_privacy = record.get("covers_federal_privacy", True)
            covers_security = record.get("covers_security_fundamentals", True)

            if not covers_privacy or not covers_security:
                findings.append({
                    "control": "AT-2",
                    "severity": "medium",
                    "finding": f"Training for {admin_id} (course {course_id}) does not cover "
                               f"required curricula: privacy={covers_privacy}, security={covers_security}",
                })
                all_compliant = False
            else:
                citations.append(Citation(
                    source=f"LMS Record — {admin_id}",
                    excerpt=f"Completed course {course_id} on {completion_date}. "
                            f"Covers federal privacy and security fundamentals.",
                ))

            days_since = record.get("days_since_completion", 0)
            if days_since > self.RECERT_WINDOW_DAYS:
                findings.append({
                    "control": "AT-3",
                    "severity": "high",
                    "finding": f"Admin {admin_id} training expired: {days_since} days since completion "
                               f"(max {self.RECERT_WINDOW_DAYS})",
                })
                all_compliant = False

        status = "VERIFIED" if all_compliant else "VIOLATED"

        narrative = (
            f"## Cybersecurity Education Assessment ({self.ksi})\n\n"
            f"**Status: {status}**\n\n"
            f"Evaluated {len(admins)} active administrators against {len(records)} training records.\n\n"
        )
        if findings:
            narrative += "### Findings\n" + "\n".join(
                f"- **[{f['control']}]** {f['finding']}" for f in findings
            )
        else:
            narrative += "All administrators have current, comprehensive security training. Zero lapses detected."

        return AgentResult(
            cluster=self.cluster_name, ksi=self.ksi, status=status,
            controls_evaluated=self.controls, findings=findings,
            citations=citations, narrative=narrative,
            raw_evidence={"admins_checked": len(admins), "records_found": len(records)},
        )

    def _build_prompt(self, records: list, admins: list) -> str:
        import json
        return f"""Evaluate cybersecurity training compliance:

TRAINING RECORDS: {json.dumps(records, indent=2)}
ACTIVE ADMINS: {json.dumps(admins, indent=2)}

Verify: 1) All admins have training records, 2) Training covers federal privacy and security,
3) No admin exceeds {self.RECERT_WINDOW_DAYS}-day recertification window.
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
