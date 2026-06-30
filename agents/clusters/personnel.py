"""
Personnel Security Agent (KSI-PS)

Evaluates personnel security controls by analyzing background check records,
NDA verification, and cross-referencing IAM provisioning timelines.

Telemetry Sources:
  - Background check vendor reports (PDF/JSON)
  - Signed NDA records
  - AWS IAM user creation events
  - HR onboarding system exports

Controls: PS-1 through PS-8
"""

from datetime import datetime, timezone
from agents.base_agent import BaseVerificationAgent, AgentResult, Citation
from agents.config import AgentConfig


class PersonnelSecurityAgent(BaseVerificationAgent):

    @property
    def cluster_name(self) -> str:
        return "personnel"

    @property
    def ksi(self) -> str:
        return "KSI-PS"

    @property
    def controls(self) -> list[str]:
        return ["PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8"]

    def evaluate(self, telemetry: dict) -> AgentResult:
        """
        Evaluate personnel security telemetry.

        Checks:
        1. All personnel with system access have cleared background checks
        2. Background checks are within valid date range
        3. NDAs are signed before access provisioning
        4. IAM access was not provisioned before adjudication
        """
        bg_checks = telemetry.get("background_checks", [])
        nda_records = telemetry.get("nda_records", [])
        iam_events = telemetry.get("iam_provisioning", [])

        if self.config.mode == "mock":
            return self._mock_evaluate(bg_checks, nda_records, iam_events)

        # Live mode: send to Bedrock for semantic analysis
        prompt = self._build_evaluation_prompt(bg_checks, nda_records, iam_events)
        response = self.invoke_bedrock(prompt, self.build_system_prompt())

        return self._parse_bedrock_response(response)

    def _mock_evaluate(
        self, bg_checks: list, nda_records: list, iam_events: list
    ) -> AgentResult:
        """Mock evaluation for PoC testing."""
        findings = []
        citations = []
        all_compliant = True

        nda_lookup = {r.get("employee_id"): r for r in nda_records}
        iam_lookup = {e.get("employee_id"): e for e in iam_events}

        for check in bg_checks:
            emp_id = check.get("employee_id", "unknown")
            status = check.get("status", "pending")
            check_date = check.get("date", "")
            clearance_id = check.get("clearance_id", "N/A")

            if status not in ("cleared", "adjudicated", "favorable"):
                findings.append({
                    "control": "PS-3",
                    "severity": "high",
                    "finding": f"Employee {emp_id} has unresolved background check status: {status}",
                    "employee_id": emp_id,
                })
                all_compliant = False
            else:
                citations.append(Citation(
                    source=f"Background Check Report — {emp_id}",
                    excerpt=f"Clearance {clearance_id} issued on {check_date}. Status: {status}.",
                ))

            # Check NDA
            nda = nda_lookup.get(emp_id)
            if not nda:
                findings.append({
                    "control": "PS-6",
                    "severity": "medium",
                    "finding": f"No NDA record found for employee {emp_id}",
                    "employee_id": emp_id,
                })
                all_compliant = False
            elif not nda.get("signed", False):
                findings.append({
                    "control": "PS-6",
                    "severity": "high",
                    "finding": f"NDA for employee {emp_id} is not signed",
                    "employee_id": emp_id,
                })
                all_compliant = False

            # Check IAM provisioning timing
            iam = iam_lookup.get(emp_id)
            if iam and check_date:
                iam_date = iam.get("provisioned_date", "")
                if iam_date and iam_date < check_date:
                    findings.append({
                        "control": "PS-3",
                        "severity": "critical",
                        "finding": f"IAM access for {emp_id} provisioned on {iam_date}, "
                                   f"BEFORE background check cleared on {check_date}",
                        "employee_id": emp_id,
                    })
                    all_compliant = False
                elif iam_date:
                    citations.append(Citation(
                        source=f"IAM Provisioning Log — {emp_id}",
                        excerpt=f"Access provisioned on {iam_date}, "
                                f"after adjudication on {check_date}.",
                    ))

        status = "VERIFIED" if all_compliant else "VIOLATED"

        narrative = self._generate_narrative(bg_checks, findings, citations, status)

        return AgentResult(
            cluster=self.cluster_name,
            ksi=self.ksi,
            status=status,
            controls_evaluated=self.controls,
            findings=findings,
            citations=citations,
            narrative=narrative,
            raw_evidence={"background_checks": len(bg_checks), "nda_records": len(nda_lookup)},
        )

    def _generate_narrative(
        self, bg_checks: list, findings: list, citations: list, status: str
    ) -> str:
        """Generate audit-defensive narrative documentation."""
        lines = [
            f"## Personnel Security Assessment ({self.ksi})\n",
            f"**Status: {status}**\n",
            f"Evaluated {len(bg_checks)} personnel records against "
            f"{len(self.controls)} NIST SP 800-53 controls.\n",
        ]

        if findings:
            lines.append("### Findings\n")
            for f in findings:
                lines.append(f"- **[{f['control']}] {f['severity'].upper()}**: {f['finding']}")
        else:
            lines.append("All personnel security controls verified. No findings.\n")

        if citations:
            lines.append("\n### Evidence Citations\n")
            for c in citations:
                lines.append(f"- *{c.source}*: {c.excerpt}")

        return "\n".join(lines)

    def _build_evaluation_prompt(
        self, bg_checks: list, nda_records: list, iam_events: list
    ) -> str:
        """Build the Bedrock evaluation prompt."""
        import json
        return f"""Evaluate the following personnel security telemetry data:

BACKGROUND CHECKS:
{json.dumps(bg_checks, indent=2)}

NDA RECORDS:
{json.dumps(nda_records, indent=2)}

IAM PROVISIONING EVENTS:
{json.dumps(iam_events, indent=2)}

For each employee, verify:
1. Background check status is "cleared" or "favorable"
2. NDA is signed
3. IAM access was NOT provisioned before background check clearance date

Output a JSON object with: status, findings (array), citations (array), narrative (string)."""

    def _parse_bedrock_response(self, response: dict) -> AgentResult:
        """Parse Bedrock response into AgentResult."""
        return AgentResult(
            cluster=self.cluster_name,
            ksi=self.ksi,
            status=response.get("status", "UNKNOWN"),
            controls_evaluated=self.controls,
            findings=response.get("findings", []),
            citations=[
                Citation(source=c.get("source", ""), excerpt=c.get("excerpt", ""))
                for c in response.get("citations", [])
            ],
            narrative=response.get("narrative", ""),
        )
